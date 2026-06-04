//
// ec_walk.metal - secp256k1 affine elliptic-curve point arithmetic and the
// batched affine "giant step" walk, on the GPU. This is Phase 3A: moving the EC
// walk itself on-device so the CPU only hands out chunk ranges (no per-key pubkey
// serialization at all).
//
// Depends on secp_field.metal (fe_* field arithmetic) and hash160.metal
// (hash160_words_from_limbs, bloom_probe); the library source is concatenated in
// that order (see metal_darwin.go metalLibrarySource).
//
// A point is two field elements (x, y) as eight little-endian 32-bit limbs each.
// The point at infinity is not represented; the walk inputs are chosen so the
// degenerate cases (P == ±Q, i.e. equal x) never occur for the production base
// points, and the differential tests use distinct, non-inverse points.
//

#include <metal_stdlib>
using namespace metal;

// ec_affine_add: (x3, y3) = (xp, yp) + (xq, yq) for distinct affine points with
// xp != xq (the generic chord case). Computes the slope inverse internally with a
// full fe_inv, so it is the per-call (non-batched) form used by tests and the
// per-thread base-point hop; the hot walk uses ec_affine_add_inv with a shared
// Montgomery inverse. All inputs/outputs are fully reduced (< p).
//
//   lambda = (yq - yp) / (xq - xp)
//   x3     = lambda^2 - xp - xq
//   y3     = lambda*(xp - x3) - yp
// ec_affine_add_inv: chord addition with a precomputed inv = 1/(xq-xp), so a
// batch of additions can share ONE field inversion via Montgomery's trick (see
// ec_walk_glv_kernel). dy = yq - yp is recomputed here (cheap). Uses distinct
// temporaries (no output/input aliasing) so the Metal compiler's thread-pointer
// assumptions cannot bite.
inline void ec_affine_add_inv(thread const uint* xp, thread const uint* yp,
                              thread const uint* xq, thread const uint* yq,
                              thread const uint* inv,
                              thread uint* x3, thread uint* y3) {
    uint dy[8], lam[8], lam2[8], t1[8], t2[8];
    fe_sub(yq, yp, dy);   // yq - yp
    fe_mul(dy, inv, lam); // lambda = (yq - yp) * inv
    fe_sqr(lam, lam2);    // lambda^2
    fe_sub(lam2, xp, t1); // lambda^2 - xp
    fe_sub(t1, xq, x3);   // lambda^2 - xp - xq
    fe_sub(xp, x3, t1);   // xp - x3
    fe_mul(lam, t1, t2);  // lambda*(xp - x3)
    fe_sub(t2, yp, y3);   // lambda*(xp - x3) - yp
}

// ec_affine_add: (x3, y3) = (xp, yp) + (xq, yq), computing the slope inverse
// internally (full fe_inv). Per-call (non-batched) form used only by the
// differential test (ec_add_test); the hot walk uses ec_affine_add_inv.
//
// noinline: this is the one path that inlines fe_inv (six uint[8]) AND several
// fe_mul (uint t[16] + ulong comba) alongside the caller's live point arrays.
// Giving it its own frame keeps the Metal stack-slot allocator from coloring a
// spilled ulong over a uint[8]'s top two limbs (a 64-bit zeroing seen in
// ec_add_test). It is test-only, so this has zero production or walk cost while
// letting fe_mul/fe_inv stay inline for the hot kernels.
__attribute__((noinline))
void ec_affine_add(thread const uint* xp, thread const uint* yp,
                   thread const uint* xq, thread const uint* yq,
                   thread uint* x3, thread uint* y3) {
    uint dx[8], inv[8];
    fe_sub(xq, xp, dx);   // xq - xp
    fe_inv(dx, inv);      // 1/(xq - xp)
    ec_affine_add_inv(xp, yp, xq, yq, inv, x3, y3);
}

// ECW_BATCH: the per-thread linear walk batch length. Each thread owns ECW_BATCH
// consecutive scalars and amortizes ONE field inversion (Montgomery's trick)
// across the batch. Larger = better inversion amortization but more per-thread
// scratch (lower occupancy); this is the knob the plan calls out to tune. The Go
// side (ecWalkBatch) MUST equal this, and the CPU coarse walk steps thread starts
// by ECW_BATCH*G.
#define ECW_BATCH 128u

// emit_point: expand one affine point's X into the six GLV+negation variants,
// hash each, Bloom-probe, and append v*L + linearIdx for hits. Mirrors
// glv_filter_kernel's inner expansion exactly (same variant layout
// v = 2*image + parity), so candidate ids reconstruct through
// privateKeyForVariantFromBase. noinline keeps its scratch (img/beta/hash words)
// in a private frame so the Metal stack-slot allocator cannot overlap a ulong
// temporary onto the caller's live uint[8] walk arrays.
__attribute__((noinline))
void emit_point(thread const uint* x, uint pfx,
                device const uint* bloom, uint mask, uint k,
                uint linearIdx, uint L, uint cap,
                device atomic_uint* mcount, device uint* mdata) {
    uint beta[8];
    for (int i = 0; i < 8; i++) beta[i] = SECP_BETA[i];
    uint img[3][8];
    fe_copy(img[0], x);
    fe_mul(beta, img[0], img[1]); // beta * x
    fe_mul(beta, img[1], img[2]); // beta^2 * x
    for (uint image = 0; image < 3u; image++) {
        for (uint parity = 0; parity < 2u; parity++) {
            uint prefix = pfx ^ parity;
            uint r[5];
            hash160_words_from_limbs(prefix, img[image], r);
            if (!bloom_probe(r, bloom, mask, k)) continue;
            uint v = 2u * image + parity;
            uint slot = atomic_fetch_add_explicit(mcount, 1u, memory_order_relaxed);
            if (slot < cap) mdata[slot] = v * L + linearIdx;
        }
    }
}

// ec_walk_glv_kernel: the full on-GPU EC walk + GLV + Hash160 + Bloom. Thread gid
// owns the ECW_BATCH consecutive linear scalars
//     base + gid*ECW_BATCH + j   (j = 0 .. ECW_BATCH-1)
// whose points are S + j*G, where S = starts[gid] = (base + gid*ECW_BATCH)*G is
// supplied by the host coarse walk (one affine point per thread, NOT per key).
// Step j = 0 is S itself; steps j = 1..ECW_BATCH-1 are chord additions S + jG
// using the shared fine table {jG} (txX/txY hold jG for j = 1..ECW_BATCH-1 at
// index j-1). The ECW_BATCH-1 additions share ONE inversion via Montgomery's
// trick, so the per-key cost is a few field muls + the six-way hash, with no
// per-key inverse. Each produced point is expanded to its six GLV+negation
// variants, hashed, and Bloom-filtered by emit_point.
//
// Degenerate denominators (S == ±jG, i.e. x_S == x_{jG}) would poison the shared
// inversion, but for production base offsets (large random seed region) and the
// differential test's chosen ranges they never occur (probability ~2^-256), so
// no per-thread fixup is done here — see fillStepsInto for the CPU's exact path.
//
// Buffers: (0) starts [gthreads*16 limbs], (1) txX, (2) txY [(ECW_BATCH-1)*8
// limbs each], (3) bloom, (4) atomic match count, (5) match-id output. Scalars:
// gthreads, L (= gthreads*ECW_BATCH, the id stride), mask, k.
kernel void ec_walk_glv_kernel(device const uint*  starts [[buffer(0)]],
                               device const uint*  txX    [[buffer(1)]],
                               device const uint*  txY    [[buffer(2)]],
                               device const uint*  bloom  [[buffer(3)]],
                               device atomic_uint* mcount [[buffer(4)]],
                               device uint*        mdata  [[buffer(5)]],
                               constant uint&      gthreads [[buffer(6)]],
                               constant uint&      L        [[buffer(7)]],
                               constant uint&      mask     [[buffer(8)]],
                               constant uint&      k        [[buffer(9)]],
                               constant uint&      cap      [[buffer(10)]],
                               uint gid [[thread_position_in_grid]]) {
    if (gid >= gthreads) return;

    uint xP[8], yP[8];
    device const uint* s = starts + gid * 16u;
    for (int i = 0; i < 8; i++) { xP[i] = s[i]; yP[i] = s[8 + i]; }

    uint baseIdx = gid * ECW_BATCH;

    // Step j = 0: the start point S itself.
    emit_point(xP, 0x02u | (yP[0] & 1u), bloom, mask, k, baseIdx, L, cap, mcount, mdata);

    // Montgomery batch inversion of the ECW_BATCH-1 chord denominators
    // d[i] = x_{(i+1)G} - x_S. Forward prefix products, one inverse, backward peel.
    //
    // Only the prefix products pre[] are stored; the individual denominators d[i]
    // are NOT (each is a cheap fe_sub of the shared table x against xP), so they
    // are recomputed on demand in both passes. Dropping the d[ECW_BATCH-1][8]
    // array halves this loop's per-thread footprint, which is what lets ECW_BATCH
    // grow far enough to amortize the (~270-mul) inverse down toward 1 mul/key.
    uint pre[ECW_BATCH - 1][8];
    for (uint i = 0; i < ECW_BATCH - 1u; i++) {
        uint qx[8], di[8];
        for (int l = 0; l < 8; l++) qx[l] = txX[i * 8u + l];
        fe_sub(qx, xP, di); // x_{(i+1)G} - x_S
        if (i == 0u) fe_copy(pre[0], di);
        else fe_mul(pre[i - 1], di, pre[i]);
    }
    uint inv[8];
    fe_inv(pre[ECW_BATCH - 2u], inv); // 1 / (d[0]*..*d[last])

    // Backward: invd = 1/d[i]; compute Q = S + (i+1)G; expand+hash+bloom.
    for (int i = (int)ECW_BATCH - 2; i >= 0; i--) {
        // Load the table point (i+1)G into thread space and add to S.
        uint qx[8], qy[8], x3[8], y3[8], invd[8];
        for (int l = 0; l < 8; l++) { qx[l] = txX[(uint)i * 8u + l]; qy[l] = txY[(uint)i * 8u + l]; }
        if (i == 0) {
            fe_copy(invd, inv);
        } else {
            fe_mul(inv, pre[i - 1], invd); // 1/d[i] = inv * (d[0]..d[i-1])
            uint di[8];
            fe_sub(qx, xP, di);            // recompute d[i] = x_{(i+1)G} - x_S
            fe_mul(inv, di, inv);          // fold d[i] back out for the next index
        }
        ec_affine_add_inv(xP, yP, qx, qy, invd, x3, y3);
        emit_point(x3, 0x02u | (y3[0] & 1u), bloom, mask, k,
                   baseIdx + (uint)i + 1u, L, cap, mcount, mdata);
    }
}
