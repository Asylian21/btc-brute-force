//
// secp_field.metal - secp256k1 prime-field (Fp) arithmetic on the GPU.
//
// This is the foundation for moving the EC walk and GLV expansion on-device
// (Phases 2-3). Field elements are 256-bit residues mod
//     p = 2^256 - 2^32 - 977  (= 0xFFFF...FFFE FFFFFC2F)
// represented as eight little-endian 32-bit limbs `uint v[8]` (v[0] = least
// significant). All public fe_* operations take fully-reduced inputs (< p) and
// produce fully-reduced outputs (< p).
//
// Limb choice: 8x32. Apple GPUs do 32-bit integer multiply natively and a
// 32x32->64 product via (ulong)a*(ulong)b is exact, while 64-bit multiply is
// emulated; a 5x52 (ulong) representation would lean on the slow path. The 8x32
// schoolbook multiply uses a 3-word (ulong + overflow) comba accumulator, and
// reduction exploits the pseudo-Mersenne shape 2^256 ≡ 2^32 + 977 (mod p).
//
// Correctness is verified by a differential test (secp_field_test.go) that runs
// each op on >= 1e5 random inputs and compares byte-for-byte against a math/big
// reference mod p.
//

#include <metal_stdlib>
using namespace metal;

// p limbs (little-endian).
constant uint SECP_P[8] = {
    0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// c = 2^256 mod p = 2^32 + 977 = 0x1000003D1. Split into the +977 low part and
// the +2^32 (one-limb shift) part for fold reduction without 33-bit products.
constant uint SECP_C_LOW = 0x000003D1u; // 977
// (the 2^32 part is handled by adding the high limb one position up)

// beta limbs (little-endian) = the GLV endomorphism constant
//   beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
// for which (beta*x, y) = lambda*(x, y) on secp256k1. MUST match the CPU betaHex
// in bitcoin-wallet-bruteforce-offline.go, or the GPU-expanded GLV variants would
// not equal the CPU-reconstructed keys.
constant uint SECP_BETA[8] = {
    0x719501eeu, 0xc1396c28u, 0x12f58995u, 0x9cf04975u,
    0xac3434e9u, 0x6e64479eu, 0x657c0710u, 0x7ae96a2bu
};

// fe_copy: d = s.
inline void fe_copy(thread uint* d, thread const uint* s) {
    for (int i = 0; i < 8; i++) d[i] = s[i];
}

// fe_is_ge_p: returns true if v >= p (v has 8 limbs, < 2^256).
inline bool fe_is_ge_p(thread const uint* v) {
    for (int i = 7; i >= 0; i--) {
        if (v[i] != SECP_P[i]) return v[i] > SECP_P[i];
    }
    return true; // equal to p
}

// fe_cond_sub_p: if v >= p, v -= p. v has 8 limbs and is assumed < 2p.
inline void fe_cond_sub_p(thread uint* v) {
    if (!fe_is_ge_p(v)) return;
    ulong borrow = 0;
    for (int i = 0; i < 8; i++) {
        ulong sub = (ulong)SECP_P[i] + borrow;
        ulong vi = (ulong)v[i];
        if (vi >= sub) {
            v[i] = (uint)(vi - sub);
            borrow = 0;
        } else {
            v[i] = (uint)(vi + 0x100000000ul - sub);
            borrow = 1;
        }
    }
}

// fold_once: in-place v[0..15] <- low8(v) + high8(v) * c, with the result spread
// over v[0..10] and v[11..15] cleared. Repeated application drives the high limbs
// to zero (the value shrinks toward < 2^256).
//
// Single forward pass with a scalar carry (no ulong scratch ARRAY): output limb i
// gets v[i] (low) + 977*v[8+i] (the +977 part of high limb i) + v[8+(i-1)] (the
// +2^32 part of high limb i-1) + carry. The high limbs v[8..15] are all read as
// inputs at iterations i<=8, strictly before the low limbs v[8..10] they overlap
// are overwritten (i>=8), so the in-place update is hazard-free. Using only
// scalar ulong temporaries (kept in registers) instead of `ulong acc[10]` avoids
// the Metal stack-coloring bug where a ulong array aliases the caller's uint[8]
// field arrays when this is inlined — which is what lets every fe_* stay inline.
inline void fold_once(thread uint* v) {
    ulong carry = 0;
    for (int i = 0; i < 11; i++) {
        ulong s = carry;
        if (i < 8) {
            s += (ulong)v[i];                              // low limb i
            s += (ulong)v[8 + i] * (ulong)SECP_C_LOW;      // 977 * high_i
        }
        if (i >= 1 && (i - 1) < 8) {
            s += (ulong)v[8 + (i - 1)];                    // 2^32 * high_{i-1}
        }
        v[i] = (uint)s;
        carry = s >> 32;
    }
    for (int i = 11; i < 16; i++) v[i] = 0;
}

// fe_reduce: 16-limb v (a full product or sum) -> fully reduced r[0..7] (< p).
inline void fe_reduce(thread uint* v, thread uint* r) {
    for (int it = 0; it < 8; it++) {
        uint hi = v[8] | v[9] | v[10] | v[11] | v[12] | v[13] | v[14] | v[15];
        if (hi == 0u) break;
        fold_once(v);
    }
    for (int i = 0; i < 8; i++) r[i] = v[i];
    fe_cond_sub_p(r);
}

// fe_mul: r = a * b mod p. Inline: it is the hottest field op and the production
// GLV kernel calls it per key (beta*x, beta^2*x), so the call overhead matters
// (~9% on that hash-bound path). Correctness across kernels comes from isolating
// the big-frame fe_inv (noinline) instead — see fe_inv.
inline void fe_mul(thread const uint* a, thread const uint* b, thread uint* r) {
    uint t[16];
    // Comba multiply with a (ulong + overflow) accumulator.
    ulong accLo = 0;
    uint accHi = 0;
    for (uint k = 0; k < 15u; k++) {
        uint imin = (k >= 8u) ? (k - 7u) : 0u;
        uint imax = (k < 8u) ? k : 7u;
        for (uint i = imin; i <= imax; i++) {
            uint j = k - i;
            ulong prod = (ulong)a[i] * (ulong)b[j];
            ulong old = accLo;
            accLo += prod;
            if (accLo < old) accHi++;
        }
        t[k] = (uint)accLo;
        accLo = (accLo >> 32) | ((ulong)accHi << 32);
        accHi = 0;
    }
    t[15] = (uint)accLo;
    fe_reduce(t, r);
}

// fe_sqr: r = a^2 mod p.
inline void fe_sqr(thread const uint* a, thread uint* r) {
    fe_mul(a, a, r);
}

// fe_sqr_inplace_n: a <- a^(2^n) mod p (n squarings in place).
inline void fe_sqr_inplace_n(thread uint* a, int n) {
    uint tmp[8];
    for (int i = 0; i < n; i++) {
        fe_sqr(a, tmp);
        fe_copy(a, tmp);
    }
}

// fe_add: r = a + b mod p.
inline void fe_add(thread const uint* a, thread const uint* b, thread uint* r) {
    uint v[16];
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong s = (ulong)a[i] + (ulong)b[i] + carry;
        v[i] = (uint)s;
        carry = s >> 32;
    }
    v[8] = (uint)carry;
    for (int i = 9; i < 16; i++) v[i] = 0;
    fe_reduce(v, r);
}

// fe_sub: r = a - b mod p.
inline void fe_sub(thread const uint* a, thread const uint* b, thread uint* r) {
    ulong borrow = 0;
    for (int i = 0; i < 8; i++) {
        ulong bi = (ulong)b[i] + borrow;
        ulong ai = (ulong)a[i];
        if (ai >= bi) {
            r[i] = (uint)(ai - bi);
            borrow = 0;
        } else {
            r[i] = (uint)(ai + 0x100000000ul - bi);
            borrow = 1;
        }
    }
    if (borrow) {
        // a < b: add p back (the borrow out of bit 256 cancels the conceptual
        // -2^256, leaving a - b + p in [0, p)).
        ulong carry = 0;
        for (int i = 0; i < 8; i++) {
            ulong s = (ulong)r[i] + (ulong)SECP_P[i] + carry;
            r[i] = (uint)s;
            carry = s >> 32;
        }
    }
}

// fe_normalize: reduce an arbitrary 256-bit value (< 2^256) to canonical < p.
inline void fe_normalize(thread const uint* a, thread uint* r) {
    fe_copy(r, a);
    fe_cond_sub_p(r); // a < 2^256 < 2p, so one conditional subtract suffices
}

// fe_inv: r = a^(p-2) mod p (modular inverse for a != 0), via the libsecp256k1
// addition chain. Returns 0 for a = 0.
//
// Footprint matters: large per-thread arrays spill to the limited Metal thread
// stack, and combined with many live locals in the caller (EC kernels) that
// corrupts results. So this uses only SIX persistent 8-limb temporaries
// (x2,x3,x22,x44,x88 + a running accumulator `acc`) instead of the 13-array
// naive chain, reusing fe_mul's safe output==input aliasing (the product is
// staged in fe_mul's local t[16] and only written back at the end).
inline void fe_inv(thread const uint* a, thread uint* r) {
    uint x2[8], x3[8], x22[8], x44[8], x88[8], acc[8];

    fe_sqr(a, x2);  fe_mul(x2, a, x2);   // x2 = a^(2^2-1)
    fe_sqr(x2, x3); fe_mul(x3, a, x3);   // x3 = a^(2^3-1)

    fe_copy(acc, x3); fe_sqr_inplace_n(acc, 3);  fe_mul(acc, x3, acc); // x6
    fe_sqr_inplace_n(acc, 3);  fe_mul(acc, x3, acc);                   // x9
    fe_sqr_inplace_n(acc, 2);  fe_mul(acc, x2, acc);                   // x11

    fe_copy(x22, acc); fe_sqr_inplace_n(x22, 11); fe_mul(x22, acc, x22); // x22
    fe_copy(x44, x22); fe_sqr_inplace_n(x44, 22); fe_mul(x44, x22, x44); // x44
    fe_copy(x88, x44); fe_sqr_inplace_n(x88, 44); fe_mul(x88, x44, x88); // x88

    fe_copy(acc, x88); fe_sqr_inplace_n(acc, 88); fe_mul(acc, x88, acc); // x176
    fe_sqr_inplace_n(acc, 44); fe_mul(acc, x44, acc);                    // x220
    fe_sqr_inplace_n(acc, 3);  fe_mul(acc, x3, acc);                     // x223

    fe_sqr_inplace_n(acc, 23); fe_mul(acc, x22, acc);
    fe_sqr_inplace_n(acc, 5);  fe_mul(acc, a, acc);
    fe_sqr_inplace_n(acc, 3);  fe_mul(acc, x2, acc);
    fe_sqr_inplace_n(acc, 2);  fe_mul(acc, a, r);
}

// fe_from_be33: load the 32-byte big-endian X of a compressed pubkey (bytes
// [1,33) of the 33-byte record at p) into little-endian limbs v[0..7]. p[0] is
// the prefix byte and is read separately by the caller. The most significant
// big-endian bytes go into the most significant limb v[7].
inline void fe_from_be33(device const uchar* p, thread uint* v) {
    for (int limb = 0; limb < 8; limb++) {
        int bo = 1 + (7 - limb) * 4; // byte offset of this limb's most significant byte
        v[limb] = ((uint)p[bo] << 24) | ((uint)p[bo + 1] << 16) |
                  ((uint)p[bo + 2] << 8) | (uint)p[bo + 3];
    }
}

// glv_filter_kernel expands one base compressed pubkey into its six GLV+negation
// variants entirely on the GPU, hashes each, and Bloom-filters them, appending
// the (variant, step) candidate id for any probe hit. This replaces the CPU-side
// writeSextet 6x byte serialization: the host now fills only ONE pubkey per walk
// step (1/6 the bytes and copies), and the kernel derives the rest with two field
// multiplies (beta*x, beta^2*x) and two prefix flips (point negation is free —
// only the parity prefix changes, x is shared).
//
// Variant layout MUST match writeSextet / privateKeyForVariantFromBase:
//   v0 (pfx,  x)     v1 (flip, x)
//   v2 (pfx,  bx)    v3 (flip, bx)
//   v4 (pfx,  b2x)   v5 (flip, b2x)
// i.e. variant v = 2*image + parity, image in {x, beta*x, beta^2*x}, parity in
// {pfx, pfx^1}. The candidate id is v*count + gid, identical to the slot index
// v*m+p of the old full-buffer layout, so the CPU reconstruction (id -> v=id/m,
// p=id%m) is unchanged.
//
// Buffers: (0) bases (count records, `stride` bytes each, [0,33) = prefix+X),
// (1) bloom bitmap, (2) atomic match count, (3) match-id output. Scalars: stride,
// count, mask, k. Grid: count threads (one base pubkey each).
kernel void glv_filter_kernel(device const uchar* bases  [[buffer(0)]],
                              device const uint*  bloom  [[buffer(1)]],
                              device atomic_uint* mcount [[buffer(2)]],
                              device uint*        mdata  [[buffer(3)]],
                              constant uint&      stride [[buffer(4)]],
                              constant uint&      count  [[buffer(5)]],
                              constant uint&      mask   [[buffer(6)]],
                              constant uint&      k      [[buffer(7)]],
                              uint                gid    [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uchar* p = bases + (uint)gid * stride;
    uint pfx = (uint)p[0];

    // beta in thread address space (fe_* take thread pointers; the constant-space
    // array cannot be passed directly).
    uint beta[8];
    for (int i = 0; i < 8; i++) beta[i] = SECP_BETA[i];

    // Three endomorphism images of X: x, beta*x, beta^2*x.
    uint img[3][8];
    fe_from_be33(p, img[0]);
    fe_mul(beta, img[0], img[1]);
    fe_mul(beta, img[1], img[2]);

    for (uint image = 0; image < 3u; image++) {
        for (uint parity = 0; parity < 2u; parity++) {
            uint prefix = pfx ^ parity; // parity 0 -> pfx, 1 -> flip (point negation)
            uint r[5];
            hash160_words_from_limbs(prefix, img[image], r);
            if (!bloom_probe(r, bloom, mask, k)) continue;
            uint v = 2u * image + parity;
            uint slot = atomic_fetch_add_explicit(mcount, 1u, memory_order_relaxed);
            if (slot < count) mdata[slot] = v * count + gid;
        }
    }
}
