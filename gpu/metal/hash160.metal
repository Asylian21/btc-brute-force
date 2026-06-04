//
// hash160.metal - GPU Hash160 = RIPEMD160(SHA256(pubkey)) for the btc-brute-force
// worker hot path, plus an on-GPU Bloom-filter variant that does the target
// membership test on the device and compacts only candidate indices back to the
// CPU (no per-key readback).
//
// Input layout mirrors the CPU keyStream.pubBuf exactly: `count` messages laid
// out at `stride` bytes each, where bytes [0,33) of every slot hold the
// compressed pubkey (0x02/0x03 prefix + 32-byte X). Bytes [33,stride) are stale
// padding and are never read. stride is 16-byte aligned in every call site so
// the uint4 input loads below are naturally aligned.
//
// The digest is five 32-bit words r[0..4], where the canonical 20-byte Hash160
// is those words emitted little-endian (r[w] -> out[4w..4w+4] little-endian).
//
// Two front ends build the SHA-256 message and share sha_then_ripemd:
//   - hash160_words: reads a 33-byte compressed pubkey from device memory (two
//     uint4 loads + byte 32).
//   - hash160_words_from_limbs: builds the message directly from a 256-bit X held
//     as eight little-endian 32-bit limbs plus a prefix byte, with no byte
//     serialization. Used by the on-GPU GLV expansion (secp_field.metal).
//
// Performance notes (Phase 1C):
//   - SHA-256 uses a 16-word sliding message schedule instead of a 64-word array.
//   - RIPEMD-160 is fully unrolled into 5x16 rounds per line with compile-time
//     message indices, rotate amounts, and round constants.
//
// Both hashes are computed bit-exactly versus btcsuite/btcutil.Hash160 (verified
// by hash160_test.go's 1M-message TestHash160BitExact and the program's startup
// self-test).
//

#include <metal_stdlib>
using namespace metal;

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32u - n)); }
inline uint rotl32(uint x, uint n) { return (x << n) | (x >> (32u - n)); }
inline uint bswap32(uint v) {
    return ((v & 0x000000ffu) << 24) |
           ((v & 0x0000ff00u) << 8)  |
           ((v & 0x00ff0000u) >> 8)  |
           ((v & 0xff000000u) >> 24);
}

constant uint K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

// RIPEMD-160 nonlinear functions (one per 16-round group).
#define RF1(x, y, z) ((x) ^ (y) ^ (z))
#define RF2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RF3(x, y, z) (((x) | ~(y)) ^ (z))
#define RF4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RF5(x, y, z) ((x) ^ ((y) | ~(z)))

// One unrolled RIPEMD-160 round on the left (L) and right (R) line.
#define LROUND(F, r, s, K) { uint t = rotl32(al + F(bl, cl, dl) + x[r] + (K), s) + el; al = el; el = dl; dl = rotl32(cl, 10u); cl = bl; bl = t; }
#define RROUND(F, r, s, K) { uint t = rotl32(ar + F(br, cr, dr) + x[r] + (K), s) + er; ar = er; er = dr; dr = rotl32(cr, 10u); cr = br; br = t; }

// sha_then_ripemd computes Hash160 from a 16-word big-endian SHA-256 message
// block w[0..15] (the message is the 33-byte compressed pubkey, padded). It
// modifies w (the SHA-256 sliding schedule) and writes the five little-endian
// digest words to r[0..4]. Bit-exact vs btcutil.Hash160.
inline void sha_then_ripemd(thread uint* w, thread uint r[5]) {
    uint a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;
    uint e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;

    // Rounds 0..15 consume the loaded words directly.
    for (uint i = 0; i < 16u; i++) {
        uint S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + K256[i] + w[i];
        uint S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    // Rounds 16..63 extend the schedule in a 16-word sliding window.
    for (uint i = 16; i < 64u; i++) {
        uint w15 = w[(i + 1u) & 15u];
        uint w2  = w[(i + 14u) & 15u];
        uint s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3);
        uint s1 = rotr32(w2, 17) ^ rotr32(w2, 19)  ^ (w2 >> 10);
        uint wi = w[i & 15u] + s0 + w[(i + 9u) & 15u] + s1;
        w[i & 15u] = wi;

        uint S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + K256[i] + wi;
        uint S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint sh0 = 0x6a09e667u + a, sh1 = 0xbb67ae85u + b, sh2 = 0x3c6ef372u + c, sh3 = 0xa54ff53au + d;
    uint sh4 = 0x510e527fu + e, sh5 = 0x9b05688cu + f, sh6 = 0x1f83d9abu + g, sh7 = 0x5be0cd19u + h;

    // ---- RIPEMD-160 over the 32-byte SHA-256 digest (single block) ----
    // RIPEMD consumes little-endian words; the SHA digest words are big-endian,
    // so each RIPEMD input word is the byte-swap of the SHA word.
    uint x[16];
    x[0] = bswap32(sh0); x[1] = bswap32(sh1); x[2] = bswap32(sh2); x[3] = bswap32(sh3);
    x[4] = bswap32(sh4); x[5] = bswap32(sh5); x[6] = bswap32(sh6); x[7] = bswap32(sh7);
    x[8]  = 0x00000080u; // 0x80 padding byte after the 32-byte message
    x[9]  = 0u; x[10] = 0u; x[11] = 0u; x[12] = 0u; x[13] = 0u;
    x[14] = 256u; // message length in bits = 32 * 8
    x[15] = 0u;

    uint al = 0x67452301u, bl = 0xefcdab89u, cl = 0x98badcfeu, dl = 0x10325476u, el = 0xc3d2e1f0u;
    uint ar = al, br = bl, cr = cl, dr = dl, er = el;

    // Left line: groups 0..4 use RF1..RF5 with constants 0, 5a82.., 6ed9.., 8f1b.., a953..
    LROUND(RF1,  0, 11, 0x00000000u) LROUND(RF1,  1, 14, 0x00000000u) LROUND(RF1,  2, 15, 0x00000000u) LROUND(RF1,  3, 12, 0x00000000u)
    LROUND(RF1,  4,  5, 0x00000000u) LROUND(RF1,  5,  8, 0x00000000u) LROUND(RF1,  6,  7, 0x00000000u) LROUND(RF1,  7,  9, 0x00000000u)
    LROUND(RF1,  8, 11, 0x00000000u) LROUND(RF1,  9, 13, 0x00000000u) LROUND(RF1, 10, 14, 0x00000000u) LROUND(RF1, 11, 15, 0x00000000u)
    LROUND(RF1, 12,  6, 0x00000000u) LROUND(RF1, 13,  7, 0x00000000u) LROUND(RF1, 14,  9, 0x00000000u) LROUND(RF1, 15,  8, 0x00000000u)

    LROUND(RF2,  7,  7, 0x5a827999u) LROUND(RF2,  4,  6, 0x5a827999u) LROUND(RF2, 13,  8, 0x5a827999u) LROUND(RF2,  1, 13, 0x5a827999u)
    LROUND(RF2, 10, 11, 0x5a827999u) LROUND(RF2,  6,  9, 0x5a827999u) LROUND(RF2, 15,  7, 0x5a827999u) LROUND(RF2,  3, 15, 0x5a827999u)
    LROUND(RF2, 12,  7, 0x5a827999u) LROUND(RF2,  0, 12, 0x5a827999u) LROUND(RF2,  9, 15, 0x5a827999u) LROUND(RF2,  5,  9, 0x5a827999u)
    LROUND(RF2,  2, 11, 0x5a827999u) LROUND(RF2, 14,  7, 0x5a827999u) LROUND(RF2, 11, 13, 0x5a827999u) LROUND(RF2,  8, 12, 0x5a827999u)

    LROUND(RF3,  3, 11, 0x6ed9eba1u) LROUND(RF3, 10, 13, 0x6ed9eba1u) LROUND(RF3, 14,  6, 0x6ed9eba1u) LROUND(RF3,  4,  7, 0x6ed9eba1u)
    LROUND(RF3,  9, 14, 0x6ed9eba1u) LROUND(RF3, 15,  9, 0x6ed9eba1u) LROUND(RF3,  8, 13, 0x6ed9eba1u) LROUND(RF3,  1, 15, 0x6ed9eba1u)
    LROUND(RF3,  2, 14, 0x6ed9eba1u) LROUND(RF3,  7,  8, 0x6ed9eba1u) LROUND(RF3,  0, 13, 0x6ed9eba1u) LROUND(RF3,  6,  6, 0x6ed9eba1u)
    LROUND(RF3, 13,  5, 0x6ed9eba1u) LROUND(RF3, 11, 12, 0x6ed9eba1u) LROUND(RF3,  5,  7, 0x6ed9eba1u) LROUND(RF3, 12,  5, 0x6ed9eba1u)

    LROUND(RF4,  1, 11, 0x8f1bbcdcu) LROUND(RF4,  9, 12, 0x8f1bbcdcu) LROUND(RF4, 11, 14, 0x8f1bbcdcu) LROUND(RF4, 10, 15, 0x8f1bbcdcu)
    LROUND(RF4,  0, 14, 0x8f1bbcdcu) LROUND(RF4,  8, 15, 0x8f1bbcdcu) LROUND(RF4, 12,  9, 0x8f1bbcdcu) LROUND(RF4,  4,  8, 0x8f1bbcdcu)
    LROUND(RF4, 13,  9, 0x8f1bbcdcu) LROUND(RF4,  3, 14, 0x8f1bbcdcu) LROUND(RF4,  7,  5, 0x8f1bbcdcu) LROUND(RF4, 15,  6, 0x8f1bbcdcu)
    LROUND(RF4, 14,  8, 0x8f1bbcdcu) LROUND(RF4,  5,  6, 0x8f1bbcdcu) LROUND(RF4,  6,  5, 0x8f1bbcdcu) LROUND(RF4,  2, 12, 0x8f1bbcdcu)

    LROUND(RF5,  4,  9, 0xa953fd4eu) LROUND(RF5,  0, 15, 0xa953fd4eu) LROUND(RF5,  5,  5, 0xa953fd4eu) LROUND(RF5,  9, 11, 0xa953fd4eu)
    LROUND(RF5,  7,  6, 0xa953fd4eu) LROUND(RF5, 12,  8, 0xa953fd4eu) LROUND(RF5,  2, 13, 0xa953fd4eu) LROUND(RF5, 10, 12, 0xa953fd4eu)
    LROUND(RF5, 14,  5, 0xa953fd4eu) LROUND(RF5,  1, 12, 0xa953fd4eu) LROUND(RF5,  3, 13, 0xa953fd4eu) LROUND(RF5,  8, 14, 0xa953fd4eu)
    LROUND(RF5, 11, 11, 0xa953fd4eu) LROUND(RF5,  6,  8, 0xa953fd4eu) LROUND(RF5, 15,  5, 0xa953fd4eu) LROUND(RF5, 13,  6, 0xa953fd4eu)

    // Right line: groups 0..4 use RF5..RF1 with constants 50a2.., 5c4d.., 6d70.., 7a6d.., 0
    RROUND(RF5,  5,  8, 0x50a28be6u) RROUND(RF5, 14,  9, 0x50a28be6u) RROUND(RF5,  7,  9, 0x50a28be6u) RROUND(RF5,  0, 11, 0x50a28be6u)
    RROUND(RF5,  9, 13, 0x50a28be6u) RROUND(RF5,  2, 15, 0x50a28be6u) RROUND(RF5, 11, 15, 0x50a28be6u) RROUND(RF5,  4,  5, 0x50a28be6u)
    RROUND(RF5, 13,  7, 0x50a28be6u) RROUND(RF5,  6,  7, 0x50a28be6u) RROUND(RF5, 15,  8, 0x50a28be6u) RROUND(RF5,  8, 11, 0x50a28be6u)
    RROUND(RF5,  1, 14, 0x50a28be6u) RROUND(RF5, 10, 14, 0x50a28be6u) RROUND(RF5,  3, 12, 0x50a28be6u) RROUND(RF5, 12,  6, 0x50a28be6u)

    RROUND(RF4,  6,  9, 0x5c4dd124u) RROUND(RF4, 11, 13, 0x5c4dd124u) RROUND(RF4,  3, 15, 0x5c4dd124u) RROUND(RF4,  7,  7, 0x5c4dd124u)
    RROUND(RF4,  0, 12, 0x5c4dd124u) RROUND(RF4, 13,  8, 0x5c4dd124u) RROUND(RF4,  5,  9, 0x5c4dd124u) RROUND(RF4, 10, 11, 0x5c4dd124u)
    RROUND(RF4, 14,  7, 0x5c4dd124u) RROUND(RF4, 15,  7, 0x5c4dd124u) RROUND(RF4,  8, 12, 0x5c4dd124u) RROUND(RF4, 12,  7, 0x5c4dd124u)
    RROUND(RF4,  4,  6, 0x5c4dd124u) RROUND(RF4,  9, 15, 0x5c4dd124u) RROUND(RF4,  1, 13, 0x5c4dd124u) RROUND(RF4,  2, 11, 0x5c4dd124u)

    RROUND(RF3, 15,  9, 0x6d703ef3u) RROUND(RF3,  5,  7, 0x6d703ef3u) RROUND(RF3,  1, 15, 0x6d703ef3u) RROUND(RF3,  3, 11, 0x6d703ef3u)
    RROUND(RF3,  7,  8, 0x6d703ef3u) RROUND(RF3, 14,  6, 0x6d703ef3u) RROUND(RF3,  6,  6, 0x6d703ef3u) RROUND(RF3,  9, 14, 0x6d703ef3u)
    RROUND(RF3, 11, 12, 0x6d703ef3u) RROUND(RF3,  8, 13, 0x6d703ef3u) RROUND(RF3, 12,  5, 0x6d703ef3u) RROUND(RF3,  2, 14, 0x6d703ef3u)
    RROUND(RF3, 10, 13, 0x6d703ef3u) RROUND(RF3,  0, 13, 0x6d703ef3u) RROUND(RF3,  4,  7, 0x6d703ef3u) RROUND(RF3, 13,  5, 0x6d703ef3u)

    RROUND(RF2,  8, 15, 0x7a6d76e9u) RROUND(RF2,  6,  5, 0x7a6d76e9u) RROUND(RF2,  4,  8, 0x7a6d76e9u) RROUND(RF2,  1, 11, 0x7a6d76e9u)
    RROUND(RF2,  3, 14, 0x7a6d76e9u) RROUND(RF2, 11, 14, 0x7a6d76e9u) RROUND(RF2, 15,  6, 0x7a6d76e9u) RROUND(RF2,  0, 14, 0x7a6d76e9u)
    RROUND(RF2,  5,  6, 0x7a6d76e9u) RROUND(RF2, 12,  9, 0x7a6d76e9u) RROUND(RF2,  2, 12, 0x7a6d76e9u) RROUND(RF2, 13,  9, 0x7a6d76e9u)
    RROUND(RF2,  9, 12, 0x7a6d76e9u) RROUND(RF2,  7,  5, 0x7a6d76e9u) RROUND(RF2, 10, 15, 0x7a6d76e9u) RROUND(RF2, 14,  8, 0x7a6d76e9u)

    RROUND(RF1, 12,  8, 0x00000000u) RROUND(RF1, 15,  5, 0x00000000u) RROUND(RF1, 10, 12, 0x00000000u) RROUND(RF1,  4,  9, 0x00000000u)
    RROUND(RF1,  1, 12, 0x00000000u) RROUND(RF1,  5,  5, 0x00000000u) RROUND(RF1,  8, 14, 0x00000000u) RROUND(RF1,  7,  6, 0x00000000u)
    RROUND(RF1,  6,  8, 0x00000000u) RROUND(RF1,  2, 13, 0x00000000u) RROUND(RF1, 13,  6, 0x00000000u) RROUND(RF1, 14,  5, 0x00000000u)
    RROUND(RF1,  0, 15, 0x00000000u) RROUND(RF1,  3, 13, 0x00000000u) RROUND(RF1,  9, 11, 0x00000000u) RROUND(RF1, 11, 11, 0x00000000u)

    r[0] = 0xefcdab89u + cl + dr;
    r[1] = 0x98badcfeu + dl + er;
    r[2] = 0x10325476u + el + ar;
    r[3] = 0xc3d2e1f0u + al + br;
    r[4] = 0x67452301u + bl + cr;
}

#undef RF1
#undef RF2
#undef RF3
#undef RF4
#undef RF5
#undef LROUND
#undef RROUND

// hash160_words computes Hash160(pubkey[0..33)) from device memory into r[0..4].
inline void hash160_words(device const uchar* p, thread uint r[5]) {
    // Load the 33-byte compressed pubkey: two aligned uint4 loads cover bytes
    // [0,32); each lane is a little-endian word, byte-swapped to a big-endian
    // SHA message word. Byte 32 is the last message byte.
    device const uint4* p4 = (device const uint4*)p;
    uint4 v0 = p4[0]; // bytes [0,16)
    uint4 v1 = p4[1]; // bytes [16,32)

    uint w[16];
    w[0] = bswap32(v0.x); w[1] = bswap32(v0.y); w[2] = bswap32(v0.z); w[3] = bswap32(v0.w);
    w[4] = bswap32(v1.x); w[5] = bswap32(v1.y); w[6] = bswap32(v1.z); w[7] = bswap32(v1.w);
    w[8]  = ((uint)p[32] << 24) | 0x00800000u; // byte 32 + 0x80 padding
    w[9]  = 0u; w[10] = 0u; w[11] = 0u; w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 264u; // message length in bits = 33 * 8

    sha_then_ripemd(w, r);
}

// hash160_words_from_limbs computes Hash160 of a compressed pubkey given its
// prefix byte (0x02/0x03) and 256-bit X as eight little-endian limbs v[0..7]
// (v[7] is the most significant). It builds the SHA-256 message words directly
// from the limbs (the big-endian SHA word i straddles two limbs by one byte), so
// no intermediate byte serialization of the GLV image is needed.
inline void hash160_words_from_limbs(uint prefix, thread const uint* v, thread uint r[5]) {
    uint w[16];
    w[0] = (prefix << 24) | (v[7] >> 8);
    w[1] = (v[7] << 24) | (v[6] >> 8);
    w[2] = (v[6] << 24) | (v[5] >> 8);
    w[3] = (v[5] << 24) | (v[4] >> 8);
    w[4] = (v[4] << 24) | (v[3] >> 8);
    w[5] = (v[3] << 24) | (v[2] >> 8);
    w[6] = (v[2] << 24) | (v[1] >> 8);
    w[7] = (v[1] << 24) | (v[0] >> 8);
    w[8] = (v[0] << 24) | 0x00800000u; // last X byte + 0x80 padding
    w[9]  = 0u; w[10] = 0u; w[11] = 0u; w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 264u; // 33 * 8

    sha_then_ripemd(w, r);
}

// hash160_kernel: one GPU thread hashes one pubkey, writing 20 bytes to out.
kernel void hash160_kernel(device const uchar*  pubkeys [[buffer(0)]],
                           device uchar*         out     [[buffer(1)]],
                           constant uint&        stride  [[buffer(2)]],
                           constant uint&        count   [[buffer(3)]],
                           uint                  gid     [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uchar* p = pubkeys + (uint)gid * stride;

    uint r[5];
    hash160_words(p, r);

    device uchar* o = out + (uint)gid * 20u;
    for (uint wi = 0; wi < 5u; wi++) {
        uint v = r[wi];
        o[wi*4u+0u] = v & 0xffu;
        o[wi*4u+1u] = (v >> 8) & 0xffu;
        o[wi*4u+2u] = (v >> 16) & 0xffu;
        o[wi*4u+3u] = (v >> 24) & 0xffu;
    }
}

// bloom_h1/bloom_h2 derive the two Kirsch-Mitzenmacher double-hashing seeds for
// a digest given as the five little-endian Hash160 words. MUST stay identical to
// the CPU builder in bloom.go (same word mix, same odd h2), or the filter could
// create false negatives and miss real matches.
inline uint bloom_h1(thread uint r[5]) { return r[0] ^ r[2] ^ r[4]; }
inline uint bloom_h2(thread uint r[5]) { return (r[1] ^ r[3]) | 1u; }

// bloom_probe returns true if the digest r passes all k Bloom probes (i.e. it is
// a candidate). Shared by the hash160 and GLV filter kernels.
inline bool bloom_probe(thread uint r[5], device const uint* bloom, uint mask, uint k) {
    uint h1 = bloom_h1(r);
    uint h2 = bloom_h2(r);
    for (uint i = 0; i < k; i++) {
        uint idx = (h1 + i * h2) & mask;
        if ((bloom[idx >> 5] & (1u << (idx & 31u))) == 0u) return false;
    }
    return true;
}

// hash160_filter_kernel: hash one pubkey, test the digest against the device
// Bloom filter, and append the thread's gid to mdata (compacted via an atomic
// counter) iff every probe bit is set. The CPU then re-derives and confirms each
// candidate against the real target set (the Bloom filter is purely a throughput
// accelerator: zero false negatives, rare false positives).
kernel void hash160_filter_kernel(device const uchar* pubkeys [[buffer(0)]],
                                  device const uint*  bloom   [[buffer(1)]],
                                  device atomic_uint* mcount  [[buffer(2)]],
                                  device uint*        mdata   [[buffer(3)]],
                                  constant uint&      stride  [[buffer(4)]],
                                  constant uint&      count   [[buffer(5)]],
                                  constant uint&      mask    [[buffer(6)]],
                                  constant uint&      k       [[buffer(7)]],
                                  uint                gid     [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uchar* p = pubkeys + (uint)gid * stride;

    uint r[5];
    hash160_words(p, r);

    if (!bloom_probe(r, bloom, mask, k)) return; // definitely not a target
    uint slot = atomic_fetch_add_explicit(mcount, 1u, memory_order_relaxed);
    if (slot < count) mdata[slot] = gid;
}
