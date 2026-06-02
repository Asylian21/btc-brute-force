//
// hash160.metal — GPU Hash160 = RIPEMD160(SHA256(pubkey)) for the btc-brute-force
// worker hot path. One GPU thread hashes one 33-byte compressed public key.
//
// Input layout mirrors the CPU keyStream.pubBuf exactly: `count` messages laid
// out at `stride` bytes each, where bytes [0,33) of every slot hold the
// compressed pubkey (0x02/0x03 prefix + 32-byte X). Bytes [33,stride) are stale
// padding and are never read. Output is `count` * 20 contiguous bytes: slot i
// receives its 20-byte Hash160 at out[i*20 .. i*20+20].
//
// Both hashes are computed bit-exactly versus btcsuite/btcutil.Hash160 (verified
// by hash160_test.go and the program's startup self-test). SHA-256 runs over a
// single 64-byte block (33 bytes + padding); RIPEMD-160 runs over a single block
// (the 32-byte SHA-256 digest + padding).
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

// RIPEMD-160 message-word selection and rotate-amount tables (left + right line).
constant uint RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
constant uint RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
constant uint SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
constant uint SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};
constant uint KL[5] = { 0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu };
constant uint KR[5] = { 0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u };

// RIPEMD-160 nonlinear functions, selected by 16-round group index (0..4).
inline uint ripemd_f(uint grp, uint x, uint y, uint z) {
    switch (grp) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        default: return x ^ (y | ~z);
    }
}

kernel void hash160_kernel(device const uchar*  pubkeys [[buffer(0)]],
                           device uchar*         out     [[buffer(1)]],
                           constant uint&        stride  [[buffer(2)]],
                           constant uint&        count   [[buffer(3)]],
                           uint                  gid     [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uchar* p = pubkeys + (uint)gid * stride;

    // ---- SHA-256 over the 33-byte compressed pubkey (single block) ----
    uint w[64];
    for (uint i = 0; i < 8u; i++) {
        uint j = i * 4u;
        w[i] = ((uint)p[j] << 24) | ((uint)p[j+1] << 16) | ((uint)p[j+2] << 8) | (uint)p[j+3];
    }
    // byte 32 is the last message byte; 0x80 is the padding start bit.
    w[8]  = ((uint)p[32] << 24) | (0x80u << 16);
    w[9]  = 0u; w[10] = 0u; w[11] = 0u; w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 264u; // message length in bits = 33 * 8
    for (uint i = 16; i < 64u; i++) {
        uint s0 = rotr32(w[i-15], 7)  ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = rotr32(w[i-2], 17)  ^ rotr32(w[i-2], 19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;
    uint e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;
    for (uint i = 0; i < 64u; i++) {
        uint S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + K256[i] + w[i];
        uint S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint sh0 = 0x6a09e667u + a, sh1 = 0xbb67ae85u + b, sh2 = 0x3c6ef372u + c, sh3 = 0xa54ff53au + d;
    uint sh4 = 0x510e527fu + e, sh5 = 0x9b05688cu + f, sh6 = 0x1f83d9abu + g, sh7 = 0x5be0cd19u + h;

    // ---- RIPEMD-160 over the 32-byte SHA-256 digest (single block) ----
    // RIPEMD consumes little-endian words; the SHA digest bytes are big-endian
    // per word, so each input word is the byte-swap of the SHA word.
    uint x[16];
    x[0] = bswap32(sh0); x[1] = bswap32(sh1); x[2] = bswap32(sh2); x[3] = bswap32(sh3);
    x[4] = bswap32(sh4); x[5] = bswap32(sh5); x[6] = bswap32(sh6); x[7] = bswap32(sh7);
    x[8]  = 0x00000080u; // 0x80 padding byte after the 32-byte message
    x[9]  = 0u; x[10] = 0u; x[11] = 0u; x[12] = 0u; x[13] = 0u;
    x[14] = 256u; // message length in bits = 32 * 8
    x[15] = 0u;

    uint al = 0x67452301u, bl = 0xefcdab89u, cl = 0x98badcfeu, dl = 0x10325476u, el = 0xc3d2e1f0u;
    uint ar = al, br = bl, cr = cl, dr = dl, er = el;
    for (uint j = 0; j < 80u; j++) {
        uint grp = j / 16u;
        uint tl = rotl32(al + ripemd_f(grp, bl, cl, dl) + x[RL[j]] + KL[grp], SL[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = tl;
        uint tr = rotl32(ar + ripemd_f(4u - grp, br, cr, dr) + x[RR[j]] + KR[grp], SR[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = tr;
    }
    uint t = 0xefcdab89u + cl + dr;
    uint r1 = 0x98badcfeu + dl + er;
    uint r2 = 0x10325476u + el + ar;
    uint r3 = 0xc3d2e1f0u + al + br;
    uint r4 = 0x67452301u + bl + cr;
    uint r0 = t;

    // ---- Emit 20-byte digest, little-endian per word ----
    device uchar* o = out + (uint)gid * 20u;
    o[0]  = r0 & 0xffu; o[1]  = (r0 >> 8) & 0xffu; o[2]  = (r0 >> 16) & 0xffu; o[3]  = (r0 >> 24) & 0xffu;
    o[4]  = r1 & 0xffu; o[5]  = (r1 >> 8) & 0xffu; o[6]  = (r1 >> 16) & 0xffu; o[7]  = (r1 >> 24) & 0xffu;
    o[8]  = r2 & 0xffu; o[9]  = (r2 >> 8) & 0xffu; o[10] = (r2 >> 16) & 0xffu; o[11] = (r2 >> 24) & 0xffu;
    o[12] = r3 & 0xffu; o[13] = (r3 >> 8) & 0xffu; o[14] = (r3 >> 16) & 0xffu; o[15] = (r3 >> 24) & 0xffu;
    o[16] = r4 & 0xffu; o[17] = (r4 >> 8) & 0xffu; o[18] = (r4 >> 16) & 0xffu; o[19] = (r4 >> 24) & 0xffu;
}
