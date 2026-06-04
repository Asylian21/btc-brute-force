package main

import (
	"encoding/binary"
	"math"
)

// ============================================================================
// BLOOM FILTER: on-GPU target membership pre-filter
// ============================================================================
//
// The GPU pipeline hashes hundreds of thousands of keys per dispatch. Reading
// every 20-byte digest back to the CPU and doing a hash-map lookup per key was
// the dominant non-GPU cost (≈11.8 MB readback + ~590k lookups per dispatch).
//
// Instead, the target Hash160 set is encoded once into a Bloom filter that lives
// in GPU device memory. The Hash160 kernel tests each digest against the filter
// on-device and atomically compacts only the (rare) candidate thread indices
// back to the CPU. The CPU then re-derives and confirms each candidate against
// the real target set, so the Bloom filter NEVER causes a missed match:
//
//   - Zero false negatives: every real target was inserted, so its probe bits
//     are all set; the kernel can never reject it.
//   - False positives are dropped by the CPU confirm pass (an exact lookup in
//     hash160Set), so no false match is ever written.
//
// The probe scheme (digest -> k bit positions) MUST be byte-identical to the
// hash160_filter_kernel in hash160.metal, or the GPU could reject a real target.
// Both sides read the 20-byte digest as five little-endian 32-bit words, derive
// two hashes (h1, h2 with h2 forced odd) and probe via Kirsch-Mitzenmacher
// double hashing idx_i = (h1 + i*h2) & mask over a power-of-two table.

// bloomMinBits is the floor on the table size (bits), so even a tiny target list
// yields a well-formed, very-low-FPR filter. bloomMaxBits caps memory (and keeps
// every bit index within uint32, matching the kernel's 32-bit arithmetic).
const (
	bloomMinBits = uint64(1) << 16 // 8 KiB bitmap minimum
	bloomMaxBits = uint64(1) << 31 // 256 MiB bitmap maximum
	bloomMaxK    = uint32(32)
)

// bloomFilter is a classic bit-array Bloom filter with a power-of-two size so
// the kernel can mask instead of modulo.
type bloomFilter struct {
	bits []uint32 // m/32 words, m a power of two
	mask uint32   // m-1
	k    uint32   // number of probes
}

// bloomDigestWords reads a 20-byte Hash160 as five little-endian 32-bit words.
// This matches how the kernel recovers words from its computed digest (the
// digest bytes are r[w] emitted little-endian, so reading them back LE gives r).
func bloomDigestWords(d [20]byte) (w0, w1, w2, w3, w4 uint32) {
	w0 = binary.LittleEndian.Uint32(d[0:4])
	w1 = binary.LittleEndian.Uint32(d[4:8])
	w2 = binary.LittleEndian.Uint32(d[8:12])
	w3 = binary.LittleEndian.Uint32(d[12:16])
	w4 = binary.LittleEndian.Uint32(d[16:20])
	return
}

// bloomHashes derives the two double-hashing seeds. Identical to bloom_h1/bloom_h2
// in hash160.metal. h2 is forced odd so the probe sequence has full period over
// the power-of-two table.
func bloomHashes(d [20]byte) (h1, h2 uint32) {
	w0, w1, w2, w3, w4 := bloomDigestWords(d)
	h1 = w0 ^ w2 ^ w4
	h2 = (w1 ^ w3) | 1
	return
}

// newBloomFilter sizes a filter for n elements at the target false-positive
// rate. The table is rounded up to a power of two (clamped to [min,max]); k is
// the optimal probe count for the chosen m/n (clamped).
func newBloomFilter(n int, fpr float64) *bloomFilter {
	if n < 1 {
		n = 1
	}
	if fpr <= 0 || fpr >= 1 {
		fpr = 1e-6
	}
	bitsPerElem := -math.Log(fpr) / (math.Ln2 * math.Ln2)
	need := uint64(math.Ceil(bitsPerElem * float64(n)))

	m := bloomMinBits
	for m < need && m < bloomMaxBits {
		m <<= 1
	}

	k := uint32(math.Round((float64(m) / float64(n)) * math.Ln2))
	if k < 1 {
		k = 1
	}
	if k > bloomMaxK {
		k = bloomMaxK
	}

	return &bloomFilter{
		bits: make([]uint32, m/32),
		mask: uint32(m - 1),
		k:    k,
	}
}

// add inserts a digest's k probe bits.
func (b *bloomFilter) add(d [20]byte) {
	h1, h2 := bloomHashes(d)
	for i := uint32(0); i < b.k; i++ {
		idx := (h1 + i*h2) & b.mask
		b.bits[idx>>5] |= 1 << (idx & 31)
	}
}

// test reports whether all k probe bits are set (true => possibly present;
// false => definitely absent). Used by tests and as a CPU reference.
func (b *bloomFilter) test(d [20]byte) bool {
	h1, h2 := bloomHashes(d)
	for i := uint32(0); i < b.k; i++ {
		idx := (h1 + i*h2) & b.mask
		if b.bits[idx>>5]&(1<<(idx&31)) == 0 {
			return false
		}
	}
	return true
}

// byteLen is the size of the bit array in bytes (for the Metal buffer).
func (b *bloomFilter) byteLen() int { return len(b.bits) * 4 }

// writeTo serializes the bit array as little-endian uint32 words into dst (a
// shared Metal buffer), matching the kernel's `device const uint*` view.
func (b *bloomFilter) writeTo(dst []byte) {
	for i, w := range b.bits {
		binary.LittleEndian.PutUint32(dst[i*4:], w)
	}
}

// newBloomFromTargets builds and fills a filter from the loaded target set.
func newBloomFromTargets(targets hash160Set, fpr float64) *bloomFilter {
	b := newBloomFilter(len(targets), fpr)
	for d := range targets {
		b.add(d)
	}
	return b
}
