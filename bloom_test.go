package main

import (
	"math/rand"
	"testing"
)

// randDigest returns a deterministic pseudo-random 20-byte digest.
func randDigest(rng *rand.Rand) [20]byte {
	var d [20]byte
	rng.Read(d[:])
	return d
}

// TestBloomNoFalseNegatives is the core correctness property: every inserted
// digest MUST test positive. A false negative here would mean the GPU filter
// could reject a real target and the run would silently miss a match.
func TestBloomNoFalseNegatives(t *testing.T) {
	rng := rand.New(rand.NewSource(0xB1009F))
	const n = 50000
	inserted := make([][20]byte, n)
	bf := newBloomFilter(n, 1e-6)
	for i := 0; i < n; i++ {
		d := randDigest(rng)
		inserted[i] = d
		bf.add(d)
	}
	for i, d := range inserted {
		if !bf.test(d) {
			t.Fatalf("false negative at element %d: inserted digest %x tested negative", i, d)
		}
	}
}

// TestBloomFalsePositiveRate fills a filter to its design size and measures the
// observed FPR against fresh non-members. It must be far below 1 (proving the
// filter is selective, not always-positive) and near the 1e-6 target.
func TestBloomFalsePositiveRate(t *testing.T) {
	rng := rand.New(rand.NewSource(0xFA15E))
	const n = 20000
	bf := newBloomFilter(n, 1e-6)
	members := make(map[[20]byte]struct{}, n)
	for i := 0; i < n; i++ {
		d := randDigest(rng)
		members[d] = struct{}{}
		bf.add(d)
	}

	const trials = 200000
	fp := 0
	for i := 0; i < trials; i++ {
		d := randDigest(rng)
		if _, isMember := members[d]; isMember {
			continue
		}
		if bf.test(d) {
			fp++
		}
	}
	rate := float64(fp) / float64(trials)
	t.Logf("bloom: n=%d m=%d bits k=%d -> observed FPR %.2e (%d/%d)", n, uint64(bf.mask)+1, bf.k, rate, fp, trials)
	// Target is 1e-6; allow generous slack for the power-of-two rounding and the
	// finite sample, but it must be well below a broken always-positive filter.
	if rate > 1e-3 {
		t.Fatalf("FPR %.2e exceeds 1e-3 bound (filter not selective enough)", rate)
	}
}

// TestBloomDeterministicHashes pins the probe-derivation scheme: the same digest
// always yields the same h1/h2 (and hence probe indices). This is the contract
// the GPU kernel mirrors; if it drifts, GPU and CPU would disagree.
func TestBloomDeterministicHashes(t *testing.T) {
	d := [20]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	h1a, h2a := bloomHashes(d)
	h1b, h2b := bloomHashes(d)
	if h1a != h1b || h2a != h2b {
		t.Fatalf("bloomHashes not deterministic")
	}
	if h2a&1 == 0 {
		t.Fatalf("h2 must be odd for full-period probing, got %#x", h2a)
	}
	// Known-value pins (little-endian words): w0=0x04030201, w2=0x0c0b0a09,
	// w4=0x14131211 -> h1 = w0^w2^w4; w1=0x08070605, w3=0x100f0e0d -> h2=(w1^w3)|1.
	wantH1 := uint32(0x04030201) ^ uint32(0x0c0b0a09) ^ uint32(0x14131211)
	wantH2 := (uint32(0x08070605) ^ uint32(0x100f0e0d)) | 1
	if h1a != wantH1 || h2a != wantH2 {
		t.Fatalf("bloomHashes = (%#x,%#x), want (%#x,%#x)", h1a, h2a, wantH1, wantH2)
	}
}

// TestBloomSizing sanity-checks the table sizing: power-of-two size, mask=m-1,
// and a sane probe count.
func TestBloomSizing(t *testing.T) {
	for _, n := range []int{1, 20, 1000, 1_000_000, 50_000_000} {
		bf := newBloomFilter(n, 1e-6)
		m := uint64(bf.mask) + 1
		if m&(m-1) != 0 {
			t.Fatalf("n=%d: table size %d is not a power of two", n, m)
		}
		if m < bloomMinBits {
			t.Fatalf("n=%d: table size %d below minimum %d", n, m, bloomMinBits)
		}
		if m > bloomMaxBits {
			t.Fatalf("n=%d: table size %d above maximum %d", n, m, bloomMaxBits)
		}
		if bf.k < 1 || bf.k > bloomMaxK {
			t.Fatalf("n=%d: k=%d out of range", n, bf.k)
		}
		if len(bf.bits) != int(m/32) {
			t.Fatalf("n=%d: bits len %d != m/32 %d", n, len(bf.bits), m/32)
		}
	}
}
