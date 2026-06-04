//go:build darwin && cgo && !nometal

package main

import (
	"encoding/binary"
	"testing"

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal"
	"github.com/btcsuite/btcutil"
)

// TestGPUGLVFilter is the Phase 2B correctness gate: it proves the on-GPU
// GLV+negation expansion is bit-exact with the CPU key reconstruction. The host
// fills only the BASE compressed pubkey per walk step (1/6 the bytes of the old
// writeSextet layout); the glv_filter_kernel derives all six variants on-device
// (x, beta*x, beta^2*x, each in both point-negation parities), hashes them, and
// Bloom-filters them.
//
// For a scattered subset of (step, variant) pairs it builds the Bloom filter
// from the variant Hash160s computed the canonical CPU way (privateKeyForVariant-
// FromBase -> real secp256k1 scalar mult -> btcutil.Hash160), then checks:
//
//   - Zero false negatives: every target (step, variant) is compacted with the
//     candidate id v*count+gid, exactly the old slot index v*m+p — so the CPU
//     reconstruction (v=id/count, p=id%count) is unchanged.
//   - Confirm pass: every candidate decodes to a (v, p), reconstructs a private
//     key, and the key's Hash160 is a real target iff it was inserted.
//
// A mismatch here means the GPU beta/beta^2 multiply, the parity (negation)
// flips, or the id mapping disagree with the CPU — i.e. the GPU would silently
// miss real matches or mislabel them. btcec scalar mult is the independent
// oracle for the endomorphism identity (beta*x, y) == lambda*P.
func TestGPUGLVFilter(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	const (
		count      = 12000 // base walk steps (one base pubkey each)
		stepStride = 17    // pick every 17th step as a 6-variant target
		start      = uint64(0)
	)
	var seed [32]byte
	seed[0] = 0x2a
	seed[31] = 0x9f

	in, err := hasher.NewBuffer(count * pubStride)
	if err != nil {
		t.Fatalf("NewBuffer(in): %v", err)
	}
	defer in.Free()
	inBytes := in.Bytes()

	// Fill only the base point P = k*G (variant 0) per step. The kernel expands
	// the other five variants from this single compressed pubkey.
	for p := 0; p < count; p++ {
		base0 := privateKeyForVariantFromBase(seed, start+uint64(p), 0)
		pc := base0.PubKey().SerializeCompressed()
		copy(inBytes[p*pubStride:p*pubStride+33], pc)
	}

	// Targets: all six variants of a scattered subset of steps. Using all six
	// exercises every (image, parity) combination the kernel produces.
	type stepVariant struct{ p, v int }
	targets := make(hash160Set)
	wantCand := make(map[uint32]stepVariant)
	for p := 0; p < count; p += stepStride {
		for v := 0; v < endoFactor; v++ {
			priv := privateKeyForVariantFromBase(seed, start+uint64(p), v)
			var h [20]byte
			copy(h[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
			targets[h] = struct{}{}
			wantCand[uint32(v*count+p)] = stepVariant{p, v}
		}
	}

	bf := newBloomFromTargets(targets, 1e-6)
	bloomBuf, err := hasher.NewBuffer(bf.byteLen())
	if err != nil {
		t.Fatalf("NewBuffer(bloom): %v", err)
	}
	defer bloomBuf.Free()
	bf.writeTo(bloomBuf.Bytes())

	mcount, err := hasher.NewBuffer(16)
	if err != nil {
		t.Fatalf("NewBuffer(mcount): %v", err)
	}
	defer mcount.Free()
	mdata, err := hasher.NewBuffer(count * 4)
	if err != nil {
		t.Fatalf("NewBuffer(mdata): %v", err)
	}
	defer mdata.Free()

	binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
	if err := hasher.GLVFilter(in, bloomBuf, mcount, mdata, count, pubStride, bf.mask, bf.k); err != nil {
		t.Fatalf("GLVFilter: %v", err)
	}

	nCand := int(binary.LittleEndian.Uint32(mcount.Bytes()[:4]))
	if nCand > count {
		t.Fatalf("candidate counter %d exceeds cap %d (compaction overflow)", nCand, count)
	}

	cand := make(map[uint32]bool, nCand)
	md := mdata.Bytes()
	for i := 0; i < nCand; i++ {
		cand[binary.LittleEndian.Uint32(md[i*4:i*4+4])] = true
	}

	// Zero false negatives: every target (step, variant) id is present.
	missing := 0
	for id, sv := range wantCand {
		if !cand[id] {
			missing++
			if missing <= 5 {
				t.Errorf("missing candidate id %d (step %d variant %d)", id, sv.p, sv.v)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d/%d GLV target variants missing from GPU candidates (FALSE NEGATIVES)", missing, len(wantCand))
	}

	// Confirm pass: decode id -> (v, p), reconstruct, re-hash, check membership.
	confirmed, falsePositives := 0, 0
	for id := range cand {
		v := int(id) / count
		p := int(id) % count
		if v < 0 || v >= endoFactor || p < 0 || p >= count {
			t.Fatalf("candidate id %d decodes to invalid (v=%d, p=%d)", id, v, p)
		}
		priv := privateKeyForVariantFromBase(seed, start+uint64(p), v)
		var h [20]byte
		copy(h[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
		if _, ok := targets[h]; ok {
			confirmed++
		} else {
			falsePositives++
		}
	}
	if confirmed != len(wantCand) {
		t.Fatalf("confirm pass kept %d target variants, want %d", confirmed, len(wantCand))
	}
	t.Logf("GPU GLV filter over %d bases (%d variants): %d candidates, %d real targets, %d false positives (FPR %.2e, k=%d, %d bits)",
		count, count*endoFactor, nCand, confirmed, falsePositives,
		float64(falsePositives)/float64(count*endoFactor), bf.k, uint64(bf.mask)+1)
}
