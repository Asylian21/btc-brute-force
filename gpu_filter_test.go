//go:build darwin && cgo && !nometal

package main

import (
	"encoding/binary"
	"testing"

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
)

// TestGPUBloomFilter is the end-to-end correctness gate for the on-GPU Bloom
// pipeline (Phase 1A). It builds real secp256k1 pubkeys, picks a subset as
// targets, encodes them into the same Bloom filter the program uploads, runs the
// hash160_filter_kernel, and checks the two properties the search relies on:
//
//   - Zero false negatives: every target gid is compacted as a candidate (a miss
//     here would silently drop a real match for a whole run).
//   - Correct confirmation: every candidate re-hashed with btcutil.Hash160 is a
//     real target iff it was inserted, so the CPU confirm pass keeps exactly the
//     true matches and the false-positive rate stays low.
func TestGPUBloomFilter(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	const n = 100000
	in, err := hasher.NewBuffer(n * pubStride)
	if err != nil {
		t.Fatalf("NewBuffer(in): %v", err)
	}
	defer in.Free()
	inBytes := in.Bytes()

	h160s := make([][20]byte, n)
	for i := 0; i < n; i++ {
		var priv [32]byte
		binary.BigEndian.PutUint64(priv[24:], uint64(i+1))
		_, pub := btcec.PrivKeyFromBytes(priv[:])
		pc := pub.SerializeCompressed()
		copy(inBytes[i*pubStride:i*pubStride+33], pc)
		copy(h160s[i][:], btcutil.Hash160(pc))
	}

	// Targets: a scattered subset. Build the exact set and the Bloom filter.
	targets := make(hash160Set)
	targetGid := make(map[int]bool)
	for i := 0; i < n; i += 97 {
		targets[h160s[i]] = struct{}{}
		targetGid[i] = true
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
	mdata, err := hasher.NewBuffer(n * 4)
	if err != nil {
		t.Fatalf("NewBuffer(mdata): %v", err)
	}
	defer mdata.Free()

	binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
	if err := hasher.Hash160Filter(in, bloomBuf, mcount, mdata, n, pubStride, bf.mask, bf.k); err != nil {
		t.Fatalf("Hash160Filter: %v", err)
	}

	nCand := int(binary.LittleEndian.Uint32(mcount.Bytes()[:4]))
	if nCand > n {
		t.Fatalf("candidate counter %d exceeds key count %d (compaction overflow)", nCand, n)
	}

	candidate := make(map[int]bool, nCand)
	md := mdata.Bytes()
	for i := 0; i < nCand; i++ {
		gid := int(binary.LittleEndian.Uint32(md[i*4 : i*4+4]))
		if gid < 0 || gid >= n {
			t.Fatalf("candidate %d has out-of-range gid %d", i, gid)
		}
		candidate[gid] = true
	}

	// Zero false negatives.
	missing := 0
	for gid := range targetGid {
		if !candidate[gid] {
			missing++
			if missing <= 5 {
				t.Errorf("target gid %d missing from GPU candidates", gid)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d/%d targets missing from GPU candidates (FALSE NEGATIVES)", missing, len(targetGid))
	}

	// Confirm pass: candidates that re-hash to a target are exactly the targets.
	confirmed := 0
	falsePositives := 0
	for gid := range candidate {
		var h [20]byte
		copy(h[:], btcutil.Hash160(inBytes[gid*pubStride:gid*pubStride+33]))
		if _, ok := targets[h]; ok {
			confirmed++
		} else {
			falsePositives++
		}
	}
	if confirmed != len(targetGid) {
		t.Fatalf("confirm pass kept %d targets, want %d", confirmed, len(targetGid))
	}
	t.Logf("GPU filter over %d keys: %d candidates, %d real targets, %d false positives (FPR %.2e, k=%d, %d bits)",
		n, nCand, confirmed, falsePositives, float64(falsePositives)/float64(n), bf.k, uint64(bf.mask)+1)
}
