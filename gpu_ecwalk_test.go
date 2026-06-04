//go:build darwin && cgo && !nometal

package main

import (
	"encoding/binary"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
)

// TestGPUSelfTestGate runs the exact backend-selection gate (gpuSelfTest): the
// GPU Hash160, GLV-expansion, and full EC-walk self-tests. A green here means the
// production --gpu path would be accepted on this device with all three on-device
// pipelines proven bit-exact against btcutil.
func TestGPUSelfTestGate(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()
	if err := gpuSelfTest(hasher); err != nil {
		t.Fatalf("gpuSelfTest gate failed: %v", err)
	}
}

// TestGPUEndToEndPipeline exercises the full PRODUCTION GPU orchestration
// (runGPU -> gpuProducer -> CPU base-pubkey fill -> GLVFilterStream -> Bloom ->
// confirm -> matchChan) against two planted targets:
//
//   - target A lives at linear step 100 of chunk 0, variant 0 (identity image,
//     even parity) — a base-point key.
//   - target B lives at linear step 1 of chunk 0, variant 3 (beta*x image, odd
//     parity) — a GLV+negation key the device derives, exercising the variant
//     decode (id = v*baseCount + gid) on the confirm path.
//
// Both being delivered on matchChan proves the hybrid producer fills, dispatches,
// decodes candidate ids back to (chunk, step, variant), reconstructs the private
// key, and that the frontierTracker advances — all through the exact production
// code paths, with the bloom filter, key reconstruction, and target membership.
func TestGPUEndToEndPipeline(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	seed0 := chunkBaseSeed(0)
	keyA := privateKeyForVariantFromBase(seed0, 100, 0) // base key, step 100
	keyB := privateKeyForVariantFromBase(seed0, 1, 3)   // GLV+negation variant, step 1
	var hashA, hashB [20]byte
	copy(hashA[:], btcutil.Hash160(keyA.PubKey().SerializeCompressed()))
	copy(hashB[:], btcutil.Hash160(keyB.PubKey().SerializeCompressed()))

	targets := hash160Set{hashA: struct{}{}, hashB: struct{}{}}

	bf := newBloomFromTargets(targets, gpuBloomFPR)
	bloomBuf, err := hasher.NewBuffer(bf.byteLen())
	if err != nil {
		t.Fatalf("bloom buffer alloc: %v", err)
	}
	defer bloomBuf.Free()
	bf.writeTo(bloomBuf.Bytes())

	tracker := newFrontierTracker(0)
	matchChan := make(chan MatchResult, 100)
	stop := make(chan struct{})
	var counter uint64

	done := make(chan struct{})
	go func() {
		// One producer, one chunk per dispatch: chunk 0 is claimed first and
		// covers both planted steps in the very first dispatch.
		runGPU(hasher, 1, 1, bloomBuf, bf.mask, bf.k, targets, matchChan, &counter, tracker, stop)
		close(done)
	}()

	foundA, foundB := false, false
	deadline := time.After(30 * time.Second)
	for !(foundA && foundB) {
		select {
		case m := <-matchChan:
			var h [20]byte
			copy(h[:], btcutil.Hash160(m.privateKey.PubKey().SerializeCompressed()))
			switch h {
			case hashA:
				foundA = true
			case hashB:
				foundB = true
			default:
				t.Fatalf("unexpected match: %x", h)
			}
		case <-deadline:
			close(stop)
			<-done
			t.Fatalf("timed out: foundA=%v (base key) foundB=%v (GLV variant)", foundA, foundB)
		}
	}

	close(stop)
	<-done
	if atomic.LoadUint64(&counter) == 0 {
		t.Fatalf("counter did not advance")
	}
	if got := tracker.frontierChunk(); got == 0 {
		t.Fatalf("frontier did not advance past chunk 0 (got %d)", got)
	}
	t.Logf("end-to-end: both planted targets found (base + GLV variant), frontier=%d, keys counted=%d",
		tracker.frontierChunk(), atomic.LoadUint64(&counter))
}

// TestGPUECWalkSelfTest validates the EXPERIMENTAL full on-GPU EC-walk pipeline
// (ec_walk.metal / GLVWalk) end-to-end against btcutil via the same self-test the
// experiment ships. Production uses the faster hybrid path, but the on-GPU walk is
// kept and must stay bit-exact, so this is a standalone gate for it.
func TestGPUECWalkSelfTest(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()
	if err := gpuECWalkSelfTest(hasher); err != nil {
		t.Fatalf("gpuECWalkSelfTest (experimental on-GPU walk) failed: %v", err)
	}
}

// TestGPUCalibrationSanity exercises the --gpu=auto calibration path after the
// Phase-4 rewrite that points it at the real on-GPU EC-walk pipeline
// (GLVWalkStream) instead of the retired CPU-EC GLVFilter path. It asserts both
// the GPU and CPU calibrators report a positive throughput (a zero would silently
// force the wrong backend) and logs the measured A/B so --gpu=auto can be trusted
// to honor the no-regression contract (GPU chosen only when >= CPU).
func TestGPUCalibrationSanity(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	producers := runtime.NumCPU()
	const chunksPerDispatch = 6
	gpuRate := calibrateGPUKeysPerSec(300*time.Millisecond, hasher, producers, chunksPerDispatch)
	cpuRate := calibrateCPUKeysPerSec(300*time.Millisecond, producers)
	if gpuRate <= 0 {
		t.Fatalf("GPU calibration returned %.1f (expected > 0) — on-GPU EC-walk path is not measured", gpuRate)
	}
	if cpuRate <= 0 {
		t.Fatalf("CPU calibration returned %.1f (expected > 0)", cpuRate)
	}
	t.Logf("calibration A/B (%d producers, %d chunks/dispatch): GPU=%.1f M keys/s, CPU=%.1f M keys/s, ratio=%.2fx",
		producers, chunksPerDispatch, gpuRate/1e6, cpuRate/1e6, gpuRate/cpuRate)
}

// TestGPUProductionSweep measures the REAL production hybrid path
// (calibrateGPUKeysPerSec = CPU EC-walk base-pubkey fill + concurrent
// GLVFilterStream dispatches across N producers) over a grid of (producers,
// chunks/dispatch) so the default that saturates this GPU can be picked. On a
// MacBook Air M3 the knee is ~8 producers x 6 chunks/dispatch (~240 M keys/s).
// Diagnostic only; skipped under -short.
func TestGPUProductionSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("sweep diagnostic skipped under -short")
	}
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()
	for _, producers := range []int{4, 8, 12} {
		for _, chunks := range []int{3, 6, 12, 24} {
			rate := calibrateGPUKeysPerSec(250*time.Millisecond, hasher, producers, chunks)
			t.Logf("producers=%-2d chunks/dispatch=%-3d -> %6.1f M keys/s", producers, chunks, rate/1e6)
		}
	}
}

// TestGPUWalkDispatchThroughput isolates the EXPERIMENTAL on-GPU EC-walk kernel
// cost (ec_walk.metal / GLVWalkStream): it fills the start points and fine table
// ONCE, then dispatches GLVWalkStream in a tight loop for a fixed window. The
// reported rate is the pure GPU ceiling of the kept-but-not-production walk
// (host-fill-free), useful for tuning ECWalkBatch. Diagnostic only; skipped under
// -short.
func TestGPUWalkDispatchThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput diagnostic skipped under -short")
	}
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	for _, chunksPerDispatch := range []int{6, 24, 48, 96, 192} {
		gthreads := chunksPerDispatch * gpuWalkThreadsPerChunk
		L := chunksPerDispatch * chunkSteps
		keyCount := L * endoFactor

		starts, _ := hasher.NewBuffer(gthreads * 16 * 4)
		txX, _ := hasher.NewBuffer((gpumetal.ECWalkBatch - 1) * 8 * 4)
		txY, _ := hasher.NewBuffer((gpumetal.ECWalkBatch - 1) * 8 * 4)
		bloom, _ := hasher.NewBuffer(1 << 17) // 1<<20 bits
		mcount, _ := hasher.NewBuffer(16)
		mdata, _ := hasher.NewBuffer(L * 4)
		stream, _ := hasher.NewStream()

		xb, yb := txX.Bytes(), txY.Bytes()
		for j := 0; j < gpumetal.ECWalkBatch-1; j++ {
			var bx, by [32]byte
			mulGx[j].PutBytesUnchecked(bx[:])
			mulGy[j].PutBytesUnchecked(by[:])
			putLimbsFromBE(xb[j*32:j*32+32], bx[:])
			putLimbsFromBE(yb[j*32:j*32+32], by[:])
		}
		ks := newKeyStreamForGPU()
		for k := 0; k < chunksPerDispatch; k++ {
			ks.setBase(chunkBaseSeed(uint64(k)))
			ks.fillStartPoints(starts.Bytes()[k*gpuStartBytesPerChunk : (k+1)*gpuStartBytesPerChunk])
		}

		const window = 400 * time.Millisecond
		var dispatches uint64
		start := time.Now()
		for time.Since(start) < window {
			binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
			if err := stream.GLVWalkStream(starts, txX, txY, bloom, mcount, mdata, gthreads, (1<<20)-1, 20); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			dispatches++
		}
		elapsed := time.Since(start).Seconds()
		rate := float64(dispatches) * float64(keyCount) / elapsed
		t.Logf("chunks/dispatch=%-3d gthreads=%-6d keys/dispatch=%-8d -> %6.1f M keys/s (pure GPU, %.2f ms/dispatch)",
			chunksPerDispatch, gthreads, keyCount, rate/1e6, elapsed*1e3/float64(dispatches))

		stream.Free()
		mdata.Free()
		mcount.Free()
		bloom.Free()
		txY.Free()
		txX.Free()
		starts.Free()
	}
}

// putLimbsLE writes a big.Int as eight little-endian 32-bit limbs into dst[0:32]
// (limb 0 least significant), the layout ec_walk_glv_kernel reads for the start
// points and fine table.
func putLimbsLE(dst []byte, x *big.Int) {
	t := new(big.Int).Set(x)
	mask := big.NewInt(0xFFFFFFFF)
	w := new(big.Int)
	for i := 0; i < 8; i++ {
		w.And(t, mask)
		binary.LittleEndian.PutUint32(dst[i*4:], uint32(w.Uint64()))
		t.Rsh(t, 32)
	}
}

// affineOf returns the affine (X, Y) coordinates of priv's public key.
func affineOf(priv *btcec.PrivateKey) (x, y *big.Int) {
	u := priv.PubKey().SerializeUncompressed() // 0x04 || X(32) || Y(32)
	return new(big.Int).SetBytes(u[1:33]), new(big.Int).SetBytes(u[33:65])
}

// scalarMulGSmall returns the affine coordinates of m*G for a small positive m.
func scalarMulGSmall(m int) (x, y *big.Int) {
	var kb [32]byte
	binary.BigEndian.PutUint64(kb[24:], uint64(m))
	priv, _ := btcec.PrivKeyFromBytes(kb[:])
	return affineOf(priv)
}

// TestGPUECWalk is the Phase 3A correctness gate: the WHOLE hot path on the GPU.
// Each thread walks ECWalkBatch consecutive points from a host-supplied start
// (one shared Montgomery inversion), expands every point to its six GLV+negation
// variants, hashes, and Bloom-filters them. The host supplies only one affine
// start point per thread (the coarse walk steps by ECWalkBatch*G) plus the shared
// fine table jG for j=1..ECWalkBatch-1 — no per-key pubkey serialization at all.
//
// The Bloom filter is built from ALL six variant Hash160s of ALL L = gthreads*
// ECWalkBatch covered scalars, computed the canonical CPU way (privateKeyFor-
// VariantFromBase -> btcec scalar mult -> btcutil.Hash160). So if the GPU walk
// computes any wrong point, that variant's digest is not in the filter and its
// candidate id goes missing -> a detected false negative. A pass therefore proves
// the on-device EC walk + GLV expansion + Hash160 are bit-exact with the CPU
// reconstruction over every covered key.
func TestGPUECWalk(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	defer hasher.Close()

	const (
		gthreads = 128
		start    = uint64(0x1234) // dispatch base offset (avoids the degenerate low-scalar range)
	)
	M := gpumetal.ECWalkBatch
	L := gthreads * M
	var seed [32]byte
	seed[0] = 0x2a
	seed[31] = 0x9f

	// Start points: starts[gid] = (seed + start + gid*M)*G, variant 0 affine.
	starts, err := hasher.NewBuffer(gthreads * 16 * 4)
	if err != nil {
		t.Fatalf("NewBuffer(starts): %v", err)
	}
	defer starts.Free()
	sb := starts.Bytes()
	for gid := 0; gid < gthreads; gid++ {
		priv := privateKeyForVariantFromBase(seed, start+uint64(gid*M), 0)
		x, y := affineOf(priv)
		off := gid * 64
		putLimbsLE(sb[off:off+32], x)
		putLimbsLE(sb[off+32:off+64], y)
	}

	// Fine table: txX[i], txY[i] = (i+1)*G for i = 0..M-2.
	txX, err := hasher.NewBuffer((M - 1) * 8 * 4)
	if err != nil {
		t.Fatalf("NewBuffer(txX): %v", err)
	}
	defer txX.Free()
	txY, err := hasher.NewBuffer((M - 1) * 8 * 4)
	if err != nil {
		t.Fatalf("NewBuffer(txY): %v", err)
	}
	defer txY.Free()
	xb, yb := txX.Bytes(), txY.Bytes()
	for i := 0; i < M-1; i++ {
		x, y := scalarMulGSmall(i + 1)
		putLimbsLE(xb[i*32:i*32+32], x)
		putLimbsLE(yb[i*32:i*32+32], y)
	}

	// Targets: all six variants of all L covered scalars.
	targets := make(hash160Set)
	for idx := 0; idx < L; idx++ {
		for v := 0; v < endoFactor; v++ {
			priv := privateKeyForVariantFromBase(seed, start+uint64(idx), v)
			var h [20]byte
			copy(h[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
			targets[h] = struct{}{}
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
	// Every covered variant is a target here, so size mdata for all 6*L ids.
	mdata, err := hasher.NewBuffer(L * endoFactor * 4)
	if err != nil {
		t.Fatalf("NewBuffer(mdata): %v", err)
	}
	defer mdata.Free()

	binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
	if err := hasher.GLVWalk(starts, txX, txY, bloomBuf, mcount, mdata, gthreads, bf.mask, bf.k); err != nil {
		t.Fatalf("GLVWalk: %v", err)
	}

	nCand := int(binary.LittleEndian.Uint32(mcount.Bytes()[:4]))
	if nCand > L*endoFactor {
		t.Fatalf("candidate counter %d exceeds cap %d (compaction overflow)", nCand, L*endoFactor)
	}
	cand := make(map[uint32]bool, nCand)
	md := mdata.Bytes()
	for i := 0; i < nCand; i++ {
		cand[binary.LittleEndian.Uint32(md[i*4:i*4+4])] = true
	}

	// Zero false negatives: every (v, linearIdx) id must be present. id = v*L + idx.
	missing := 0
	for idx := 0; idx < L; idx++ {
		for v := 0; v < endoFactor; v++ {
			id := uint32(v*L + idx)
			if !cand[id] {
				missing++
				if missing <= 5 {
					t.Errorf("missing candidate id %d (idx %d variant %d)", id, idx, v)
				}
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d/%d walk variants missing from GPU candidates (FALSE NEGATIVES)", missing, L*endoFactor)
	}

	// Confirm pass: decode id -> (v, idx), reconstruct, re-hash, check membership.
	confirmed, falsePositives := 0, 0
	for id := range cand {
		v := int(id) / L
		idx := int(id) % L
		if v < 0 || v >= endoFactor || idx < 0 || idx >= L {
			t.Fatalf("candidate id %d decodes to invalid (v=%d, idx=%d)", id, v, idx)
		}
		priv := privateKeyForVariantFromBase(seed, start+uint64(idx), v)
		var h [20]byte
		copy(h[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
		if _, ok := targets[h]; ok {
			confirmed++
		} else {
			falsePositives++
		}
	}
	if confirmed != L*endoFactor {
		t.Fatalf("confirm pass kept %d variants, want %d", confirmed, L*endoFactor)
	}
	t.Logf("on-GPU EC walk over %d threads x %d batch = %d keys (%d variants): %d candidates, %d confirmed, %d false positives (k=%d, %d bits)",
		gthreads, M, L, L*endoFactor, nCand, confirmed, falsePositives, bf.k, uint64(bf.mask)+1)
}
