//go:build darwin && arm64 && cgo && !nometal

package main

import (
	"math"
	"strings"
	"testing"
	"time"

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal"
)

// TestGPUCalibrationSessionReuse proves successive configurations reuse a
// prepared session and advance only fully completed ranges. Saturating the
// actual shared bitmap then forces a real GPU compaction overflow: the complete
// sample must be rejected without publishing any progress or partial rate.
// Positive-rate assertions are liveness checks, not performance acceptance.
func TestGPUCalibrationSessionReuse(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		if err.Error() == "metal: no Metal device available" {
			t.Skipf("Metal unavailable: %v", err)
		}
		t.Fatalf("Metal initialization failed: %v", err)
	}
	t.Cleanup(hasher.Close)
	s, err := newGPUCalibrationSession(hasher, 1, 2)
	if err != nil {
		t.Fatalf("prepare calibration session: %v", err)
	}
	t.Cleanup(s.close)
	if s.bf.byteLen() != 1<<18 || s.bf.k != 22 {
		t.Fatalf("synthetic Bloom size=%d k=%d, want 262144 bytes k=22", s.bf.byteLen(), s.bf.k)
	}
	var populated bool
	for _, word := range s.bf.bits {
		if word != 0 {
			populated = true
			break
		}
	}
	if !populated {
		t.Fatal("calibration Bloom is empty")
	}
	for _, chunks := range []int{1, 2} {
		before := s.nextChunk
		rate, err := s.measure(10*time.Millisecond, chunks)
		if err != nil {
			t.Fatalf("measure chunks=%d: %v", chunks, err)
		}
		if !(rate > 0) || math.IsInf(rate, 0) {
			t.Fatalf("chunks=%d rate=%g, want a finite positive rate", chunks, rate)
		}
		completed := s.workers[0].completed
		want := before + completed*uint64(chunks)
		if completed == 0 || s.nextChunk <= before || s.nextChunk != want {
			t.Fatalf("chunks=%d completed=%d cursor=%d previous=%d want=%d", chunks, completed, s.nextChunk, before, want)
		}
	}

	// Every digest now passes all probes. The kernel counts six candidates per
	// base point but only writes its capped candidate buffer; the host must
	// detect the overflow before attempting any candidate reconstruction.
	for i := range s.bloom.Bytes() {
		s.bloom.Bytes()[i] = 0xff
	}
	before := s.nextChunk
	rate, err := s.measure(10*time.Millisecond, 1)
	if err == nil || !strings.Contains(err.Error(), "candidate buffer overflow") || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("saturated Bloom: rate=%g error=%v, want candidate overflow rejection", rate, err)
	}
	if rate != 0 || s.nextChunk != before || s.workers[0].completed != 0 {
		t.Fatalf("rejected sample published progress: rate=%g cursor=%d previous=%d completed=%d", rate, s.nextChunk, before, s.workers[0].completed)
	}
}

// No valid Metal context is needed: each invalid configuration must fail its
// initial argument guard before Bloom/buffer/stream allocation or GPU work.
func TestGPUCalibrationRejectsInvalidConfiguration(t *testing.T) {
	uninitialized := new(gpumetal.Hasher)
	for _, tc := range []struct {
		name              string
		hasher            *gpumetal.Hasher
		producers, chunks int
	}{
		{"nil hasher", nil, 1, 1},
		{"zero producers", uninitialized, 0, 1},
		{"negative producers", uninitialized, -1, 1},
		{"zero chunks", uninitialized, 1, 0},
		{"negative chunks", uninitialized, 1, -1},
		{"overflowing chunks", uninitialized, 1, int(^uint(0)>>1)/(chunkSteps*pubStride) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newGPUCalibrationSession(tc.hasher, tc.producers, tc.chunks)
			if s != nil || err == nil || !strings.Contains(err.Error(), "invalid GPU calibration configuration") {
				t.Fatalf("session=%v error=%v, want rejection before allocation", s, err)
			}
		})
	}

	// A nil worker makes accidental entry into the worker loop fail immediately;
	// invalid samples must instead return at their initial argument guard.
	s := &gpuCalibrationSession{maxChunks: 2, nextChunk: 91, workers: []*gpuCalibrationWorker{nil}}
	for _, tc := range []struct {
		name     string
		duration time.Duration
		chunks   int
	}{
		{"zero duration", 0, 1},
		{"negative duration", -time.Millisecond, 1},
		{"zero sample chunks", time.Millisecond, 0},
		{"negative sample chunks", time.Millisecond, -1},
		{"sample exceeds allocation", time.Millisecond, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rate, err := s.measure(tc.duration, tc.chunks)
			if rate != 0 || err == nil || !strings.Contains(err.Error(), "invalid calibration sample") || s.nextChunk != 91 {
				t.Fatalf("rate=%g error=%v cursor=%d, want upfront rejection with cursor=91", rate, err, s.nextChunk)
			}
		})
	}
	if got := calibrateGPUKeysPerSec(-time.Millisecond, uninitialized, 1, 1); got != 0 {
		t.Fatalf("negative-duration calibration=%g, want zero", got)
	}
}

func TestGPUCalibrationMedian3(t *testing.T) {
	for _, values := range [][3]float64{
		{1, 2, 3}, {1, 3, 2}, {2, 1, 3},
		{2, 3, 1}, {3, 1, 2}, {3, 2, 1},
		{2, 2, 2}, {1, 2, 2}, {2, 2, 3},
	} {
		if got := gpuCalibrationMedian3(values); got != 2 {
			t.Errorf("median(%v)=%g, want 2", values, got)
		}
	}
}

func TestGPUAutoTuneSelection(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		if err.Error() == "metal: no Metal device available" {
			t.Skipf("Metal unavailable: %v", err)
		}
		t.Fatalf("Metal initialization failed: %v", err)
	}
	t.Cleanup(hasher.Close)
	chunks, tg, rate := autoTuneGPU(hasher, 3, 1, 0)
	if (chunks != 1 && chunks != 3 && chunks != 4 && chunks != 6) ||
		(tg != 0 && tg != 256 && tg != 384 && tg != 512) ||
		!(rate > 0) || math.IsInf(rate, 0) {
		t.Fatalf("invalid tuning result: chunks=%d TG=%d rate=%g", chunks, tg, rate)
	}
	t.Logf("completed coordinate search and confirmations: chunks=%d TG=%d %.1f M hashes/s (liveness check)", chunks, tg, rate/1e6)
}
