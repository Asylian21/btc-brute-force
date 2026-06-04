package main

import (
	"sync"
	"testing"
)

// TestFrontierTrackerInOrder verifies that completing contiguous ranges in order
// advances the frontier monotonically across the whole completed prefix.
func TestFrontierTrackerInOrder(t *testing.T) {
	f := newFrontierTracker(0)
	if got := f.frontierChunk(); got != 0 {
		t.Fatalf("fresh tracker frontier = %d, want 0", got)
	}

	for i := uint64(0); i < 5; i++ {
		start := f.claim(1)
		if start != i {
			t.Fatalf("claim %d returned start %d, want %d", i, start, i)
		}
		// Frontier must not advance before the range is completed.
		if got := f.frontierChunk(); got != i {
			t.Fatalf("after claim %d, frontier = %d, want %d (not yet complete)", i, got, i)
		}
		f.complete(start, 1)
		if got := f.frontierChunk(); got != i+1 {
			t.Fatalf("after complete %d, frontier = %d, want %d", i, got, i+1)
		}
	}
}

// TestFrontierTrackerOutOfOrder is the core gap-free guarantee under the
// out-of-order completion the GPU pipeline creates: a later range that finishes
// first must NOT advance the frontier past an earlier, still-in-flight range.
func TestFrontierTrackerOutOfOrder(t *testing.T) {
	f := newFrontierTracker(0)

	a := f.claim(2) // [0,2)
	b := f.claim(2) // [2,4)
	c := f.claim(2) // [4,6)
	if a != 0 || b != 2 || c != 4 {
		t.Fatalf("claims returned %d,%d,%d, want 0,2,4", a, b, c)
	}

	// Complete the LAST range first: frontier must stay at 0 (gap at [0,4)).
	f.complete(c, 2)
	if got := f.frontierChunk(); got != 0 {
		t.Fatalf("frontier = %d after completing only [4,6), want 0", got)
	}

	// Complete the MIDDLE range: still a gap at [0,2), frontier stays at 0.
	f.complete(b, 2)
	if got := f.frontierChunk(); got != 0 {
		t.Fatalf("frontier = %d after completing [2,6), want 0", got)
	}

	// Complete the FIRST range: now [0,6) is contiguous, frontier jumps to 6.
	f.complete(a, 2)
	if got := f.frontierChunk(); got != 6 {
		t.Fatalf("frontier = %d after completing [0,6), want 6", got)
	}
}

// TestFrontierTrackerStartOffset verifies a tracker resumed at a nonzero chunk
// (the --resume case) hands out and tracks the frontier from that offset.
func TestFrontierTrackerStartOffset(t *testing.T) {
	const start = 1000
	f := newFrontierTracker(start)
	if got := f.frontierChunk(); got != start {
		t.Fatalf("resumed frontier = %d, want %d", got, start)
	}
	s := f.claim(3)
	if s != start {
		t.Fatalf("first claim after resume = %d, want %d", s, start)
	}
	f.complete(s, 3)
	if got := f.frontierChunk(); got != start+3 {
		t.Fatalf("frontier = %d after completing [%d,%d), want %d", got, start, start+3, start+3)
	}
}

// TestFrontierTrackerConcurrentClaims stresses claim() from many goroutines and
// proves every chunk index in [0, total) is handed out exactly once (no overlap,
// no gap) regardless of scheduling — the property that lets any number of
// producers cooperate on one cursor without skipping or double-covering keys.
func TestFrontierTrackerConcurrentClaims(t *testing.T) {
	f := newFrontierTracker(0)
	const (
		producers   = 16
		claimsEach  = 500
		claimSize   = 3
		totalChunks = producers * claimsEach * claimSize
	)

	seen := make([]int32, totalChunks)
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < claimsEach; i++ {
				start := f.claim(claimSize)
				for k := uint64(0); k < claimSize; k++ {
					seen[start+k]++
				}
				f.complete(start, claimSize)
			}
		}()
	}
	wg.Wait()

	for i, v := range seen {
		if v != 1 {
			t.Fatalf("chunk %d handed out %d times, want exactly 1", i, v)
		}
	}
	// Every range was completed, so the frontier must have reached the end.
	if got := f.frontierChunk(); got != totalChunks {
		t.Fatalf("final frontier = %d, want %d", got, totalChunks)
	}
}

// TestFrontierTrackerPartialThenGap checks that overlapping/adjacent completions
// advance the frontier only across the contiguous prefix, leaving later isolated
// completed ranges parked in `done` until the gap before them is filled.
func TestFrontierTrackerPartialThenGap(t *testing.T) {
	f := newFrontierTracker(0)
	_ = f.claim(10) // pretend a single producer claimed [0,10)

	// Complete [0,3): frontier -> 3.
	f.complete(0, 3)
	if got := f.frontierChunk(); got != 3 {
		t.Fatalf("frontier = %d, want 3", got)
	}
	// Complete [5,8): isolated, frontier stays at 3.
	f.complete(5, 3)
	if got := f.frontierChunk(); got != 3 {
		t.Fatalf("frontier = %d, want 3 (gap at [3,5))", got)
	}
	// Fill the gap [3,5): frontier should jump across [3,8) -> 8.
	f.complete(3, 2)
	if got := f.frontierChunk(); got != 8 {
		t.Fatalf("frontier = %d, want 8", got)
	}
	// Finish the tail [8,10): frontier -> 10.
	f.complete(8, 2)
	if got := f.frontierChunk(); got != 10 {
		t.Fatalf("frontier = %d, want 10", got)
	}
}
