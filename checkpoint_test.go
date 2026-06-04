package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// mustSeed decodes a 64-hex-char private key for tests (fatal on error).
func mustSeed(t *testing.T, s string) [32]byte {
	t.Helper()
	seed, err := parsePrivateKeyHex(s)
	if err != nil {
		t.Fatalf("mustSeed(%q): %v", s, err)
	}
	return seed
}

// withStartKeySeed sets the global scan-window base for the duration of a test
// and restores it afterward, since writeCheckpoint reads startKeySeed.
func withStartKeySeed(t *testing.T, seed [32]byte) {
	t.Helper()
	prev := startKeySeed
	startKeySeed = seed
	t.Cleanup(func() { startKeySeed = prev })
}

// TestParsePrivateKeyHex covers the length-first validation: a wrong-length or
// odd-length string (the hand-editing slip that broke the user's custom
// checkpoint and the old --start-key example) must give a clear message, not the
// cryptic "encoding/hex: odd length hex string".
func TestParsePrivateKeyHex(t *testing.T) {
	valid := "a7f31c92b04d0210000000000000000000000000000000000000000000000001"
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid 64", valid, false},
		{"valid key 1", "0000000000000000000000000000000000000000000000000000000000000001", false},
		{"odd length 65", "A7F31C92B04D02100000000000000000000000000000000000000000000000001", true},
		{"too short", "0001", true},
		{"empty", "", true},
		{"bad hex char", "zz" + valid[2:], true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePrivateKeyHex(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parsePrivateKeyHex(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestLinearOffsetFromKeys verifies the (frontier - base) mod N offset decode,
// including the rejection of a frontier below the base or more than 2^64 keys
// above it (outside the supported 2^64-key scan window).
func TestLinearOffsetFromKeys(t *testing.T) {
	base := startKeyOne

	// A few in-window offsets must round-trip exactly.
	for _, off := range []uint64{0, 1, chunkSteps, 5*chunkSteps + 123, 1 << 40} {
		frontier := addOffsetToSeed(base, off)
		got, err := linearOffsetFromKeys(base, frontier)
		if err != nil {
			t.Fatalf("offset %d: unexpected error %v", off, err)
		}
		if got != off {
			t.Fatalf("offset round-trip: got %d, want %d", got, off)
		}
	}

	// A frontier BELOW the base (key 0 < base key 1) is -1 mod N: a huge value
	// with nonzero high bytes, so it must be rejected (not silently wrapped).
	below := mustSeed(t, "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := linearOffsetFromKeys(base, below); err == nil {
		t.Fatalf("expected error for frontier below base, got nil")
	}

	// A frontier more than 2^64 keys above the base must be rejected.
	far := mustSeed(t, "0000000000000000000000000000000000000000000000010000000000000001")
	if _, err := linearOffsetFromKeys(base, far); err == nil {
		t.Fatalf("expected error for frontier > 2^64 above base, got nil")
	}
}

// TestWriteReadCheckpointRoundTrip writes a checkpoint at a known frontier chunk
// from a custom window base, reads it back, and confirms the resume helpers
// recover EXACTLY that base and chunk — the core save/continue contract.
func TestWriteReadCheckpointRoundTrip(t *testing.T) {
	base := mustSeed(t, "a7f31c92b04d0210000000000000000000000000000000000000000000000001")
	withStartKeySeed(t, base)

	const frontierChunk = 42
	path := filepath.Join(t.TempDir(), "cp.json")
	if err := writeCheckpoint(path, frontierChunk, 8); err != nil {
		t.Fatalf("writeCheckpoint: %v", err)
	}

	cp, err := readCheckpoint(path)
	if err != nil {
		t.Fatalf("readCheckpoint: %v", err)
	}
	if cp.Version != checkpointVersion {
		t.Fatalf("version = %d, want %d", cp.Version, checkpointVersion)
	}
	if cp.StartKey != hex.EncodeToString(base[:]) {
		t.Fatalf("start_key = %s, want %s", cp.StartKey, hex.EncodeToString(base[:]))
	}
	wantFrontier := privateKeyHexFromBase(base, frontierChunk*chunkSteps)
	if cp.NextPrivateKey != wantFrontier {
		t.Fatalf("next_private_key = %s, want %s", cp.NextPrivateKey, wantFrontier)
	}
	if cp.TotalKeys != frontierChunk*chunkSteps*endoFactor {
		t.Fatalf("total_keys = %d, want %d", cp.TotalKeys, uint64(frontierChunk)*chunkSteps*endoFactor)
	}

	// Resume helpers must recover the exact base and chunk.
	gotBase, err := resumeBaseSeed(cp)
	if err != nil {
		t.Fatalf("resumeBaseSeed: %v", err)
	}
	if gotBase != base {
		t.Fatalf("resumeBaseSeed = %x, want %x", gotBase, base)
	}
	gotChunk, err := resumeStartChunk(cp, gotBase)
	if err != nil {
		t.Fatalf("resumeStartChunk: %v", err)
	}
	if gotChunk != frontierChunk {
		t.Fatalf("resumeStartChunk = %d, want %d", gotChunk, frontierChunk)
	}
	// The resumed chunk's first key must equal the saved frontier key, tying the
	// checkpoint position to the actual scan cursor.
	resumedKey := addOffsetToSeed(gotBase, gotChunk*chunkSteps)
	if got := hex.EncodeToString(resumedKey[:]); got != cp.NextPrivateKey {
		t.Fatalf("chunkBaseSeed(resumeChunk) = %s, want frontier %s", got, cp.NextPrivateKey)
	}
}

// TestResumeWithExplicitStartKey resumes a checkpoint that records both a window
// base and a frontier inside it: the base is used verbatim and the chunk is the
// floored offset from it.
func TestResumeWithExplicitStartKey(t *testing.T) {
	base := mustSeed(t, "0000000000000000000000000000000000000000000000000000000000000001")
	cp := &checkpointFile{
		Version:        checkpointVersion,
		StartKey:       hex.EncodeToString(base[:]),
		NextPrivateKey: privateKeyHexFromBase(base, 85002*chunkSteps),
	}
	gotBase, err := resumeBaseSeed(cp)
	if err != nil {
		t.Fatalf("resumeBaseSeed: %v", err)
	}
	if gotBase != base {
		t.Fatalf("base = %x, want %x", gotBase, base)
	}
	gotChunk, err := resumeStartChunk(cp, gotBase)
	if err != nil {
		t.Fatalf("resumeStartChunk: %v", err)
	}
	if gotChunk != 85002 {
		t.Fatalf("chunk = %d, want 85002", gotChunk)
	}
}

// TestResumeNoStartKeyReanchorsFarKey is the regression test for the user's bug:
// a hand-written checkpoint with ONLY next_private_key (no start_key) set to a
// key far past key 1 used to fail ("outside the supported scan window"). It must
// now anchor the window AT that key and resume from chunk 0.
func TestResumeNoStartKeyReanchorsFarKey(t *testing.T) {
	frontier := "a7f31c92b04d0210000000000000000000000000000000000000000000000001"
	cp := &checkpointFile{
		Version:        checkpointVersion,
		NextPrivateKey: frontier, // no StartKey
	}
	base, err := resumeBaseSeed(cp)
	if err != nil {
		t.Fatalf("resumeBaseSeed: %v", err)
	}
	if hex.EncodeToString(base[:]) != frontier {
		t.Fatalf("base = %x, want re-anchored to frontier %s", base, frontier)
	}
	chunk, err := resumeStartChunk(cp, base)
	if err != nil {
		t.Fatalf("resumeStartChunk: %v", err)
	}
	if chunk != 0 {
		t.Fatalf("chunk = %d, want 0 (window anchored at frontier)", chunk)
	}
}

// TestResumeNoStartKeyLegacySmallKey covers a legacy key-1 checkpoint (no
// start_key) with a small frontier: it must resume cleanly (re-anchored at the
// frontier, chunk 0) rather than erroring.
func TestResumeNoStartKeyLegacySmallKey(t *testing.T) {
	frontier := "0000000000000000000000000000000000000000000000000000000052f98001"
	cp := &checkpointFile{
		Version:        checkpointVersion,
		NextPrivateKey: frontier,
	}
	base, err := resumeBaseSeed(cp)
	if err != nil {
		t.Fatalf("resumeBaseSeed: %v", err)
	}
	if hex.EncodeToString(base[:]) != frontier {
		t.Fatalf("base = %x, want %s", base, frontier)
	}
	chunk, err := resumeStartChunk(cp, base)
	if err != nil {
		t.Fatalf("resumeStartChunk: %v", err)
	}
	if chunk != 0 {
		t.Fatalf("chunk = %d, want 0", chunk)
	}
}

// TestResumeStartChunkFloorsToBoundary verifies a hand-edited frontier that is
// NOT chunk-aligned floors DOWN to the chunk boundary, so a resume re-scans a
// partial chunk at worst and never skips keys.
func TestResumeStartChunkFloorsToBoundary(t *testing.T) {
	base := startKeyOne
	// Frontier 5 full chunks + 123 keys past base.
	frontier := addOffsetToSeed(base, 5*chunkSteps+123)
	cp := &checkpointFile{
		Version:        checkpointVersion,
		StartKey:       hex.EncodeToString(base[:]),
		NextPrivateKey: hex.EncodeToString(frontier[:]),
	}
	chunk, err := resumeStartChunk(cp, base)
	if err != nil {
		t.Fatalf("resumeStartChunk: %v", err)
	}
	if chunk != 5 {
		t.Fatalf("chunk = %d, want 5 (floored)", chunk)
	}
}

// TestResumeRejectsInvalidKeys verifies the resume helpers reject malformed or
// out-of-range keys with a clear error in both the start_key and no-start_key
// paths.
func TestResumeRejectsInvalidKeys(t *testing.T) {
	// Odd-length next_private_key, no start_key.
	if _, err := resumeBaseSeed(&checkpointFile{NextPrivateKey: "abc"}); err == nil {
		t.Fatalf("expected error for short next_private_key")
	}
	// next_private_key = key 0 (point at infinity), no start_key.
	zero := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := resumeBaseSeed(&checkpointFile{NextPrivateKey: zero}); err == nil {
		t.Fatalf("expected error for key 0 as window base")
	}
	// Bad start_key.
	if _, err := resumeBaseSeed(&checkpointFile{StartKey: "xyz", NextPrivateKey: zero}); err == nil {
		t.Fatalf("expected error for bad start_key")
	}
}

// TestReadCheckpointErrors covers the on-disk validation: bad JSON, wrong
// version, and a missing frontier key must all be rejected.
func TestReadCheckpointErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := readCheckpoint(write("bad.json", "{not json")); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
	if _, err := readCheckpoint(write("v1.json", `{"version":1,"next_private_key":"`+
		`0000000000000000000000000000000000000000000000000000000000000001"}`)); err == nil {
		t.Fatalf("expected error for unsupported version")
	}
	if _, err := readCheckpoint(write("nokey.json", `{"version":2}`)); err == nil {
		t.Fatalf("expected error for missing next_private_key")
	}
	if _, err := readCheckpoint(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

// TestCheckpointResumeContinuity is an end-to-end-style continuity check: write a
// checkpoint, resume it, write a SECOND checkpoint further along, and confirm the
// second frontier is strictly past the first while the window base is preserved.
func TestCheckpointResumeContinuity(t *testing.T) {
	base := mustSeed(t, "a7f31c92b04d0210000000000000000000000000000000000000000000000001")
	withStartKeySeed(t, base)
	path := filepath.Join(t.TempDir(), "cp.json")

	if err := writeCheckpoint(path, 10, 4); err != nil {
		t.Fatalf("writeCheckpoint #1: %v", err)
	}
	cp1, err := readCheckpoint(path)
	if err != nil {
		t.Fatalf("readCheckpoint #1: %v", err)
	}
	b1, _ := resumeBaseSeed(cp1)
	c1, _ := resumeStartChunk(cp1, b1)
	if c1 != 10 {
		t.Fatalf("resumed chunk #1 = %d, want 10", c1)
	}

	// Simulate progress: a later run advances the frontier to chunk 25.
	if err := writeCheckpoint(path, 25, 8); err != nil {
		t.Fatalf("writeCheckpoint #2: %v", err)
	}
	cp2, err := readCheckpoint(path)
	if err != nil {
		t.Fatalf("readCheckpoint #2: %v", err)
	}
	if cp2.StartKey != cp1.StartKey {
		t.Fatalf("window base changed across resume: %s -> %s", cp1.StartKey, cp2.StartKey)
	}
	b2, _ := resumeBaseSeed(cp2)
	c2, _ := resumeStartChunk(cp2, b2)
	if c2 <= c1 {
		t.Fatalf("frontier did not advance: chunk %d -> %d", c1, c2)
	}
}
