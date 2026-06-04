//go:build !darwin || !cgo || nometal

// This is the portable fallback for the metal package: it is built on every
// platform/build that is NOT (darwin && cgo && !nometal) — i.e. Linux, Windows,
// CGO_ENABLED=0 cross-compiles, and the explicit `nometal` opt-out. It exposes
// the same symbols as metal_darwin.go so callers compile unchanged, but reports
// the GPU as unavailable, so the program transparently uses the CPU hot path.
package metal

import "errors"

var errUnavailable = errors.New("metal: GPU acceleration is unavailable in this build (requires native darwin + cgo)")

// Available always reports false in the stub build.
func Available() bool { return false }

// Hasher is an empty placeholder mirroring the darwin type's method set.
type Hasher struct{}

// Buffer is an empty placeholder mirroring the darwin type's method set.
type Buffer struct{ data []byte }

// New always fails in the stub build.
func New() (*Hasher, error) { return nil, errUnavailable }

// Name returns a sentinel for the stub build.
func (h *Hasher) Name() string { return "none" }

// Close is a no-op in the stub build.
func (h *Hasher) Close() {}

// NewBuffer always fails in the stub build.
func (h *Hasher) NewBuffer(n int) (*Buffer, error) { return nil, errUnavailable }

// Bytes returns nil in the stub build.
func (b *Buffer) Bytes() []byte { return b.data }

// Free is a no-op in the stub build.
func (b *Buffer) Free() {}

// Hash160 always fails in the stub build.
func (h *Hasher) Hash160(in, out *Buffer, count, stride int) error { return errUnavailable }

// Hash160Filter always fails in the stub build.
func (h *Hasher) Hash160Filter(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	return errUnavailable
}

// GLVFilter always fails in the stub build.
func (h *Hasher) GLVFilter(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	return errUnavailable
}

// ECWalkBatch mirrors the darwin constant so callers compile unchanged.
const ECWalkBatch = 16

// GLVWalk always fails in the stub build.
func (h *Hasher) GLVWalk(starts, txX, txY, bloom, mcount, mdata *Buffer, gthreads int, mask, k uint32) error {
	return errUnavailable
}

// Stream is an empty placeholder mirroring the darwin type's method set.
type Stream struct{}

// NewStream always fails in the stub build.
func (h *Hasher) NewStream() (*Stream, error) { return nil, errUnavailable }

// Free is a no-op in the stub build.
func (s *Stream) Free() {}

// Hash160FilterStream always fails in the stub build.
func (s *Stream) Hash160FilterStream(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	return errUnavailable
}

// GLVFilterStream always fails in the stub build.
func (s *Stream) GLVFilterStream(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	return errUnavailable
}

// GLVWalkStream always fails in the stub build.
func (s *Stream) GLVWalkStream(starts, txX, txY, bloom, mcount, mdata *Buffer, gthreads int, mask, k uint32) error {
	return errUnavailable
}
