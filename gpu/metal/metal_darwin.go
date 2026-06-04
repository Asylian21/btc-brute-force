//go:build darwin && cgo && !nometal

// Package metal provides an Apple Metal GPU implementation of the search hot
// path. It started as a Hash160 (RIPEMD160(SHA256(pubkey))) offload and grows
// toward a full on-GPU pipeline (secp256k1 EC walk + GLV expansion + Hash160 +
// on-device target filtering). CPU producers fill shared buffers and/or hand
// out chunk ranges; this package runs the GPU kernels.
//
// On Apple Silicon the buffers live in unified memory, so inputs and outputs
// are written/read in place with zero copy across the CPU/GPU boundary. The
// kernel source is compiled once into a Metal library at startup; individual
// kernels are exposed as compute pipelines built on demand and dispatched
// generically (see bridge.h).
//
// This file is built only on darwin with cgo; every other platform/build uses
// the metal_stub.go fallback, which reports the GPU as unavailable. The package
// exposes the same cross-platform symbols in both builds so the caller compiles
// everywhere.
package metal

/*
#cgo darwin LDFLAGS: -framework Metal -framework Foundation
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

//go:embed hash160.metal
var metalSource string

//go:embed secp_field.metal
var secpFieldSource string

//go:embed ec_walk.metal
var ecWalkSource string

// metalLibrarySource is the full source compiled into the Metal library. It is
// the concatenation of every embedded .metal fragment, in dependency order:
// hash160 (Hash160 + Bloom probe), then the secp256k1 field library (fe_*), then
// the EC-walk kernel (point arithmetic + batched walk), which uses both. Keeping
// it a single package-level string means New (production) and newWithSource
// (tests) share exactly the same production kernels.
func metalLibrarySource() string {
	return metalSource + "\n" + secpFieldSource + "\n" + ecWalkSource
}

// Available reports whether this build can attempt GPU acceleration. A nil
// device is still possible at New time (e.g. headless CI), which New surfaces.
func Available() bool { return true }

// Hasher owns a Metal device, command queue, compiled library, and a cache of
// compute pipelines keyed by kernel function name. Dispatches are serialized by
// mu because they share one command queue; throughput comes from large batches
// and CPU/GPU overlap, not concurrent dispatch. A Hasher is safe for use by
// multiple goroutines.
type Hasher struct {
	ctx  *C.mh_ctx
	name string
	mu   sync.Mutex // serializes GPU dispatches (one shared command queue)

	pmu   sync.Mutex                // guards pipes
	pipes map[string]unsafe.Pointer // kernel function name -> retained pipeline
}

// Buffer is a Metal shared (unified-memory) allocation. Bytes returns a Go slice
// aliasing GPU-visible memory: writing into it (the pubkey batch) or reading
// from it (the Hash160 results) needs no copy on Apple Silicon.
type Buffer struct {
	b    C.mh_buffer
	data []byte
}

// New creates a Hasher, compiling the kernel library and building the hash160
// pipeline (so a broken kernel fails fast here). It returns an error if no Metal
// device is present or the kernel fails to build.
func New() (*Hasher, error) { return newWithSource(metalLibrarySource()) }

// newWithSource builds a Hasher from arbitrary kernel source. Production uses
// New (the embedded library); tests use this to compile extra differential
// kernels (e.g. secp256k1 field-op probes) alongside the production source.
func newWithSource(src string) (*Hasher, error) {
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))

	var cerr *C.char
	ctx := C.mh_init(csrc, &cerr)
	if ctx == nil {
		msg := "metal: initialization failed"
		if cerr != nil {
			msg = "metal: " + C.GoString(cerr)
			C.free(unsafe.Pointer(cerr))
		}
		return nil, errors.New(msg)
	}
	h := &Hasher{
		ctx:   ctx,
		name:  C.GoString(C.mh_device_name(ctx)),
		pipes: make(map[string]unsafe.Pointer),
	}
	// Build the core hash160 pipeline eagerly so a compile/link problem with the
	// production kernel surfaces at construction time, not mid-run.
	if _, err := h.pipeline("hash160_kernel"); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// Name returns the GPU device name (e.g. "Apple M3").
func (h *Hasher) Name() string { return h.name }

// Close releases all Metal resources (pipelines, library, queue, device). The
// Hasher must not be used afterwards.
func (h *Hasher) Close() {
	if h == nil {
		return
	}
	h.pmu.Lock()
	for _, p := range h.pipes {
		C.mh_release_pipeline(p)
	}
	h.pipes = nil
	h.pmu.Unlock()
	if h.ctx != nil {
		C.mh_close(h.ctx)
		h.ctx = nil
	}
}

// pipeline returns the cached compute pipeline for a kernel function, building
// and caching it on first use.
func (h *Hasher) pipeline(name string) (unsafe.Pointer, error) {
	h.pmu.Lock()
	defer h.pmu.Unlock()
	if p, ok := h.pipes[name]; ok {
		return p, nil
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var cerr *C.char
	p := C.mh_new_pipeline(h.ctx, cname, &cerr)
	if p == nil {
		msg := "metal: pipeline build failed for " + name
		if cerr != nil {
			msg = "metal: " + C.GoString(cerr) + " (" + name + ")"
			C.free(unsafe.Pointer(cerr))
		}
		return nil, errors.New(msg)
	}
	h.pipes[name] = p
	return p, nil
}

// NewBuffer allocates an n-byte shared buffer. Free it with (*Buffer).Free.
func (h *Hasher) NewBuffer(n int) (*Buffer, error) {
	if n <= 0 {
		return nil, fmt.Errorf("metal: invalid buffer size %d", n)
	}
	var cb C.mh_buffer
	if C.mh_new_buffer(h.ctx, C.size_t(n), &cb) != 0 {
		return nil, errors.New("metal: shared buffer allocation failed")
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(cb.ptr)), n)
	return &Buffer{b: cb, data: data}, nil
}

// Bytes returns the slice aliasing this buffer's shared memory.
func (b *Buffer) Bytes() []byte { return b.data }

// Free releases the underlying Metal buffer. Bytes must not be used afterwards.
func (b *Buffer) Free() {
	if b != nil && b.b.buf != nil {
		C.mh_free_buffer(&b.b)
		b.data = nil
	}
}

// dispatch runs the named kernel on the default command queue, serialized by mu.
// Used by low-frequency paths (the self-test, calibration, Hash160) where the
// global lock is fine. The high-throughput run uses a per-producer Stream.
func (h *Hasher) dispatch(pipelineName string, bufs []*Buffer, scalars []uint32, grid int) error {
	return h.dispatchOn(nil, true, pipelineName, bufs, scalars, grid)
}

// dispatchOn runs the named kernel over `grid` threads on `queue` (nil => default
// queue), binding bufs at buffer indices 0..len(bufs)-1 and scalars via setBytes
// at the following indices (so kernel argument order is buffers first, then
// scalars). If lock is true it serializes on mu (default-queue callers); a Stream
// passes lock=false because each Stream/queue is owned by a single goroutine, so
// independent producers run concurrently and the GPU overlaps their work. It
// blocks until the GPU finishes.
func (h *Hasher) dispatchOn(queue unsafe.Pointer, lock bool, pipelineName string, bufs []*Buffer, scalars []uint32, grid int) error {
	if grid <= 0 {
		return nil
	}
	pipe, err := h.pipeline(pipelineName)
	if err != nil {
		return err
	}

	handles := make([]unsafe.Pointer, len(bufs))
	for i, b := range bufs {
		if b == nil || b.b.buf == nil {
			return fmt.Errorf("metal: dispatch %s: nil buffer at index %d", pipelineName, i)
		}
		handles[i] = unsafe.Pointer(b.b.buf)
	}

	var bufsPtr *unsafe.Pointer
	if len(handles) > 0 {
		bufsPtr = &handles[0]
	}
	var scalarsPtr *C.uint32_t
	if len(scalars) > 0 {
		scalarsPtr = (*C.uint32_t)(unsafe.Pointer(&scalars[0]))
	}

	runtime.LockOSThread()
	if lock {
		h.mu.Lock()
	}
	rc := C.mh_dispatch(h.ctx, queue, pipe,
		bufsPtr, C.uint32_t(len(handles)),
		scalarsPtr, C.uint32_t(len(scalars)),
		C.uint32_t(grid))
	if lock {
		h.mu.Unlock()
	}
	runtime.UnlockOSThread()

	// Keep handles alive across the cgo call (defensive; cgo already pins args).
	runtime.KeepAlive(handles)
	runtime.KeepAlive(scalars)
	runtime.KeepAlive(bufs)

	if rc != 0 {
		return fmt.Errorf("metal: dispatch %s failed (code %d)", pipelineName, int(rc))
	}
	return nil
}

// Stream is an independent command queue. Each GPU producer goroutine owns one
// Stream and dispatches on it without the global lock, so the GPU overlaps work
// submitted from several producers instead of running one serialized dispatch at
// a time. A Stream is NOT safe for concurrent use by multiple goroutines.
type Stream struct {
	h *Hasher
	q unsafe.Pointer
}

// NewStream creates a command queue for one producer goroutine.
func (h *Hasher) NewStream() (*Stream, error) {
	q := C.mh_new_queue(h.ctx)
	if q == nil {
		return nil, errors.New("metal: command queue creation failed")
	}
	return &Stream{h: h, q: q}, nil
}

// Free releases the stream's command queue.
func (s *Stream) Free() {
	if s != nil && s.q != nil {
		C.mh_release_queue(s.q)
		s.q = nil
	}
}

// Hash160FilterStream is Hash160Filter dispatched on this stream's own queue
// (no global lock), for concurrent producers. See Hash160Filter for the buffer
// and scalar contract; the caller must zero mcount before each call.
func (s *Stream) Hash160FilterStream(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	if count <= 0 {
		return nil
	}
	if stride < 33 {
		return fmt.Errorf("metal: stride %d too small (need >= 33)", stride)
	}
	if len(in.data) < count*stride {
		return fmt.Errorf("metal: input buffer too small: have %d need %d", len(in.data), count*stride)
	}
	if len(mcount.data) < 4 {
		return fmt.Errorf("metal: mcount buffer too small: have %d need >= 4", len(mcount.data))
	}
	if len(mdata.data) < count*4 {
		return fmt.Errorf("metal: mdata buffer too small: have %d need %d", len(mdata.data), count*4)
	}
	return s.h.dispatchOn(s.q, false, "hash160_filter_kernel",
		[]*Buffer{in, bloom, mcount, mdata},
		[]uint32{uint32(stride), uint32(count), mask, k},
		count)
}

// glvFilterArgs validates the shared GLV-filter buffer/scalar contract used by
// both GLVFilter and GLVFilterStream. count is the number of base pubkeys (walk
// steps); the kernel expands each into 6 GLV+negation variants internally.
func glvFilterArgs(in, mcount, mdata *Buffer, count, stride int) error {
	if stride < 33 {
		return fmt.Errorf("metal: stride %d too small (need >= 33)", stride)
	}
	if len(in.data) < count*stride {
		return fmt.Errorf("metal: input buffer too small: have %d need %d", len(in.data), count*stride)
	}
	if len(mcount.data) < 4 {
		return fmt.Errorf("metal: mcount buffer too small: have %d need >= 4", len(mcount.data))
	}
	if len(mdata.data) < count*4 {
		return fmt.Errorf("metal: mdata buffer too small: have %d need %d", len(mdata.data), count*4)
	}
	return nil
}

// GLVFilter expands count base pubkeys from in (stride bytes each, first 33 =
// prefix+X) into their 6 GLV+negation variants on the GPU, hashes each, and
// tests it against the device Bloom filter. For every probe hit it appends the
// candidate id v*count+gid (variant v in [0,6), base step gid) to mdata via the
// atomic counter in mcount, which the CALLER must zero before each call.
//
// The candidate id matches the old full-buffer slot index (v*m+p), so the CPU
// reconstructs the private key with the existing privateKeyForVariantFromBase
// (v=id/count, p=id%count). The caller confirms each candidate against the real
// target set; the Bloom filter only accelerates (zero false negatives).
//
// Kernel argument order (glv_filter_kernel): buffer(0)=bases, buffer(1)=bloom,
// buffer(2)=mcount, buffer(3)=mdata, then scalars stride, count, mask, k.
func (h *Hasher) GLVFilter(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	if count <= 0 {
		return nil
	}
	if err := glvFilterArgs(in, mcount, mdata, count, stride); err != nil {
		return err
	}
	return h.dispatch("glv_filter_kernel",
		[]*Buffer{in, bloom, mcount, mdata},
		[]uint32{uint32(stride), uint32(count), mask, k},
		count)
}

// GLVFilterStream is GLVFilter dispatched on this stream's own queue (no global
// lock), for concurrent producers. See GLVFilter for the buffer/scalar contract;
// the caller must zero mcount before each call.
func (s *Stream) GLVFilterStream(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	if count <= 0 {
		return nil
	}
	if err := glvFilterArgs(in, mcount, mdata, count, stride); err != nil {
		return err
	}
	return s.h.dispatchOn(s.q, false, "glv_filter_kernel",
		[]*Buffer{in, bloom, mcount, mdata},
		[]uint32{uint32(stride), uint32(count), mask, k},
		count)
}

// ECWalkBatch is the per-thread linear walk batch length: each ec_walk_glv_kernel
// thread owns ECWalkBatch consecutive scalars and amortizes one field inversion
// across them. It MUST equal the ECW_BATCH #define in ec_walk.metal. The host
// supplies one start point per thread (the coarse walk steps by ECWalkBatch*G)
// and a fine table of jG for j=1..ECWalkBatch-1.
const ECWalkBatch = 128

// glvWalkArgs validates the on-GPU EC-walk buffer contract. gthreads is the
// number of start points; L = gthreads*ECWalkBatch is the total scalars covered
// (and the candidate-id stride). starts holds gthreads affine points (16 limbs
// each: x,y); txX/txY hold ECWalkBatch-1 table points (8 limbs each).
func glvWalkArgs(starts, txX, txY, mcount, mdata *Buffer, gthreads int) error {
	if len(starts.data) < gthreads*16*4 {
		return fmt.Errorf("metal: starts buffer too small: have %d need %d", len(starts.data), gthreads*16*4)
	}
	need := (ECWalkBatch - 1) * 8 * 4
	if len(txX.data) < need || len(txY.data) < need {
		return fmt.Errorf("metal: fine table too small: have x=%d y=%d need %d", len(txX.data), len(txY.data), need)
	}
	if len(mcount.data) < 4 {
		return fmt.Errorf("metal: mcount buffer too small: have %d need >= 4", len(mcount.data))
	}
	if len(mdata.data) < gthreads*ECWalkBatch*4 {
		return fmt.Errorf("metal: mdata buffer too small: have %d need %d", len(mdata.data), gthreads*ECWalkBatch*4)
	}
	return nil
}

// GLVWalk runs the full on-GPU pipeline: each of gthreads threads walks
// ECWalkBatch consecutive points from its start (one shared inversion), expands
// each to 6 GLV+negation variants, hashes, and Bloom-filters them. Candidate ids
// v*L + linearIdx (L = gthreads*ECWalkBatch, linearIdx = gid*ECWalkBatch + j) are
// appended to mdata via the atomic counter mcount, which the CALLER must zero
// first. The CPU reconstructs the key with privateKeyForVariantFromBase using the
// dispatch base offset + linearIdx and confirms against the real target set.
//
// Kernel argument order (ec_walk_glv_kernel): buffer(0)=starts, (1)=txX, (2)=txY,
// (3)=bloom, (4)=mcount, (5)=mdata, then scalars gthreads, L, mask, k.
func (h *Hasher) GLVWalk(starts, txX, txY, bloom, mcount, mdata *Buffer, gthreads int, mask, k uint32) error {
	if gthreads <= 0 {
		return nil
	}
	if err := glvWalkArgs(starts, txX, txY, mcount, mdata, gthreads); err != nil {
		return err
	}
	L := uint32(gthreads * ECWalkBatch)
	capN := uint32(len(mdata.data) / 4)
	return h.dispatch("ec_walk_glv_kernel",
		[]*Buffer{starts, txX, txY, bloom, mcount, mdata},
		[]uint32{uint32(gthreads), L, mask, k, capN},
		gthreads)
}

// GLVWalkStream is GLVWalk dispatched on this stream's own queue (no global
// lock), for concurrent producers. See GLVWalk for the buffer/scalar contract;
// the caller must zero mcount before each call.
func (s *Stream) GLVWalkStream(starts, txX, txY, bloom, mcount, mdata *Buffer, gthreads int, mask, k uint32) error {
	if gthreads <= 0 {
		return nil
	}
	if err := glvWalkArgs(starts, txX, txY, mcount, mdata, gthreads); err != nil {
		return err
	}
	L := uint32(gthreads * ECWalkBatch)
	capN := uint32(len(mdata.data) / 4)
	return s.h.dispatchOn(s.q, false, "ec_walk_glv_kernel",
		[]*Buffer{starts, txX, txY, bloom, mcount, mdata},
		[]uint32{uint32(gthreads), L, mask, k, capN},
		gthreads)
}

// Hash160 computes count Hash160 digests from in (count messages at stride
// bytes, first 33 used) into out (count*20 bytes). in and out should be buffers
// from NewBuffer for zero-copy. The call blocks until the GPU finishes.
//
// Kernel argument order (hash160_kernel): buffer(0)=pubkeys, buffer(1)=out,
// buffer(2)=stride, buffer(3)=count.
func (h *Hasher) Hash160(in, out *Buffer, count, stride int) error {
	if count <= 0 {
		return nil
	}
	if stride < 33 {
		return fmt.Errorf("metal: stride %d too small (need >= 33)", stride)
	}
	if len(in.data) < count*stride {
		return fmt.Errorf("metal: input buffer too small: have %d need %d", len(in.data), count*stride)
	}
	if len(out.data) < count*20 {
		return fmt.Errorf("metal: output buffer too small: have %d need %d", len(out.data), count*20)
	}
	return h.dispatch("hash160_kernel", []*Buffer{in, out}, []uint32{uint32(stride), uint32(count)}, count)
}

// Hash160Filter hashes count pubkeys from in (stride bytes each, first 33 used)
// and tests each digest against the device Bloom filter `bloom`. It appends the
// gid of every candidate (all probe bits set) to mdata via the atomic counter
// in mcount, which the CALLER must zero before each call. mask is the filter's
// power-of-two-minus-one bit mask and k its probe count.
//
// The caller reads the first uint32 of mcount for the candidate count (bounded
// by count) and the first that-many uint32s of mdata for the gids, then confirms
// each against the real target set. There is no per-key readback.
//
// Kernel argument order (hash160_filter_kernel): buffer(0)=pubkeys,
// buffer(1)=bloom, buffer(2)=mcount, buffer(3)=mdata, then scalars stride,
// count, mask, k.
func (h *Hasher) Hash160Filter(in, bloom, mcount, mdata *Buffer, count, stride int, mask, k uint32) error {
	if count <= 0 {
		return nil
	}
	if stride < 33 {
		return fmt.Errorf("metal: stride %d too small (need >= 33)", stride)
	}
	if len(in.data) < count*stride {
		return fmt.Errorf("metal: input buffer too small: have %d need %d", len(in.data), count*stride)
	}
	if len(mcount.data) < 4 {
		return fmt.Errorf("metal: mcount buffer too small: have %d need >= 4", len(mcount.data))
	}
	if len(mdata.data) < count*4 {
		return fmt.Errorf("metal: mdata buffer too small: have %d need %d", len(mdata.data), count*4)
	}
	return h.dispatch("hash160_filter_kernel",
		[]*Buffer{in, bloom, mcount, mdata},
		[]uint32{uint32(stride), uint32(count), mask, k},
		count)
}
