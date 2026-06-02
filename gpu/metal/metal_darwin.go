//go:build darwin && cgo && !nometal

// Package metal provides an Apple Metal GPU implementation of the Hash160 hot
// path (RIPEMD160(SHA256(pubkey))). It is the GPU half of the producer/consumer
// pipeline: CPU workers fill shared pubkey buffers via the secp256k1 walk and
// this package hashes whole batches on the GPU.
//
// On Apple Silicon the buffers live in unified memory, so the pubkey input and
// the Hash160 output are written/read in place with zero copy across the CPU/GPU
// boundary. The kernel source (hash160.metal) is compiled at startup.
//
// This file is built only on darwin with cgo; every other platform/build uses
// the metal_stub.go fallback, which reports the GPU as unavailable. The package
// exposes the same symbols in both builds so the caller compiles everywhere.
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

// Available reports whether this build can attempt GPU acceleration. A nil
// device is still possible at New time (e.g. headless CI), which New surfaces.
func Available() bool { return true }

// Hasher owns a Metal device, command queue, and compiled hash160 pipeline.
// Hash160 dispatches are serialized by mu because they share one command queue;
// throughput comes from large batches and CPU/GPU overlap, not concurrent
// dispatch. A Hasher is safe for use by multiple goroutines.
type Hasher struct {
	ctx  *C.mh_ctx
	name string
	mu   sync.Mutex
}

// Buffer is a Metal shared (unified-memory) allocation. Bytes returns a Go slice
// aliasing GPU-visible memory: writing into it (the pubkey batch) or reading
// from it (the Hash160 results) needs no copy on Apple Silicon.
type Buffer struct {
	b    C.mh_buffer
	data []byte
}

// New creates a Hasher, compiling the kernel and building the pipeline. It
// returns an error if no Metal device is present or the kernel fails to build.
func New() (*Hasher, error) {
	csrc := C.CString(metalSource)
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
	return &Hasher{ctx: ctx, name: C.GoString(C.mh_device_name(ctx))}, nil
}

// Name returns the GPU device name (e.g. "Apple M3").
func (h *Hasher) Name() string { return h.name }

// Close releases all Metal resources. The Hasher must not be used afterwards.
func (h *Hasher) Close() {
	if h != nil && h.ctx != nil {
		C.mh_close(h.ctx)
		h.ctx = nil
	}
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

// Hash160 computes count Hash160 digests from in (count messages at stride
// bytes, first 33 used) into out (count*20 bytes). in and out should be buffers
// from NewBuffer for zero-copy. The call blocks until the GPU finishes.
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

	// Keep the cgo/Metal calls on one OS thread for the duration of a dispatch.
	runtime.LockOSThread()
	h.mu.Lock()
	rc := C.mh_run(h.ctx, &in.b, &out.b, C.uint32_t(count), C.uint32_t(stride))
	h.mu.Unlock()
	runtime.UnlockOSThread()

	if rc != 0 {
		return fmt.Errorf("metal: dispatch failed (code %d)", int(rc))
	}
	return nil
}
