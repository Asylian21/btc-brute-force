//go:build darwin && cgo && !nometal

// bridge.h - C API over the Objective-C / Metal implementation in bridge.m.
//
// The Go cgo wrapper (metal_darwin.go) calls only these functions. All Metal
// objects (device, queue, library, pipelines, buffers) are owned by the C side;
// Go only holds opaque handles and the shared-buffer contents pointers it
// writes into.
//
// The API is kernel-agnostic: mh_init compiles a Metal library once, callers
// build one compute pipeline per kernel function (mh_new_pipeline) and dispatch
// any of them over arbitrary buffer/scalar arguments (mh_dispatch). This lets
// the package host several kernels (hash160, on-GPU Bloom filter, secp256k1
// field-op test kernels, the full EC walk) from a single compiled library.

#ifndef BTC_BRUTE_FORCE_METAL_BRIDGE_H
#define BTC_BRUTE_FORCE_METAL_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

typedef struct mh_ctx mh_ctx;

// A Metal shared (unified-memory) buffer. `ptr` aliases GPU-visible memory the
// caller can write/read directly with zero copy on Apple Silicon.
typedef struct {
    void*    buf; // id<MTLBuffer> (retained)
    uint8_t* ptr; // [buf contents]
    size_t   len;
} mh_buffer;

// mh_init compiles the kernel source into a Metal library and creates the
// device + command queue. On failure it returns NULL and, if err != NULL, sets
// *err to a malloc'd message the caller must free(). It does NOT build any
// pipeline; use mh_new_pipeline for each kernel function.
mh_ctx* mh_init(const char* metal_source, char** err);
void    mh_close(mh_ctx* ctx);

// mh_device_name returns the GPU device name (owned by ctx, valid until close).
const char* mh_device_name(mh_ctx* ctx);

// mh_new_pipeline builds a compute pipeline for the named kernel function from
// the compiled library. Returns a retained pipeline handle (opaque), or NULL
// and, if err != NULL, a malloc'd message. Release it with mh_release_pipeline.
void* mh_new_pipeline(mh_ctx* ctx, const char* fn_name, char** err);
void  mh_release_pipeline(void* pipeline);

// mh_new_buffer allocates a shared buffer of `bytes` and fills *out. Returns 0
// on success, non-zero on failure.
int  mh_new_buffer(mh_ctx* ctx, size_t bytes, mh_buffer* out);
void mh_free_buffer(mh_buffer* b);

// mh_new_queue creates an independent command queue (retained), so different
// producer goroutines can submit and wait on their own queue without a global
// lock. The GPU then overlaps work from several queues instead of running one
// globally-serialized dispatch at a time. Release with mh_release_queue.
void* mh_new_queue(mh_ctx* ctx);
void  mh_release_queue(void* queue);

// mh_dispatch runs `pipeline` over `grid` threads on `queue` (NULL => the
// context's default queue). It binds bufs[0..nbufs) at buffer indices
// 0..nbufs-1, then binds each 32-bit value in scalars[0..nscalars) via setBytes
// at indices nbufs..nbufs+nscalars-1 (so kernel argument order is buffers first,
// then scalars). It blocks until the GPU finishes. Returns 0 on success,
// non-zero on error. `bufs` entries are id<MTLBuffer> handles (the
// mh_buffer.buf field).
int mh_dispatch(mh_ctx* ctx, void* queue, void* pipeline,
                void** bufs, uint32_t nbufs,
                const uint32_t* scalars, uint32_t nscalars,
                uint32_t grid);

#endif // BTC_BRUTE_FORCE_METAL_BRIDGE_H
