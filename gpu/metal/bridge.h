//go:build darwin && cgo && !nometal

// bridge.h — C API over the Objective-C / Metal implementation in bridge.m.
//
// The Go cgo wrapper (metal_darwin.go) calls only these functions. All Metal
// objects (device, queue, pipeline, buffers) are owned by the C side; Go only
// holds opaque handles and the shared-buffer contents pointers it writes into.

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

// mh_init compiles the kernel source and builds the compute pipeline. On
// failure it returns NULL and, if err != NULL, sets *err to a malloc'd message
// the caller must free().
mh_ctx* mh_init(const char* metal_source, char** err);
void    mh_close(mh_ctx* ctx);

// mh_device_name returns the GPU device name (owned by ctx, valid until close).
const char* mh_device_name(mh_ctx* ctx);

// mh_new_buffer allocates a shared buffer of `bytes` and fills *out. Returns 0
// on success, non-zero on failure.
int  mh_new_buffer(mh_ctx* ctx, size_t bytes, mh_buffer* out);
void mh_free_buffer(mh_buffer* b);

// mh_run dispatches the hash160 kernel over `count` messages of `stride` bytes
// from `in`, writing 20*count bytes into `out`, and blocks until completion.
// Returns 0 on success, non-zero on GPU error.
int mh_run(mh_ctx* ctx, mh_buffer* in, mh_buffer* out, uint32_t count, uint32_t stride);

#endif // BTC_BRUTE_FORCE_METAL_BRIDGE_H
