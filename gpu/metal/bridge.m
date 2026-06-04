//go:build darwin && cgo && !nometal

// bridge.m - Objective-C / Metal implementation behind bridge.h.
//
// Compiled by cgo only on darwin with CGO_ENABLED=1 (guarded by the build tag
// on metal_darwin.go, which is the package's only file with `import "C"`). Uses
// manual reference counting (no ARC) and wraps every dispatch in an
// @autoreleasepool so transient command buffers/encoders do not accumulate
// across the millions of dispatches a long run performs.
//
// The context owns the device, a command queue, and the compiled library.
// Pipelines are built per kernel function and dispatched generically, so the
// same library can host hash160, the on-GPU Bloom filter, the secp256k1
// field-op test kernels, and the full EC walk without recompiling.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdlib.h>
#include <string.h>
#include "bridge.h"

struct mh_ctx {
    id<MTLDevice>       device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary>      lib;
    char*               name;
};

static char* copy_cstr(const char* s) {
    size_t n = strlen(s) + 1;
    char* d = (char*)malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

mh_ctx* mh_init(const char* metal_source, char** err) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            if (err) *err = copy_cstr("no Metal device available");
            return NULL;
        }
        [device retain];

        NSError* nserr = nil;
        NSString* src = [NSString stringWithUTF8String:metal_source];
        MTLCompileOptions* opts = [[MTLCompileOptions alloc] init];
        id<MTLLibrary> lib = [device newLibraryWithSource:src options:opts error:&nserr];
        [opts release];
        if (lib == nil) {
            if (err) *err = copy_cstr(nserr ? [[nserr localizedDescription] UTF8String] : "kernel compile failed");
            [device release];
            return NULL;
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (queue == nil) {
            if (err) *err = copy_cstr("command queue creation failed");
            [lib release];
            [device release];
            return NULL;
        }

        mh_ctx* ctx = (mh_ctx*)calloc(1, sizeof(mh_ctx));
        ctx->device = device;
        ctx->queue = queue;
        ctx->lib = lib;
        ctx->name = copy_cstr([[device name] UTF8String]);
        return ctx;
    }
}

void mh_close(mh_ctx* ctx) {
    if (ctx == NULL) return;
    [ctx->lib release];
    [ctx->queue release];
    [ctx->device release];
    free(ctx->name);
    free(ctx);
}

const char* mh_device_name(mh_ctx* ctx) {
    return ctx ? ctx->name : "";
}

void* mh_new_pipeline(mh_ctx* ctx, const char* fn_name, char** err) {
    if (ctx == NULL || fn_name == NULL) {
        if (err) *err = copy_cstr("mh_new_pipeline: nil context or name");
        return NULL;
    }
    @autoreleasepool {
        NSString* name = [NSString stringWithUTF8String:fn_name];
        id<MTLFunction> fn = [ctx->lib newFunctionWithName:name];
        if (fn == nil) {
            if (err) *err = copy_cstr("kernel function not found");
            return NULL;
        }
        NSError* nserr = nil;
        id<MTLComputePipelineState> pipe = [ctx->device newComputePipelineStateWithFunction:fn error:&nserr];
        [fn release];
        if (pipe == nil) {
            if (err) *err = copy_cstr(nserr ? [[nserr localizedDescription] UTF8String] : "pipeline creation failed");
            return NULL;
        }
        return (void*)pipe; // retained; released by mh_release_pipeline
    }
}

void mh_release_pipeline(void* pipeline) {
    if (pipeline == NULL) return;
    id<MTLComputePipelineState> pipe = (id<MTLComputePipelineState>)pipeline;
    [pipe release];
}

int mh_new_buffer(mh_ctx* ctx, size_t bytes, mh_buffer* out) {
    if (ctx == NULL || out == NULL || bytes == 0) return 1;
    @autoreleasepool {
        id<MTLBuffer> buf = [ctx->device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        if (buf == nil) return 1;
        out->buf = (void*)buf;
        out->ptr = (uint8_t*)[buf contents];
        out->len = bytes;
        return 0;
    }
}

void mh_free_buffer(mh_buffer* b) {
    if (b == NULL || b->buf == NULL) return;
    id<MTLBuffer> buf = (id<MTLBuffer>)b->buf;
    [buf release];
    b->buf = NULL;
    b->ptr = NULL;
    b->len = 0;
}

void* mh_new_queue(mh_ctx* ctx) {
    if (ctx == NULL) return NULL;
    // newCommandQueue follows the +1 "new" ownership convention (not
    // autoreleased), so it is returned as-is and released by mh_release_queue.
    id<MTLCommandQueue> q = [ctx->device newCommandQueue];
    if (q == nil) return NULL;
    return (void*)q;
}

void mh_release_queue(void* queue) {
    if (queue == NULL) return;
    id<MTLCommandQueue> q = (id<MTLCommandQueue>)queue;
    [q release];
}

int mh_dispatch(mh_ctx* ctx, void* queue, void* pipeline,
                void** bufs, uint32_t nbufs,
                const uint32_t* scalars, uint32_t nscalars,
                uint32_t grid) {
    if (ctx == NULL || pipeline == NULL || grid == 0) return 1;
    @autoreleasepool {
        id<MTLComputePipelineState> pipe = (id<MTLComputePipelineState>)pipeline;
        id<MTLCommandQueue> q = queue ? (id<MTLCommandQueue>)queue : ctx->queue;
        id<MTLCommandBuffer> cb = [q commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
        [enc setComputePipelineState:pipe];

        for (uint32_t i = 0; i < nbufs; i++) {
            [enc setBuffer:(id<MTLBuffer>)bufs[i] offset:0 atIndex:i];
        }
        for (uint32_t i = 0; i < nscalars; i++) {
            uint32_t v = scalars[i];
            [enc setBytes:&v length:sizeof(uint32_t) atIndex:(nbufs + i)];
        }

        NSUInteger maxT = pipe.maxTotalThreadsPerThreadgroup;
        NSUInteger tg = maxT < 256 ? maxT : 256;
        if (tg > grid) tg = grid;
        MTLSize gridSz = MTLSizeMake(grid, 1, 1);
        MTLSize tgs = MTLSizeMake(tg, 1, 1);
        [enc dispatchThreads:gridSz threadsPerThreadgroup:tgs];
        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];

        if (cb.status != MTLCommandBufferStatusCompleted) return 2;
        return 0;
    }
}
