//go:build darwin && cgo && !nometal

// bridge.m — Objective-C / Metal implementation behind bridge.h.
//
// Compiled by cgo only on darwin with CGO_ENABLED=1 (guarded by the build tag
// on metal_darwin.go, which is the package's only file with `import "C"`). Uses
// manual reference counting (no ARC) and wraps every dispatch in an
// @autoreleasepool so transient command buffers/encoders do not accumulate
// across the millions of dispatches a long run performs.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdlib.h>
#include <string.h>
#include "bridge.h"

struct mh_ctx {
    id<MTLDevice>              device;
    id<MTLCommandQueue>        queue;
    id<MTLComputePipelineState> pipeline;
    char*                      name;
    NSUInteger                 tgSize; // threads per threadgroup
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

        id<MTLFunction> fn = [lib newFunctionWithName:@"hash160_kernel"];
        if (fn == nil) {
            if (err) *err = copy_cstr("kernel function hash160_kernel not found");
            [lib release];
            [device release];
            return NULL;
        }

        id<MTLComputePipelineState> pipe = [device newComputePipelineStateWithFunction:fn error:&nserr];
        [fn release];
        [lib release];
        if (pipe == nil) {
            if (err) *err = copy_cstr(nserr ? [[nserr localizedDescription] UTF8String] : "pipeline creation failed");
            [device release];
            return NULL;
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (queue == nil) {
            if (err) *err = copy_cstr("command queue creation failed");
            [pipe release];
            [device release];
            return NULL;
        }

        mh_ctx* ctx = (mh_ctx*)calloc(1, sizeof(mh_ctx));
        ctx->device = device;
        ctx->queue = queue;
        ctx->pipeline = pipe;
        ctx->name = copy_cstr([[device name] UTF8String]);
        NSUInteger maxT = pipe.maxTotalThreadsPerThreadgroup;
        ctx->tgSize = maxT < 256 ? maxT : 256;
        return ctx;
    }
}

void mh_close(mh_ctx* ctx) {
    if (ctx == NULL) return;
    [ctx->pipeline release];
    [ctx->queue release];
    [ctx->device release];
    free(ctx->name);
    free(ctx);
}

const char* mh_device_name(mh_ctx* ctx) {
    return ctx ? ctx->name : "";
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

int mh_run(mh_ctx* ctx, mh_buffer* in, mh_buffer* out, uint32_t count, uint32_t stride) {
    if (ctx == NULL || in == NULL || out == NULL || count == 0) return 1;
    @autoreleasepool {
        id<MTLCommandBuffer> cb = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeline];
        [enc setBuffer:(id<MTLBuffer>)in->buf offset:0 atIndex:0];
        [enc setBuffer:(id<MTLBuffer>)out->buf offset:0 atIndex:1];
        [enc setBytes:&stride length:sizeof(uint32_t) atIndex:2];
        [enc setBytes:&count length:sizeof(uint32_t) atIndex:3];

        NSUInteger tg = ctx->tgSize;
        if (tg > count) tg = count;
        MTLSize grid = MTLSizeMake(count, 1, 1);
        MTLSize tgs = MTLSizeMake(tg, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:tgs];
        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];

        if (cb.status != MTLCommandBufferStatusCompleted) return 2;
        return 0;
    }
}
