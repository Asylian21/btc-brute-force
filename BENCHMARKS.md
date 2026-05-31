# Performance Benchmarks

This document explains how to benchmark the Bitcoin address-collision research toolkit and how to interpret the results. The important number for the optimized program is `BenchmarkKeyStreamPerKey`, because it measures the production worker hot path: batched secp256k1 point addition plus Hash160 lookup preparation.

## How to Run Benchmarks

```bash
# Preferred: uses the same Darwin linker workaround as normal builds.
make bench

# Manual equivalent on macOS 15+ with Go < 1.24.
go test -ldflags="-s -w -linkmode=external" -bench=. -benchmem -benchtime=5s . ./bench/...

# Linux and other platforms usually do not need the linkmode flag.
go test -bench=. -benchmem -benchtime=5s . ./bench/...
```

The root package contains benchmarks for the current optimized implementation. The `bench/` package contains educational component benchmarks for the older direct key/hash/Base58 pipeline.

## Current Results

Measured locally with Go 1.22.5 on darwin/arm64:

### Runtime Throughput

On a MacBook Air M3, the optimized program reaches roughly **20 million keys/sec** in sustained multi-worker runtime output (measured around 19.9M keys/sec with 4 worker threads). This is the headline practical throughput number because it includes the actual worker pool, target Hash160 lookup, stats accounting, and runtime scheduling. The GLV endomorphism contributes twice over: it yields a second valid key per affine point for one extra field multiply (more keys per field inversion), and those endomorphism keys are real, distinct keys checked against the target set, so they are counted honestly.

### Microbenchmarks

| Benchmark | ns/op | Approx keys/sec | Memory/op | Allocs/op | What it measures |
| --- | ---: | ---: | ---: | ---: | --- |
| `BenchmarkKeyStreamPerKey` | 172.5 | ~5,797,000 keys/sec | 0 B | 0 | Optimized hot path (batched affine walk + GLV endomorphism), per checked key |
| `BenchmarkGenerateKeyAndHash160` | 29,322 | ~34,104 keys/sec | 488 B | 8 | Fresh random key + scalar multiplication + Hash160 |

`BenchmarkKeyStreamPerKey` counts every checked key, including the endomorphism image produced alongside each affine point (each linear walk step yields two keys), so its ns/op is the amortized cost per key actually compared against the target set.

The educational component benchmarks in `bench/` (the older direct key/hash/Base58 pipeline) measure separately: `BenchmarkHashPipeline` ~31,298 ns/op, `BenchmarkKeyGeneration` ~29,260 ns/op, `BenchmarkHash160` ~299.9 ns/op, `BenchmarkBase58Encode` ~67.61 ns/op.

Raw command used:

```text
make bench
```

Raw output:

```text
BenchmarkKeyStreamPerKey-8          35442716    172.5 ns/op      0 B/op   0 allocs/op
BenchmarkGenerateKeyAndHash160-8      205078  29322 ns/op      488 B/op   8 allocs/op
BenchmarkHashPipeline-8              189744  31298 ns/op      907 B/op  43 allocs/op
BenchmarkKeyGeneration-8             208429  29260 ns/op      192 B/op   4 allocs/op
BenchmarkHash160-8                 20013122    299.9 ns/op    296 B/op   4 allocs/op
BenchmarkBase58Encode-8            92944420     67.61 ns/op   144 B/op   3 allocs/op
```

## What Changed

The previous benchmark story was dominated by per-key secp256k1 scalar multiplication. That is useful for teaching the naive Bitcoin address pipeline, but it is not how the current worker is structured.

The current implementation makes one random starting scalar per worker and walks consecutive keys from that segment:

1. Compute the initial point `P = base*G` once.
2. Use precomputed multiples of the generator `G` to derive `P + iG` with affine point addition.
3. For each affine point `(x, y)`, also take its GLV endomorphism image `(beta*x, y) = lambda*P` for the cost of one field multiply — a second valid key that shares the same `y`.
4. Batch the field inversions with Montgomery's trick so one inversion covers a whole 2,048-step batch (4,096 keys with the endomorphism).
5. Hash compressed public keys with SIMD SHA256, then a multi-buffer RIPEMD160 that writes its 20-byte digests straight into the result slice (no scatter copy).
6. Compare raw 20-byte Hash160 values against the target set.
7. Encode Base58 only on the rare match path.

This is why `BenchmarkKeyStreamPerKey` is roughly 170x faster per key than `BenchmarkGenerateKeyAndHash160` in the local run above:

```text
29322 ns/op / 172.5 ns/op = ~170x
```

## Interpreting Keys/sec

Convert `ns/op` to keys/sec with:

```text
keys/sec = 1,000,000,000 / ns_per_op
```

Example:

```text
1,000,000,000 / 172.5 = ~5,797,000 keys/sec
```

Actual program throughput depends on CPU core mix, thermal throttling, worker count, Go scheduler behavior, the target set size, and background system load. For a long run, the 10-second `[Stats]` output is more representative than a short benchmark; on the MacBook Air M3 runtime run, that sustained output is about **20M keys/sec**.

## Why It Still Does Not Matter for Theft

The P2PKH hash space is 2^160, about `1.46 x 10^48` possible hashes.

Searching 1% of that space means about `1.46 x 10^46` guesses. At an optimistic 20 million keys/sec:

```text
1.46e46 / 2.0e7 seconds = 7.3e38 seconds
7.3e38 / 31,557,600 seconds/year = ~2.3e31 years
```

That is many orders of magnitude beyond any practical computation. The optimization work makes the benchmark more honest; it does not make brute forcing Bitcoin practical.

## Optimization Notes

Current production hot-path optimizations:

1. **Batched affine EC walk**: one scalar multiplication per worker, then group addition for whole batches.
2. **GLV endomorphism**: each affine point `(x, y)` also yields `(beta*x, y) = lambda*P` for one extra field multiply — a second valid key sharing the same `y` (so the `02/03` parity is shared), with private scalar `lambda*k mod n`. This doubles the keys produced per field inversion and amortizes the slope/`y3`/normalization work; see the section below.
3. **Montgomery batch inversion**: amortizes the expensive field inversion across a whole batch.
4. **Fast secp256k1 Fp field backend**: the per-key base-field arithmetic (multiply, square, add, negate, normalize, inversion) runs on [`github.com/Asylian21/secp256k1-field`](https://github.com/Asylian21/secp256k1-field), a 5x52-limb implementation with arm64/amd64 assembler kernels, instead of dcrd's pure-Go 10x26 `FieldVal`. Field math was the dominant CPU cost of the walk; see the section below.
5. **Hash160 target database**: input addresses are decoded once; workers compare fixed 20-byte arrays.
6. **Specialized RIPEMD160**: avoids streaming hasher overhead for the fixed 32-byte SHA256 digest input.
7. **Zero-copy Hash160**: the multi-buffer RIPEMD160 pass writes its 20-byte digests straight into the caller's `[][20]byte` result slice (`ripemd160mb.Size == 20`), so the batch needs no intermediate output buffer and no per-key scatter copy.
8. **SIMD SHA256**: uses `minio/sha256-simd` for compressed public-key hashing and checksums.
9. **Allocation-free worker batch**: per-worker scratch buffers keep the hot loop at `0 B/op`.
10. **Batch counter updates**: atomics are updated per batch, not per key.

## GLV Endomorphism and Zero-Copy Hash160

secp256k1 admits an efficiently computable endomorphism: for any point `P = (x, y)`,
the point `(beta*x mod p, y)` is also on the curve and equals `lambda*P`, where
`beta` is a nontrivial cube root of unity in the base field `Fp` and `lambda` is
the matching cube root of unity in the scalar field `Fn`. So the affine walk gets
a second valid key per point for the cost of one field multiply (`beta*x`); it
shares the same `y`, hence the same compressed-key parity, and its private scalar
is `lambda*k mod n` (reconstructed only on the rare match path). The same batch
also stopped copying Hash160 results twice: RIPEMD160 now writes directly into the
caller's slice and SHA256 digests are stored with a single array assignment.

Back-to-back `BenchmarkKeyStreamPerKey` on a MacBook Air M3 (darwin/arm64,
Go 1.22.5, `GOMAXPROCS=1`, `-benchtime=2s -count=10`, median ns per *checked* key):

| Hot path | ns/key | keys/sec | Allocs | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Identity-only affine walk (before) | ~222.1 | ~4.50M | 0 | 1.00x |
| + GLV endomorphism + zero-copy Hash160 | ~171.5 | ~5.83M | 0 | **1.30x** |

The endomorphism halves the per-key elliptic-curve work (slope, `y3`, normalization,
and the amortized inversion are shared across the two candidates), while SHA256 and
RIPEMD160 still run per key — so the net gain is roughly **1.3x**, not 2x. The hot
loop stays at `0 allocs/op`. Reproduce:

```bash
GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=10 .
```

## secp256k1 Field (Fp) Backend

The base-field arithmetic over `p = 2^256 - 2^32 - 977` (the EC point-addition
math) was the single largest CPU cost of the key walk. The hot loop now uses
`field.Val` from `github.com/Asylian21/secp256k1-field` — a 5x52-bit limb layout
(25 wide `64x64->128` products per multiply vs dcrd's 100 narrow `32x32->64`
ones) with hand-written arm64 (MUL/UMULH) and amd64 (BMI2 MULX) kernels and a
pure-Go fallback. dcrd is retained for scalar math (`ModNScalar`,
`ScalarBaseMultNonConst`); only the per-key field math moved, bridged once per
worker via the canonical 32-byte encoding. The swap is bit-identical to dcrd
(verified by differential fuzzing) and keeps the hot loop at `0 allocs/op`.

Back-to-back `BenchmarkKeyStreamPerKey` on a MacBook Air M3 (darwin/arm64,
Go 1.22.5, `GOMAXPROCS=1`, `-benchtime=2s -count=5`, median ns/key), toggling
only the field backend (the dcrd row was measured by reverting just the field
type):

| Field backend | ns/key | keys/sec | Allocs | Speedup |
| --- | ---: | ---: | ---: | ---: |
| dcrd `FieldVal` (10x26, pure Go) | ~424 | ~2.36M | 0 | 1.00x |
| `field.Val` generic (5x52, pure Go) | ~281 | ~3.56M | 0 | **1.51x** |
| `field.Val` arm64 asm (5x52, MUL/UMULH) | ~215 | ~4.65M | 0 | **1.98x** |

The assembler backend nearly **doubles** single-thread hot-loop throughput. The
gain exceeds a naive "multiply only" estimate because the 5x52 layout also
speeds up add/negate/normalize and the Montgomery inversion (~2.8x faster than
dcrd's). Component micro-benchmarks (in the field library) measure the arm64
kernels at Mul 3.28x, Square 2.86x, and Inverse 2.81x versus dcrd.

Reproduce the backend comparison:

```bash
# assembler (default on arm64/amd64+BMI2)
GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=5 .

# portable backend
GOSECP256K1FIELD_FORCE=generic GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=5 .
```

## Memory Usage

- Per worker: batch buffers for Hash160 output and elliptic-curve scratch values.
- Target database: one Go map entry per valid P2PKH address, keyed by `[20]byte`.
- Checkpoints: small JSON files containing one saved next private key per segment.

Large address lists, checkpoint files, and match outputs are intentionally git-ignored because they are runtime inputs or outputs, not source artifacts.

## Contributing Benchmarks

To add benchmark results:

1. Run `make bench` on an idle system.
2. Record CPU model, architecture, Go version, OS, power mode, and worker-relevant context.
3. Include raw benchmark output.
4. Compare `BenchmarkKeyStreamPerKey` for the optimized hot path and `BenchmarkGenerateKeyAndHash160` for the direct scalar-multiplication baseline.
