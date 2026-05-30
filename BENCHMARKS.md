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

On a MacBook Air M3, the optimized program reaches roughly **10 million keys/sec** in sustained multi-worker runtime output. This is the headline practical throughput number because it includes the actual worker pool, target Hash160 lookup, stats accounting, and runtime scheduling.

### Microbenchmarks

| Benchmark | ns/op | Approx ops/sec | Memory/op | Allocs/op | What it measures |
| --- | ---: | ---: | ---: | ---: | --- |
| `BenchmarkKeyStreamPerKey` | 532.6 | ~1,877,582 keys/sec | 0 B | 0 | Optimized batched worker hot path |
| `BenchmarkGenerateKeyAndHash160` | 28,833 | ~34,682 keys/sec | 488 B | 8 | Fresh random key + scalar multiplication + Hash160 |
| `BenchmarkRIPEMD160Hash32` | 149.8 | ~6,675,567 ops/sec | 0 B | 0 | Specialized fixed 32-byte RIPEMD160 |
| `BenchmarkRIPEMD160Streaming` | 190.8 | ~5,241,090 ops/sec | 0 B | 0 | Reference streaming RIPEMD160 path |

Raw command used:

```text
make bench
```

Raw output:

```text
BenchmarkKeyStreamPerKey-8          11544244    532.6 ns/op      0 B/op   0 allocs/op
BenchmarkGenerateKeyAndHash160-8      200103  28833 ns/op      488 B/op   8 allocs/op
BenchmarkRIPEMD160Hash32-8         42184846    149.8 ns/op      0 B/op   0 allocs/op
BenchmarkRIPEMD160Streaming-8      31684458    190.8 ns/op      0 B/op   0 allocs/op
BenchmarkHashPipeline-8              187718  30737 ns/op      907 B/op  43 allocs/op
BenchmarkKeyGeneration-8             208545  30547 ns/op      192 B/op   4 allocs/op
BenchmarkHash160-8                 20697853    299.6 ns/op    296 B/op   4 allocs/op
BenchmarkBase58Encode-8            92063546     64.65 ns/op   144 B/op   3 allocs/op
```

## What Changed

The previous benchmark story was dominated by per-key secp256k1 scalar multiplication. That is useful for teaching the naive Bitcoin address pipeline, but it is not how the current worker is structured.

The current implementation makes one random starting scalar per worker and walks consecutive keys from that segment:

1. Compute the initial point `P = base*G` once.
2. Use precomputed multiples of the generator `G` to derive `P + iG`.
3. Batch the field inversions with Montgomery's trick so one inversion covers a 2,048-key batch.
4. Hash compressed public keys with SIMD SHA256 and a fixed-input RIPEMD160.
5. Compare raw 20-byte Hash160 values against the target set.
6. Encode Base58 only on the rare match path.

This is why `BenchmarkKeyStreamPerKey` is roughly 54x faster than `BenchmarkGenerateKeyAndHash160` in the local run above:

```text
28833 ns/op / 532.6 ns/op = ~54.1x
```

## Interpreting Keys/sec

Convert `ns/op` to keys/sec with:

```text
keys/sec = 1,000,000,000 / ns_per_op
```

Example:

```text
1,000,000,000 / 532.6 = ~1,877,582 keys/sec
```

Actual program throughput depends on CPU core mix, thermal throttling, worker count, Go scheduler behavior, the target set size, and background system load. For a long run, the 10-second `[Stats]` output is more representative than a short benchmark; on the MacBook Air M3 runtime run, that sustained output is about **10M keys/sec**.

## Why It Still Does Not Matter for Theft

The P2PKH hash space is 2^160, about `1.46 x 10^48` possible hashes.

Searching 1% of that space means about `1.46 x 10^46` guesses. At an optimistic 10 million keys/sec:

```text
1.46e46 / 1.0e7 seconds = 1.46e39 seconds
1.46e39 / 31,557,600 seconds/year = ~4.6e31 years
```

That is many orders of magnitude beyond any practical computation. The optimization work makes the benchmark more honest; it does not make brute forcing Bitcoin practical.

## Optimization Notes

Current production hot-path optimizations:

1. **Batched affine EC walk**: one scalar multiplication per worker, then group addition for whole batches.
2. **Montgomery batch inversion**: amortizes the expensive field inversion across 2,048 keys.
3. **Hash160 target database**: input addresses are decoded once; workers compare fixed 20-byte arrays.
4. **Specialized RIPEMD160**: avoids streaming hasher overhead for the fixed 32-byte SHA256 digest input.
5. **SIMD SHA256**: uses `minio/sha256-simd` for compressed public-key hashing and checksums.
6. **Allocation-free worker batch**: per-worker scratch buffers keep the hot loop at `0 B/op`.
7. **Batch counter updates**: atomics are updated per batch, not per key.

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
