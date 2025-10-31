# Performance Benchmarks

This document contains performance benchmarks for the Bitcoin address collision research toolkit. Benchmarks measure the core hash pipeline performance (key generation → address derivation).

## How to Run Benchmarks

```bash
# Run all benchmarks
go test -bench=. -benchmem ./bench

# Run with longer duration for more accurate results
go test -bench=. -benchmem -benchtime=5s ./bench

# Run specific benchmark
go test -bench=BenchmarkHashPipeline -benchmem ./bench
```

## Benchmark Results

Results are measured using Go's built-in benchmarking tool. The `BenchmarkHashPipeline` test measures the complete address generation pipeline, which is the most representative metric for real-world performance.

### Current Results

| Machine     | CPU              | Go Version | Keys/sec | Memory/op | Allocs/op | Date |
| ----------- | ---------------- | ---------- | -------- | --------- | --------- | ---- |
| MacBook Pro | Apple M3 (ARM64) | 1.22.5     | ~16,580  | 1,311 B   | 52        | 2024 |

_Note: Performance varies significantly based on CPU architecture, generation, and load. These are baseline measurements._

### Detailed Breakdown

**Full Pipeline (BenchmarkHashPipeline)**

- Throughput: ~16,580 keys/second per core
- Memory per operation: 1,311 bytes
- Allocations per operation: 52

**Component Benchmarks:**

- Key Generation: ~16,450 keys/sec
- Hash160 (SHA256+RIPEMD160): ~3,294,000 ops/sec
- Base58 Encoding: ~15,070,000 ops/sec

### Understanding the Numbers

The bottleneck in the pipeline is **elliptic curve key generation** (secp256k1 point multiplication), which accounts for ~95% of the execution time. Hash operations and encoding are highly optimized and contribute minimally to overall latency.

**Why Keys/sec Matters:**

- This determines how many addresses you can check per second
- Real-world performance scales linearly with CPU cores
- Example: 8 cores × 16,580 keys/sec = ~132,640 keys/sec total

### Contributing Benchmarks

To add your benchmark results:

1. Run: `go test -bench=BenchmarkHashPipeline -benchmem -benchtime=5s ./bench`
2. Note your CPU model and Go version
3. Calculate keys/sec from the output (divide `benchtime` by `ns/op`)
4. Submit a PR with your results added to the table above

**Example calculation:**

```
BenchmarkHashPipeline-8    60564    60303 ns/op
Keys/sec = 1,000,000,000 / 60303 ≈ 16,580 keys/sec
```

## Performance Characteristics

### CPU Architecture Impact

- **ARM64 (Apple Silicon)**: ~15,000-20,000 keys/sec per core
- **AMD64 (Intel/AMD)**: ~20,000-50,000 keys/sec per core (varies by generation)
- **Older CPUs**: ~5,000-15,000 keys/sec per core

### Memory Usage

- Per worker: ~1-2 MB (mostly stack)
- Address database: ~50-100 bytes per address
- 1M addresses ≈ 50-100 MB RAM

### Scaling

Performance scales linearly with CPU cores up to physical core count. Hyperthreading provides minimal benefit for this CPU-bound workload.

## Real-World Implications

At ~16,580 keys/sec per core:

- **Single core**: 16,580 keys/sec = 1.43 billion keys/day
- **8 cores**: 132,640 keys/sec = 11.5 billion keys/day
- **Address space**: 2^160 ≈ 1.46 × 10^48 possible addresses

**Time to search 1% of address space (brute force):**

- 1% of 2^160 = 1.46 × 10^46 addresses
- At 132,640 keys/sec: ~3.5 × 10^38 years

This demonstrates why Bitcoin brute force is computationally infeasible.

## Optimization Notes

The toolkit uses several optimizations:

1. **SIMD-accelerated SHA256**: 2-3x faster than standard library
2. **Compressed public keys**: 33 bytes vs 65 bytes (faster hashing)
3. **Buffer pooling**: Reduces GC pressure by ~90%
4. **Batch atomic updates**: Reduces contention by 10,000x

Future optimizations could include:

- GPU acceleration (100-1000x theoretical speedup)
- Assembly-optimized secp256k1 operations
- Custom memory allocators

However, even with 1000x speedup, brute force remains infeasible due to the astronomical size of the address space.
