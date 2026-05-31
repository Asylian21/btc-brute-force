# Test Results Summary

## Test Execution Date
2026-05-31

## Test Status: ✅ ALL PASSING

### Unit Tests
- ✅ TestKeyStreamMatchesReference - Batched EC walk + GLV endomorphism + negation match an independent scalar-multiplication reference across all 6 variants per step (k, n-k, λk, n-λk, λ²k, n-λ²k)
- ✅ TestKeyStreamAllVariants - Dedicated all-variant gate: every one of the 6 GLV+negation slots matches a fresh math/big + btcec reference (both the Hash160 and the reconstructed private key), independent seed
- ✅ TestKeyStreamContinuity - Consecutive batches continue at the exact next offset (all 6 GLV+negation variants verified in the second batch)
- ✅ TestEndomorphismConstants - beta and lambda are nontrivial cube roots of unity, correctly paired so (beta*x, y) == lambda*P
- ✅ TestReadTargetHashes - P2PKH input addresses load as Hash160 targets
- ✅ TestReadTargetHashesEmptyFile - Empty files load cleanly
- ✅ TestReadTargetHashesNonexistentFile - Missing files return an error
- ✅ TestGenerateKeyAndHash160 - Random key and Hash160 generation works
- ✅ TestGenerateKeyAndHash160Unique - Generated Hash160 values are unique across sample runs
- ✅ TestBufferPool - Buffer pool provides reusable address-encoding buffers

### Integration Tests (2 tests)
- ✅ TestBinaryExecution - Tests binary can be built and executed
- ✅ TestBinaryWithMockData - Tests binary with mock address files

### Benchmarks
- ✅ MacBook Air M3 runtime throughput - Latest sustained optimized program output **~45.1M keys/sec at 8 threads** (**+18.7%** over the ~38.0M pre-`sha256mb` baseline in a back-to-back A/B); same generation sustains ~26M keys/sec at 4 threads (pre-`sha256mb`; itself up from ~19.9M at endoFactor=2, ~1.33x)
- ✅ BenchmarkKeyStreamPerKey - Optimized hot path: ~118.5 ns per checked key (~8.4M keys/sec per benchmark worker), 0 allocs/op — down from ~136.7 ns (**−13.35%**, `benchstat` n=10) after the multi-buffer SHA-256 vectorization
- ✅ Multi-buffer SHA-256 (sha256mb) - `BenchmarkHash33` arm64 `sha2x4` vs scalar `crypto/sha256`: ~57.6M vs ~21.6M hashes/sec at n=6144 (**~2.6x**), 0 allocs/op
- ✅ GLV 2→6 keys per EC step - ~172.5 → ~136.7 ns/checked key (endoFactor 2→6, keyBatchSize 2048→1024; -benchtime=2s -count=6 median; pre-`sha256mb`), a ~1.26x per-key speedup, still 0 allocs/op
- ✅ BenchmarkGenerateKeyAndHash160 - Fresh scalar-multiplication baseline: ~29.1k ns/op (~34.4k keys/sec)
- ✅ `bench/` package benchmarks - Educational baseline pipeline/component benchmarks (HashPipeline, KeyGeneration, Hash160, Base58Encode)

### Dependency Library Tests (sha256mb)
The HASH160 hot path now routes through the sibling module
[`github.com/Asylian21/sha256mb`](https://github.com/Asylian21/sha256mb). Its
suites pass on this machine across every backend and under the race detector:
- ✅ `go test ./...` (native: arm64 `sha2x4` + fused HASH160)
- ✅ `GOSHA256MB_FORCE=scalar go test ./...` (scalar `crypto/sha256` oracle)
- ✅ `GOSHA256MB_FORCE=sha2x4 go test ./...` (forced 4-lane hardware-SHA kernel)
- ✅ `GOHASH160MB_FORCE=fused go test ./hash160mb` (register-fused SHA→RIPEMD kernel)
- ✅ `go test -race ./...`
- ✅ `Hash33` is differentially verified against `crypto/sha256` and `FromPubkeys33` against `crypto/sha256` + `golang.org/x/crypto/ripemd160` (the `btcutil.Hash160` algorithm), including lane/tail boundaries, poisoned inter-message padding, fuzzing (`FuzzHash33`, `FuzzFromPubkeys33`), and 0-alloc assertions

### Performance Progress
- ✅ Replaced per-key scalar multiplication in the worker path with a batched affine walk rebased once per claimed chunk
- ✅ Expanded each affine point to six checked keys through GLV endomorphism plus point negation
- ✅ Vectorized the SHA-256 step with multi-buffer `sha256mb` (arm64 `sha2x4`, ~2.6x scalar), fused into the multi-buffer RIPEMD-160 pass — **−13.35%** per key, **+18.7%** at 8 threads
- ✅ Moved target matching to raw Hash160 lookups and deferred Base58 encoding to the rare match path
- ✅ Added zero-copy RIPEMD160 output into the caller's `[20]byte` result slice
- ✅ Kept the optimized benchmark hot path at 0 allocations per checked key
- ✅ Preserved long-run progress with a JSON checkpoint that stores a single scan frontier (resumable with any thread count, no keys skipped)

### Code Quality Checks
- ✅ go vet - No issues found
- ✅ Build - Binary builds successfully
- ✅ Binary execution - Binary runs correctly

## Test Coverage
- Coverage focuses on the cryptographic hot path, Hash160 parsing, RIPEMD160 equivalence, and batch continuity.
- The infinite worker loop, stats reporter, and match writer remain integration/behavioral areas rather than small unit tests.

## Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make bench

# Run all (tests + benchmarks)
make test-all

# Run integration tests
go test -tags=integration ./cmd/btc-brute-force -v
```

## CI/CD Status
- ✅ CI workflow configured (`.github/workflows/ci.yml`)
- ✅ Test workflow configured (`.github/workflows/test.yml`)
- ✅ Release workflow configured (`.github/workflows/release.yml`)

All tests run automatically on push/PR and on release tags.
