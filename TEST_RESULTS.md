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
- ✅ MacBook Air M3 runtime throughput - Sustained optimized program output ~26M keys/sec at 4 threads (up from ~19.9M at endoFactor=2, ~1.33x) and ~39M keys/sec at 8 threads (6 keys per EC step: GLV endomorphism + point negation)
- ✅ BenchmarkKeyStreamPerKey - Optimized hot path: ~136.7 ns per checked key (~7.3M keys/sec per benchmark worker), 0 allocs/op
- ✅ GLV 2→6 keys per EC step - ~172.5 → ~136.7 ns/checked key (endoFactor 2→6, keyBatchSize 2048→1024; -benchtime=2s -count=6 median), a ~1.26x per-key speedup, still 0 allocs/op
- ✅ BenchmarkGenerateKeyAndHash160 - Fresh scalar-multiplication baseline: ~28.7k ns/op (~34.8k keys/sec)
- ✅ `bench/` package benchmarks - Educational baseline pipeline/component benchmarks (HashPipeline, KeyGeneration, Hash160, Base58Encode)

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
