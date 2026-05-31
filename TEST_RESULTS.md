# Test Results Summary

## Test Execution Date
2026-05-31

## Test Status: ✅ ALL PASSING

### Unit Tests
- ✅ TestKeyStreamMatchesReference - Batched EC walk + GLV endomorphism match an independent scalar-multiplication reference (identity and lambda-scaled keys)
- ✅ TestKeyStreamContinuity - Consecutive batches continue at the exact next offset (identity and endomorphism halves)
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
- ✅ MacBook Air M3 runtime throughput - Sustained optimized program output around ~20M keys/sec (identity + endomorphism keys)
- ✅ BenchmarkKeyStreamPerKey - Optimized hot path: ~172.5 ns per checked key (~5.8M keys/sec per benchmark worker), 0 allocs/op
- ✅ GLV endomorphism + zero-copy Hash160 - ~222 → ~171.5 ns/key (GOMAXPROCS=1, median of 10), a ~1.30x speedup, still 0 allocs/op
- ✅ BenchmarkGenerateKeyAndHash160 - Fresh scalar-multiplication baseline: ~34.1k keys/sec
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
