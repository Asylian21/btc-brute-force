# Testing Guide

This document describes the test suite for the Bitcoin Address-Collision Research Toolkit.

## Test Structure

The project includes comprehensive tests at multiple levels:

### Unit Tests (`bitcoin-wallet-bruteforce-offline_test.go`)

Tests individual functions and components:

- **TestKeyStreamMatchesReference**: Verifies the batched EC walk against an independent scalar-multiplication reference
- **TestKeyStreamContinuity**: Verifies consecutive batches continue at the exact next private-key offset
- **TestReadTargetHashes**: Tests loading P2PKH addresses as raw Hash160 targets
- **TestReadTargetHashesEmptyFile**: Tests handling of empty files
- **TestReadTargetHashesNonexistentFile**: Tests error handling for missing files
- **TestGenerateKeyAndHash160**: Tests random key and Hash160 generation
- **TestGenerateKeyAndHash160Unique**: Tests uniqueness across repeated generated hashes
- **TestBufferPool**: Tests buffer pool functionality
- **TestRIPEMD160Hash32**: Verifies the specialized RIPEMD160 hot path against the streaming reference

### Integration Tests (`cmd/btc-brute-force/integration_test.go`)

Tests full binary execution (requires `-tags=integration`):

- **TestBinaryExecution**: Tests binary can be built and executed
- **TestBinaryWithMockData**: Tests binary with mock address files

### Benchmark Tests (`bench/bench_test.go`)

Educational component benchmarks:

- **BenchmarkHashPipeline**: Full address generation pipeline
- **BenchmarkKeyGeneration**: Key generation only
- **BenchmarkHash160**: Hash160 operation
- **BenchmarkBase58Encode**: Base58 encoding

### Production Hot-Path Benchmarks (`bitcoin-wallet-bruteforce-offline_test.go`)

- **BenchmarkKeyStreamPerKey**: Batched EC walk plus Hash160, amortized per key
- **BenchmarkGenerateKeyAndHash160**: Direct fresh-key baseline
- **BenchmarkRIPEMD160Hash32**: Specialized fixed-input RIPEMD160
- **BenchmarkRIPEMD160Streaming**: Streaming RIPEMD160 reference

## Running Tests

### Run All Unit Tests

```bash
make test
```

### Run Tests Verbosely

```bash
go test -ldflags="-s -w -linkmode=external" -v .
```

### Run Tests with Coverage

```bash
make test-coverage
go tool cover -html=coverage.out -o coverage.html
```

### Run Integration Tests

```bash
go test -tags=integration ./cmd/btc-brute-force -v
```

### Run Benchmarks

```bash
# Quick benchmarks (1 second)
go test -ldflags="-s -w -linkmode=external" -bench=. -benchmem -benchtime=1s . ./bench/...

# Longer benchmarks (5 seconds)
make bench
```

### Run All Tests via Makefile

```bash
# Run unit tests
make test

# Run go vet
make vet

# Run all tests and benchmarks
make test-all

# Run with coverage
make test-coverage
```

## CI/CD Testing

Tests run automatically in CI/CD pipelines:

- **On every push/PR**: Unit tests, vet, lint
- **On tags**: Full test suite + binary builds
- **Test workflow**: `.github/workflows/test.yml`
- **CI workflow**: `.github/workflows/ci.yml`

## Test Coverage

Current coverage: ~20% (focused on core functions)

Coverage breakdown:

- `readTargetHashes`: ✅ Tested
- `generateKeyAndHash160`: ✅ Tested
- `keyStream.nextBatch`: ✅ Tested against reference scalar multiplication
- `ripemd160Hash32`: ✅ Tested against the streaming reference implementation
- `bufferPool`: ✅ Tested
- `worker`: ⚠️ Not tested (infinite loop, requires signal handling)
- `matchWriter`: ⚠️ Not tested (requires goroutine orchestration)
- `statsReporter`: ⚠️ Not tested (requires time-based testing)
- `main`: ⚠️ Not tested (requires full program execution)

## Writing New Tests

### Unit Test Example

```go
func TestMyFunction(t *testing.T) {
    result, err := myFunction(input)
    if err != nil {
        t.Fatalf("myFunction failed: %v", err)
    }
    if result != expected {
        t.Errorf("Expected %v, got %v", expected, result)
    }
}
```

### Benchmark Example

```go
func BenchmarkMyFunction(b *testing.B) {
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _ = myFunction(input)
    }
}
```

## Test Best Practices

1. **Use `t.TempDir()`** for temporary files
2. **Use `t.Skipf()`** for optional tests (e.g., integration tests)
3. **Use `t.Fatalf()`** for setup failures
4. **Use `t.Errorf()`** for assertion failures
5. **Clean up resources** using `defer` or `t.Cleanup()`
6. **Test error cases** as well as success cases
7. **Use table-driven tests** for multiple test cases

## Continuous Integration

All tests must pass before merging:

```bash
# Pre-commit checklist
make vet      # Static analysis
make test     # Unit tests
make bench    # Benchmarks (quick)
make build    # Release binary build
```

## Troubleshooting

### Tests fail locally but pass in CI

- Check Go version matches CI (`go version`)
- Run `go mod tidy` to sync dependencies
- Clear test cache: `go clean -testcache`
- On macOS 15+ with Go < 1.24, use `make test` so the required external link mode is applied.

### Integration tests skip

- Ensure binary can be built: `make build`
- Check Go is installed: `go version`
- Integration tests require build step

### Benchmarks show different results

- Ensure no other processes are running
- Run longer benchmarks: `-benchtime=5s`
- Compare multiple runs (results vary)

## Test Status

✅ **All unit tests passing**  
✅ **All benchmarks running**  
✅ **CI/CD configured**  
⚠️ **Integration tests optional** (require build step)
