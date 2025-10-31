# Testing Guide

This document describes the test suite for the Bitcoin Address-Collision Research Toolkit.

## Test Structure

The project includes comprehensive tests at multiple levels:

### Unit Tests (`cmd/btc-brute-force/main_test.go`)

Tests individual functions and components:

- **TestReadAddresses**: Tests loading addresses from file
- **TestReadAddressesEmptyFile**: Tests handling of empty files
- **TestReadAddressesNonexistentFile**: Tests error handling for missing files
- **TestGenerateKeyAndAddress**: Tests key and address generation
- **TestGenerateKeyAndAddressMultiple**: Tests uniqueness of generated addresses
- **TestGenerateKeyAndAddressValidFormat**: Tests address format validation
- **TestBufferPool**: Tests buffer pool functionality

### Integration Tests (`cmd/btc-brute-force/integration_test.go`)

Tests full binary execution (requires `-tags=integration`):

- **TestBinaryExecution**: Tests binary can be built and executed
- **TestBinaryWithMockData**: Tests binary with mock address files

### Benchmark Tests (`bench/bench_test.go`)

Performance benchmarks:

- **BenchmarkHashPipeline**: Full address generation pipeline
- **BenchmarkKeyGeneration**: Key generation only
- **BenchmarkHash160**: Hash160 operation
- **BenchmarkBase58Encode**: Base58 encoding

## Running Tests

### Run All Unit Tests

```bash
go test ./...
```

### Run Tests Verbosely

```bash
go test -v ./...
```

### Run Tests with Coverage

```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Run Integration Tests

```bash
go test -tags=integration ./cmd/btc-brute-force -v
```

### Run Benchmarks

```bash
# Quick benchmarks (1 second)
go test -bench=. -benchmem -benchtime=1s ./bench

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

- `readAddresses`: ✅ Fully tested
- `generateKeyAndAddress`: ✅ Fully tested
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
```

## Troubleshooting

### Tests fail locally but pass in CI

- Check Go version matches CI (`go version`)
- Run `go mod tidy` to sync dependencies
- Clear test cache: `go clean -testcache`

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
