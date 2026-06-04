.PHONY: build build-cpu run-example resume-example bench bench-gpu docker-build clean test test-gpu vet lint all

# Binary name
BINARY_NAME=btc-brute-force
# Build the whole package (multiple files: bitcoin-wallet-bruteforce-offline.go,
# bloom.go, doc.go), not a single source file.
MAIN=.
BIN_DIR=bin
THREADS?=8
EXAMPLE_ADDRESSES=example-addresses.txt
EXAMPLE_OUTPUT=example-matches.txt
EXAMPLE_CHECKPOINT=example-checkpoint.json

# macOS 15+ requires LC_UUID in Mach-O binaries (Go < 1.24); external linkmode fixes it.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS=-s -w -linkmode=external
else
  LDFLAGS=-s -w
endif

# Build the binary. On macOS, native cgo is enabled by default, so this ships
# the Apple Metal GPU Hash160 path (auto-enabled at runtime). -s -w is required
# for a valid ad-hoc code signature on the external-linked cgo binary.
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

# Build a CPU-only binary (Metal compiled out via the nometal stub). Useful for
# debugging or measuring the CPU baseline against the GPU path.
build-cpu:
	@echo "Building $(BINARY_NAME)-cpu (CPU-only, Metal disabled)..."
	@mkdir -p $(BIN_DIR)
	@go build -tags=nometal -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-cpu $(MAIN)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)-cpu"

# Build and run the small bundled demo address list.
run-example: build
	@echo "Starting demo with $(THREADS) worker thread(s). Press Ctrl+C to stop."
	@echo "Targets: $(EXAMPLE_ADDRESSES) | Output: $(EXAMPLE_OUTPUT) | Checkpoint: $(EXAMPLE_CHECKPOINT)"
	@$(BIN_DIR)/$(BINARY_NAME) --checkpoint=$(EXAMPLE_CHECKPOINT) $(THREADS) $(EXAMPLE_OUTPUT) $(EXAMPLE_ADDRESSES)

# Resume the bundled demo from its saved checkpoint.
resume-example: build
	@echo "Resuming demo with $(THREADS) worker thread(s). Press Ctrl+C to stop."
	@echo "Targets: $(EXAMPLE_ADDRESSES) | Output: $(EXAMPLE_OUTPUT) | Checkpoint: $(EXAMPLE_CHECKPOINT)"
	@$(BIN_DIR)/$(BINARY_NAME) --resume --checkpoint=$(EXAMPLE_CHECKPOINT) $(THREADS) $(EXAMPLE_OUTPUT) $(EXAMPLE_ADDRESSES)

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -ldflags="$(LDFLAGS)" -bench=. -benchmem -benchtime=5s . ./bench/...

# Benchmark the GPU vs CPU Hash160 throughput (Apple Metal, darwin only).
bench-gpu:
	@echo "Benchmarking GPU vs CPU Hash160 (Apple Metal)..."
	@go test -ldflags="$(LDFLAGS)" -run '^$$' -bench 'Benchmark(GPU|CPU)Hash160' -benchtime=2s ./gpu/metal/

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):latest .
	@echo "Docker image built: $(BINARY_NAME):latest"

# Run all tests (quick): every correctness test, but -short skips the long GPU
# throughput sweeps (TestGPUProductionSweep, TestGPUWalkDispatchThroughput).
test:
	@echo "Running tests..."
	@go test -short -ldflags="$(LDFLAGS)" -v .

# Run the full GPU test surface (Apple Metal, darwin only): the on-device
# differential suite (field vs math/big, Hash160 vs btcutil, EC add, GLV) plus the
# main-package production-pipeline tests (self-test gate, hybrid end-to-end,
# --gpu=auto calibration, and the experimental on-GPU EC walk + self-test). No
# -short, so it is thorough; all tests skip cleanly if no Metal device is present.
test-gpu:
	@echo "Running GPU (Metal) test surface..."
	@go test -ldflags="$(LDFLAGS)" ./gpu/metal/
	@go test -ldflags="$(LDFLAGS)" -run 'TestGPU' -v .

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet . ./bench ./gpu/...
	@go vet -tags=integration ./cmd/btc-brute-force

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -ldflags="$(LDFLAGS)" -coverprofile=coverage.out .
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run all tests (including benchmarks)
test-all:
	@echo "Running all tests and benchmarks..."
	@go test -ldflags="$(LDFLAGS)" -v .
	@go test -ldflags="$(LDFLAGS)" -bench=. -benchmem -benchtime=1s . ./bench/...

# All-in-one: vet, test, build
all: vet test build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -f $(BINARY_NAME)
	@rm -f $(BINARY_NAME).exe
	@rm -f coverage.out coverage.html
	@rm -f $(EXAMPLE_OUTPUT) $(EXAMPLE_CHECKPOINT) $(EXAMPLE_CHECKPOINT).tmp
	@go clean
	@echo "Clean complete"
