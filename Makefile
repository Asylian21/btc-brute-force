.PHONY: build run-example resume-example bench docker-build clean test vet lint all

# Binary name
BINARY_NAME=btc-brute-force
MAIN=./bitcoin-wallet-bruteforce-offline.go
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

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

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

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):latest .
	@echo "Docker image built: $(BINARY_NAME):latest"

# Run all tests
test:
	@echo "Running tests..."
	@go test -ldflags="$(LDFLAGS)" -v .

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet . ./bench
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
