.PHONY: build bench docker-build clean test vet lint all

# Binary name
BINARY_NAME=btc-brute-force
CMD_PATH=./cmd/btc-brute-force
BIN_DIR=bin

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -benchtime=5s ./bench/...

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):latest .
	@echo "Docker image built: $(BINARY_NAME):latest"

# Run all tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run all tests (including benchmarks)
test-all:
	@echo "Running all tests and benchmarks..."
	@go test -v ./...
	@go test -bench=. -benchmem -benchtime=1s ./bench/...

# All-in-one: vet, test, build
all: vet test build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -f $(BINARY_NAME)
	@rm -f $(BINARY_NAME).exe
	@rm -f coverage.out coverage.html
	@go clean
	@echo "Clean complete"
