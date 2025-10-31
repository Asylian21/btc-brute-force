# Multi-stage Dockerfile for btc-brute-force
# Build stage: Use golang image to compile the binary
FROM golang:1.23-alpine AS build

WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary with CGO disabled for static linking
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/btc-brute-force ./cmd/btc-brute-force

# Runtime stage: Use minimal alpine image
FROM alpine:3.20

# Install ca-certificates for HTTPS (if needed for future features)
RUN apk --no-cache add ca-certificates

# Copy binary from build stage
COPY --from=build /out/btc-brute-force /usr/local/bin/btc-brute-force

# Set entrypoint
ENTRYPOINT ["btc-brute-force"]

# Default command (can be overridden)
CMD ["--help"]

