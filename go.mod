// Go Module Definition for Bitcoin Wallet Bruteforce
//
// This file defines the Go module and its dependencies.
// It's automatically managed by Go's module system.
//
// Module Name: btcgen
// Go Version: 1.22+ (with toolchain 1.22.5)
//
// Purpose:
//	Declares all external packages required for Bitcoin address generation
//	and cryptographic operations.

module github.com/Asylian21/btc-brute-force

// Minimum Go version required
go 1.22

// Specific Go toolchain version used for building
toolchain go1.22.5

// ============================================================================
// DIRECT DEPENDENCIES (explicitly imported in source code)
// ============================================================================

require (
	// Bitcoin SECP256k1 elliptic curve cryptography
	// Purpose: Generate private/public key pairs using Bitcoin's curve
	// Features:
	//   - Private key generation (256-bit random number)
	//   - Public key derivation (elliptic curve point multiplication)
	//   - Compressed public key serialization (33 bytes)
	// Performance: Optimized implementation with assembly for common platforms
	github.com/btcsuite/btcd/btcec/v2 v2.3.5

	// Bitcoin utility functions
	// Purpose: Hash160 calculation (RIPEMD160(SHA256(pubkey)))
	// Features:
	//   - Address encoding/decoding utilities
	//   - Base58 encoding (used but imported separately)
	//   - Bitcoin-specific hashing functions
	// Note: This is the official Bitcoin library in Go
	github.com/btcsuite/btcutil v1.0.2

	// SIMD-accelerated SHA256 hashing
	// Purpose: Hardware-accelerated SHA256 for checksum calculation
	// Performance Boost: 2-3x faster than standard library crypto/sha256
	// Features:
	//   - Auto-detection of CPU capabilities (AVX2, AVX, SSE, ARM NEON)
	//   - Falls back to standard implementation if SIMD not available
	//   - Drop-in replacement for crypto/sha256
	// Critical for performance: SHA256 is called twice per address (checksum)
	github.com/minio/sha256-simd v1.0.1
)

// ============================================================================
// INDIRECT DEPENDENCIES (required by our direct dependencies)
// ============================================================================

require (
	// Bitcoin daemon core library
	// Used by btcutil for constants and shared types
	// Not directly used in our code
	github.com/btcsuite/btcd v0.20.1-beta // indirect

	// SECP256k1 curve implementation (lower level)
	// Used by btcec/v2 for elliptic curve operations
	// Provides the mathematical primitives for ECDSA
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect

	// CPU feature detection
	// Used by sha256-simd to detect SIMD capabilities
	// Determines which optimized implementation to use
	github.com/klauspost/cpuid/v2 v2.2.3 // indirect

	// Additional cryptographic primitives
	// Purpose: Used internally by btcsuite libraries
	// Not directly imported in our code, but required by dependencies
	golang.org/x/crypto v0.17.0 // indirect

	// Operating system interface
	// Low-level system calls used by cryptographic libraries
	// Platform-specific implementations
	golang.org/x/sys v0.15.0 // indirect
)

// ============================================================================
// DEPENDENCY TREE VISUALIZATION
// ============================================================================
//
// btcgen (our program)
// ├── btcsuite/btcd/btcec/v2 (SECP256k1 crypto)
// │   └── decred/dcrd/dcrec/secp256k1/v4 (curve math)
// ├── btcsuite/btcutil (Bitcoin utilities)
// │   └── btcsuite/btcd (core library)
// ├── minio/sha256-simd (fast SHA256)
// │   └── klauspost/cpuid/v2 (CPU detection)
// └── golang.org/x/crypto (crypto primitives)
//     └── golang.org/x/sys (system calls)
//
// ============================================================================
// BUILD & DEPENDENCY MANAGEMENT COMMANDS
// ============================================================================
//
// Build Command:
//	go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
//
// Update Dependencies:
//	go get -u ./...          # Update all dependencies
//	go mod tidy              # Remove unused dependencies
//	go mod verify            # Verify checksums
//
// Vendor Dependencies (optional):
//	go mod vendor            # Copy dependencies to vendor/ directory
//	go build -mod=vendor     # Build using vendored dependencies
