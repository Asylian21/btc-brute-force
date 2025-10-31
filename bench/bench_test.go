package bench

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	sha256simd "github.com/minio/sha256-simd"
)

// BenchmarkHashPipeline benchmarks the core Bitcoin address generation pipeline:
// Private Key → Public Key → SHA256 → RIPEMD160 → Base58 encoding
func BenchmarkHashPipeline(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Generate private key
		privateKey, err := btcec.NewPrivateKey()
		if err != nil {
			b.Fatal(err)
		}

		// Serialize compressed public key (33 bytes)
		pubKeyBytes := privateKey.PubKey().SerializeCompressed()

		// Hash160: RIPEMD160(SHA256(pubkey))
		hash160 := btcutil.Hash160(pubKeyBytes)

		// Build address payload
		buf := make([]byte, 0, 25)
		buf = append(buf, 0x00)       // Version byte
		buf = append(buf, hash160...) // Hash160

		// Double SHA256 for checksum
		h1 := sha256simd.Sum256(buf)
		h2 := sha256simd.Sum256(h1[:])

		// Append checksum
		buf = append(buf, h2[:4]...)

		// Base58 encode
		_ = base58.Encode(buf)
	}
}

// BenchmarkKeyGeneration benchmarks only the private/public key generation
func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		privateKey, err := btcec.NewPrivateKey()
		if err != nil {
			b.Fatal(err)
		}
		_ = privateKey.PubKey().SerializeCompressed()
	}
}

// BenchmarkHash160 benchmarks the Hash160 operation (SHA256 + RIPEMD160)
func BenchmarkHash160(b *testing.B) {
	// Pre-generate a public key for consistent benchmarking
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pubKeyBytes := privateKey.PubKey().SerializeCompressed()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = btcutil.Hash160(pubKeyBytes)
	}
}

// BenchmarkBase58Encode benchmarks Base58 encoding
func BenchmarkBase58Encode(b *testing.B) {
	// Create a sample payload (version + hash160 + checksum)
	buf := make([]byte, 25)
	buf[0] = 0x00 // Version
	// Rest is zero, but that's fine for encoding benchmark

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = base58.Encode(buf)
	}
}
