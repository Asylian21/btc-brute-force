package main

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	field "github.com/Asylian21/secp256k1-field"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// secp256k1 group order N.
const secp256k1Order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

// secp256k1 GLV endomorphism scalar lambda (matches betaHex; lambda^3 == 1 mod N).
// Used as an independent reference for the endomorphism keys (the production code
// uses lambdaScalar parsed from lambdaHex).
const secp256k1Lambda = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"

// newKeyStreamSeeded builds a keyStream from a fixed seed for deterministic tests.
func newKeyStreamSeeded(seed [32]byte) *keyStream {
	ks := &keyStream{
		dx:       make([]field.Val, keyBatchSize),
		pre:      make([]field.Val, keyBatchSize),
		degenIdx: make([]int, 0, 4),
		digBuf:   make([]byte, endoFactor*keyBatchSize*32),
	}
	ks.setBase(seed)
	return ks
}

// variantReferenceHash independently derives the expected private key bytes and
// Hash160 for GLV+negation variant v at linear scalar (baseInt + absOffset) mod
// order, using math/big + btcec (a fresh derivation, never the hot path). The
// variant scalars mirror privateKeyForVariant: v0:k v1:n-k v2:λk v3:n-λk v4:λ²k
// v5:n-λ²k (mod order).
func variantReferenceHash(baseInt, order, lambda *big.Int, absOffset uint64, v int) ([]byte, [20]byte) {
	k := new(big.Int).Add(baseInt, new(big.Int).SetUint64(absOffset))
	switch v {
	case 2, 3:
		k.Mul(k, lambda)
	case 4, 5:
		k.Mul(k, lambda)
		k.Mul(k, lambda)
	}
	k.Mod(k, order)
	if v%2 == 1 {
		k.Sub(order, k) // n - k (point negation); n - 0 reduces back to 0
		k.Mod(k, order)
	}
	wantPriv := k.FillBytes(make([]byte, 32))
	priv, _ := btcec.PrivKeyFromBytes(wantPriv)
	var wantHash [20]byte
	copy(wantHash[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
	return wantPriv, wantHash
}

// TestKeyStreamMatchesReference proves the incremental EC walk produces exactly
// the same private keys and Hash160s as an independent math/big + btcec
// reference that performs a fresh scalar multiplication for each key. It checks
// all 6 GLV+negation variants per sampled linear step in the new slot layout.
func TestKeyStreamMatchesReference(t *testing.T) {
	order, _ := new(big.Int).SetString(secp256k1Order, 16)

	var seed [32]byte
	seed[0] = 0x9a
	seed[15] = 0x37
	seed[31] = 0x42

	lambda, ok := new(big.Int).SetString(secp256k1Lambda, 16)
	if !ok {
		t.Fatal("failed to parse lambda")
	}

	ks := newKeyStreamSeeded(seed)

	// Variant-major layout: hashes[v*keyBatchSize+p] is variant v at step p.
	// m == keyBatchSize here.
	hashes := make([][20]byte, endoFactor*keyBatchSize)
	start := ks.nextBatch(hashes)
	if start != 0 {
		t.Fatalf("expected first batch to start at offset 0, got %d", start)
	}

	baseInt := new(big.Int).SetBytes(seed[:])
	baseInt.Mod(baseInt, order)

	check := func(p int) {
		t.Helper()
		for v := 0; v < endoFactor; v++ {
			wantPriv, wantHash := variantReferenceHash(baseInt, order, lambda, start+uint64(p), v)

			if hashes[v*keyBatchSize+p] != wantHash {
				t.Errorf("variant %d step %d: walk hash160 %x != reference %x", v, p, hashes[v*keyBatchSize+p], wantHash)
			}

			// privateKeyForVariant must reconstruct the same private key bytes.
			gotPriv := ks.privateKeyForVariant(start+uint64(p), v).Serialize()
			if !bytes.Equal(gotPriv, wantPriv) {
				t.Errorf("variant %d step %d: privateKeyForVariant %x != reference %x", v, p, gotPriv, wantPriv)
			}
		}
	}

	for _, p := range []int{0, 1, 2, 3, 7, 100, 511, 512, 1000, keyBatchSize - 1} {
		check(p)
	}
}

// TestKeyStreamAllVariants is the dedicated correctness gate for the 6-variant
// slot layout. For an independent seed it verifies every GLV+negation variant
// (both the Hash160 written to out[v*keyBatchSize+p] and the private key from
// privateKeyForVariant) against a fresh math/big + btcec reference, across an
// exhaustive small step prefix plus a few scattered larger steps.
func TestKeyStreamAllVariants(t *testing.T) {
	order, _ := new(big.Int).SetString(secp256k1Order, 16)
	lambda, ok := new(big.Int).SetString(secp256k1Lambda, 16)
	if !ok {
		t.Fatal("failed to parse lambda")
	}

	var seed [32]byte
	seed[0] = 0xc3
	seed[7] = 0x11
	seed[31] = 0xbd
	ks := newKeyStreamSeeded(seed)

	hashes := make([][20]byte, endoFactor*keyBatchSize)
	start := ks.nextBatch(hashes)

	baseInt := new(big.Int).SetBytes(seed[:])
	baseInt.Mod(baseInt, order)

	// Exhaustive small prefix plus a few scattered larger steps. All entries MUST
	// be < keyBatchSize (the per-batch step count), expressed relative to it so
	// the test stays correct under any keyBatchSize.
	steps := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		keyBatchSize / 3, keyBatchSize / 2, keyBatchSize - 2, keyBatchSize - 1}
	for _, p := range steps {
		for v := 0; v < endoFactor; v++ {
			wantPriv, wantHash := variantReferenceHash(baseInt, order, lambda, start+uint64(p), v)

			if hashes[v*keyBatchSize+p] != wantHash {
				t.Errorf("variant %d step %d: hash160 %x != reference %x", v, p, hashes[v*keyBatchSize+p], wantHash)
			}

			gotPriv := ks.privateKeyForVariant(start+uint64(p), v).Serialize()
			if !bytes.Equal(gotPriv, wantPriv) {
				t.Errorf("variant %d step %d: privateKeyForVariant %x != reference %x", v, p, gotPriv, wantPriv)
			}
		}
	}
}

// TestKeyStreamContinuity verifies the offset accounting across consecutive
// batches stays consistent (second batch continues exactly where the first
// ended), checking all 6 GLV+negation variants at a few steps in the second batch.
func TestKeyStreamContinuity(t *testing.T) {
	order, _ := new(big.Int).SetString(secp256k1Order, 16)
	lambda, _ := new(big.Int).SetString(secp256k1Lambda, 16)
	var seed [32]byte
	seed[31] = 0x07
	ks := newKeyStreamSeeded(seed)

	baseInt := new(big.Int).SetBytes(seed[:])
	baseInt.Mod(baseInt, order)

	hashes := make([][20]byte, endoFactor*keyBatchSize)
	_ = ks.nextBatch(hashes) // first batch
	start := ks.nextBatch(hashes)
	if start != uint64(keyBatchSize) {
		t.Fatalf("expected second batch to start at %d, got %d", keyBatchSize, start)
	}

	for _, p := range []int{0, 5, keyBatchSize - 1} {
		for v := 0; v < endoFactor; v++ {
			_, wantHash := variantReferenceHash(baseInt, order, lambda, start+uint64(p), v)
			if hashes[v*keyBatchSize+p] != wantHash {
				t.Errorf("second batch variant %d step %d: %x != %x", v, p, hashes[v*keyBatchSize+p], wantHash)
			}
		}
	}
}

// BenchmarkKeyStreamPerKey measures the amortized per-key cost of the production
// hot path (point addition + endomorphism + batched inversion + Hash160). It
// counts every key actually produced — identity AND endomorphism — so ns/op is
// the cost per checked key (len(hashes) == endoFactor*keyBatchSize per batch).
func BenchmarkKeyStreamPerKey(b *testing.B) {
	ks := newKeyStreamSeeded([32]byte{1, 2, 3})
	hashes := make([][20]byte, endoFactor*keyBatchSize)
	b.ReportAllocs()
	b.ResetTimer()
	produced := 0
	for produced < b.N {
		ks.nextBatch(hashes)
		produced += len(hashes)
	}
}

// TestEndomorphismConstants verifies the GLV constants independently of the hot
// path: beta and lambda are nontrivial cube roots of unity in Fp and Fn
// respectively, and they are correctly paired so that (beta*x, y) == lambda*P
// (checked on the generator G).
func TestEndomorphismConstants(t *testing.T) {
	// beta^3 == 1 (mod p) and beta != 1.
	var one, b2, b3 field.Val
	one.SetInt(1)
	b2.SquareVal(&betaVal)
	b3.Mul2(&b2, &betaVal)
	b3.Normalize()
	if !b3.Equals(&one) {
		t.Fatalf("beta^3 != 1 mod p")
	}
	if betaVal.Equals(&one) {
		t.Fatalf("beta == 1 (trivial cube root)")
	}

	// lambda^3 == 1 (mod N) and lambda != 1, via an independent big.Int.
	order, _ := new(big.Int).SetString(secp256k1Order, 16)
	lambda, _ := new(big.Int).SetString(secp256k1Lambda, 16)
	l3 := new(big.Int).Exp(lambda, big.NewInt(3), order)
	if l3.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("lambda^3 != 1 mod N")
	}
	if lambda.Cmp(big.NewInt(1)) == 0 {
		t.Fatalf("lambda == 1 (trivial cube root)")
	}

	// Pairing: (beta*Gx, Gy) must equal lambda*G. mulGx[0]/mulGy[0] hold 1*G.
	var lamScalar secp.ModNScalar
	var lb [32]byte
	lambda.FillBytes(lb[:])
	lamScalar.SetBytes(&lb)
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&lamScalar, &p)
	p.ToAffine()
	lamGx := fieldFromDcrd(&p.X)
	lamGy := fieldFromDcrd(&p.Y)

	var betaGx field.Val
	betaGx.Mul2(&betaVal, &mulGx[0])
	betaGx.Normalize()
	gy := mulGy[0]
	if !betaGx.Equals(&lamGx) {
		t.Fatalf("beta*Gx != (lambda*G).x: %s vs %s", betaGx.String(), lamGx.String())
	}
	if !gy.Equals(&lamGy) {
		t.Fatalf("Gy != (lambda*G).y: %s vs %s", gy.String(), lamGy.String())
	}
}

func TestReadTargetHashes(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-addresses.txt")

	testAddresses := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
		"1CounterpartyXXXXXXXXXXXXXXXUWLpVr",
	}

	content := ""
	for _, addr := range testAddresses {
		content += addr + "\n"
	}
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	targets, err := readTargetHashes(testFile)
	if err != nil {
		t.Fatalf("readTargetHashes failed: %v", err)
	}

	if len(targets) != len(testAddresses) {
		t.Errorf("Expected %d hashes, got %d", len(testAddresses), len(targets))
	}
}

func TestReadTargetHashesEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(testFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	targets, err := readTargetHashes(testFile)
	if err != nil {
		t.Fatalf("readTargetHashes failed on empty file: %v", err)
	}

	if len(targets) != 0 {
		t.Errorf("Expected 0 hashes from empty file, got %d", len(targets))
	}
}

func TestReadTargetHashesNonexistentFile(t *testing.T) {
	_, err := readTargetHashes("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestGenerateKeyAndHash160(t *testing.T) {
	privateKey, hash160, err := generateKeyAndHash160()
	if err != nil {
		t.Fatalf("generateKeyAndHash160 failed: %v", err)
	}

	if privateKey == nil {
		t.Error("Private key is nil")
	}

	if hash160 == [20]byte{} {
		t.Error("Hash160 is zero")
	}

	address := encodeP2PKH(hash160)
	if address == "" || address[0] != '1' {
		t.Errorf("Expected P2PKH address starting with '1', got: %s", address)
	}
	if len(address) < 26 || len(address) > 35 {
		t.Errorf("Address length %d is outside expected range (26-35)", len(address))
	}
}

func TestGenerateKeyAndHash160Unique(t *testing.T) {
	seen := make(map[[20]byte]struct{})

	for i := 0; i < 100; i++ {
		_, hash160, err := generateKeyAndHash160()
		if err != nil {
			t.Fatalf("generateKeyAndHash160 failed on iteration %d: %v", i, err)
		}
		if _, dup := seen[hash160]; dup {
			t.Errorf("Duplicate hash160 generated")
		}
		seen[hash160] = struct{}{}
	}
}

func TestBufferPool(t *testing.T) {
	buf1 := bufferPool.Get().([]byte)
	if cap(buf1) < 128 {
		t.Errorf("Expected buffer capacity >= 128, got %d", cap(buf1))
	}
	bufferPool.Put(buf1)

	buf2 := bufferPool.Get().([]byte)
	if cap(buf2) < 128 {
		t.Errorf("Expected buffer capacity >= 128, got %d", cap(buf2))
	}
	bufferPool.Put(buf2)
}

func BenchmarkGenerateKeyAndHash160(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := generateKeyAndHash160()
		if err != nil {
			b.Fatal(err)
		}
	}
}
