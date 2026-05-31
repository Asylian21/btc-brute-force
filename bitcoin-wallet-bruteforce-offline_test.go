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

// TestKeyStreamMatchesReference proves the incremental EC walk produces exactly
// the same private keys and Hash160s as an independent math/big + btcec
// reference that performs a fresh scalar multiplication for each key.
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

	// out[0:keyBatchSize] are identity keys; out[keyBatchSize:] are their
	// endomorphism images. m == keyBatchSize here.
	hashes := make([][20]byte, endoFactor*keyBatchSize)
	start := ks.nextBatch(hashes)
	if start != 0 {
		t.Fatalf("expected first batch to start at offset 0, got %d", start)
	}

	baseInt := new(big.Int).SetBytes(seed[:])
	baseInt.Mod(baseInt, order)

	check := func(j int) {
		t.Helper()
		// Independent identity reference private key: (base + offset) mod N.
		k := new(big.Int).Add(baseInt, big.NewInt(int64(uint64(start)+uint64(j))))
		k.Mod(k, order)
		wantPriv := k.FillBytes(make([]byte, 32))

		priv, _ := btcec.PrivKeyFromBytes(wantPriv)
		pub := priv.PubKey().SerializeCompressed()
		var wantHash [20]byte
		copy(wantHash[:], btcutil.Hash160(pub))

		if hashes[j] != wantHash {
			t.Errorf("identity index %d: walk hash160 %x != reference %x", j, hashes[j], wantHash)
		}

		// privateKeyAt must reconstruct the same private key bytes.
		gotPriv := ks.privateKeyAt(start + uint64(j)).Serialize()
		if !bytes.Equal(gotPriv, wantPriv) {
			t.Errorf("identity index %d: privateKeyAt %x != reference %x", j, gotPriv, wantPriv)
		}

		// Independent endomorphism reference private key: lambda*(base+offset) mod N.
		ek := new(big.Int).Mul(k, lambda)
		ek.Mod(ek, order)
		ewantPriv := ek.FillBytes(make([]byte, 32))

		epriv, _ := btcec.PrivKeyFromBytes(ewantPriv)
		var ewantHash [20]byte
		copy(ewantHash[:], btcutil.Hash160(epriv.PubKey().SerializeCompressed()))

		if hashes[keyBatchSize+j] != ewantHash {
			t.Errorf("endomorphism index %d: walk hash160 %x != reference %x", j, hashes[keyBatchSize+j], ewantHash)
		}

		// privateKeyAtEndo must reconstruct lambda*(base+offset) mod N.
		gotEndo := ks.privateKeyAtEndo(start + uint64(j)).Serialize()
		if !bytes.Equal(gotEndo, ewantPriv) {
			t.Errorf("endomorphism index %d: privateKeyAtEndo %x != reference %x", j, gotEndo, ewantPriv)
		}
	}

	for _, j := range []int{0, 1, 2, 3, 7, 100, 511, 512, 1000, keyBatchSize - 1} {
		check(j)
	}
}

// TestKeyStreamContinuity verifies the offset accounting across consecutive
// batches stays consistent (second batch continues exactly where the first ended).
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

	// Verify a couple of identity and endomorphism keys in the second batch.
	for _, j := range []int{0, 5, keyBatchSize - 1} {
		k := new(big.Int).Add(baseInt, big.NewInt(int64(start+uint64(j))))
		k.Mod(k, order)
		wantPriv := k.FillBytes(make([]byte, 32))
		priv, _ := btcec.PrivKeyFromBytes(wantPriv)
		var wantHash [20]byte
		copy(wantHash[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
		if hashes[j] != wantHash {
			t.Errorf("second batch identity index %d: %x != %x", j, hashes[j], wantHash)
		}

		ek := new(big.Int).Mul(k, lambda)
		ek.Mod(ek, order)
		ewantPriv := ek.FillBytes(make([]byte, 32))
		epriv, _ := btcec.PrivKeyFromBytes(ewantPriv)
		var ewantHash [20]byte
		copy(ewantHash[:], btcutil.Hash160(epriv.PubKey().SerializeCompressed()))
		if hashes[keyBatchSize+j] != ewantHash {
			t.Errorf("second batch endomorphism index %d: %x != %x", j, hashes[keyBatchSize+j], ewantHash)
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
