package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadAddresses tests the readAddresses function
func TestReadAddresses(t *testing.T) {
	// Create a temporary file with test addresses
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-addresses.txt")

	testAddresses := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
		"1CounterpartyXXXXXXXXXXXXXXXUWLpVr",
	}

	// Write test addresses to file
	content := ""
	for _, addr := range testAddresses {
		content += addr + "\n"
	}
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test reading addresses
	addresses, err := readAddresses(testFile)
	if err != nil {
		t.Fatalf("readAddresses failed: %v", err)
	}

	// Verify all addresses were loaded
	if len(addresses) != len(testAddresses) {
		t.Errorf("Expected %d addresses, got %d", len(testAddresses), len(addresses))
	}

	// Verify each address exists
	for _, addr := range testAddresses {
		if !addresses[addr] {
			t.Errorf("Address %s not found in map", addr)
		}
	}
}

// TestReadAddressesEmptyFile tests reading an empty file
func TestReadAddressesEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	// Create empty file
	if err := os.WriteFile(testFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	addresses, err := readAddresses(testFile)
	if err != nil {
		t.Fatalf("readAddresses failed on empty file: %v", err)
	}

	if len(addresses) != 0 {
		t.Errorf("Expected 0 addresses from empty file, got %d", len(addresses))
	}
}

// TestReadAddressesNonexistentFile tests error handling for nonexistent file
func TestReadAddressesNonexistentFile(t *testing.T) {
	_, err := readAddresses("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

// TestGenerateKeyAndAddress tests the generateKeyAndAddress function
func TestGenerateKeyAndAddress(t *testing.T) {
	privateKey, address, err := generateKeyAndAddress()
	if err != nil {
		t.Fatalf("generateKeyAndAddress failed: %v", err)
	}

	// Verify private key is not nil
	if privateKey == nil {
		t.Error("Private key is nil")
	}

	// Verify address is not empty
	if address == "" {
		t.Error("Address is empty")
	}

	// Verify address starts with '1' (P2PKH)
	if len(address) == 0 || address[0] != '1' {
		t.Errorf("Expected P2PKH address starting with '1', got: %s", address)
	}

	// Verify address length is reasonable (26-35 chars for P2PKH)
	if len(address) < 26 || len(address) > 35 {
		t.Errorf("Address length %d is outside expected range (26-35)", len(address))
	}
}

// TestGenerateKeyAndAddressMultiple tests that multiple calls generate different keys
func TestGenerateKeyAndAddressMultiple(t *testing.T) {
	addresses := make(map[string]bool)

	// Generate 100 addresses and verify they're all unique
	for i := 0; i < 100; i++ {
		_, address, err := generateKeyAndAddress()
		if err != nil {
			t.Fatalf("generateKeyAndAddress failed on iteration %d: %v", i, err)
		}

		if addresses[address] {
			t.Errorf("Duplicate address generated: %s", address)
		}
		addresses[address] = true
	}

	if len(addresses) != 100 {
		t.Errorf("Expected 100 unique addresses, got %d", len(addresses))
	}
}

// TestGenerateKeyAndAddressValidFormat tests address format validation
func TestGenerateKeyAndAddressValidFormat(t *testing.T) {
	// Base58 alphabet (excludes 0, O, I, l)
	validChars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	validMap := make(map[rune]bool)
	for _, c := range validChars {
		validMap[c] = true
	}

	// Generate and validate 10 addresses
	for i := 0; i < 10; i++ {
		_, address, err := generateKeyAndAddress()
		if err != nil {
			t.Fatalf("generateKeyAndAddress failed: %v", err)
		}

		// Check all characters are valid Base58
		for _, c := range address {
			if !validMap[c] {
				t.Errorf("Invalid Base58 character '%c' in address: %s", c, address)
			}
		}

		// Verify starts with '1'
		if address[0] != '1' {
			t.Errorf("Address does not start with '1': %s", address)
		}
	}
}

// TestBufferPool tests buffer pool functionality
func TestBufferPool(t *testing.T) {
	// Get buffer from pool
	buf1 := bufferPool.Get().([]byte)
	if cap(buf1) < 128 {
		t.Errorf("Expected buffer capacity >= 128, got %d", cap(buf1))
	}

	// Return to pool
	bufferPool.Put(buf1)

	// Get another buffer (should reuse)
	buf2 := bufferPool.Get().([]byte)

	// Verify it's a valid buffer
	if cap(buf2) < 128 {
		t.Errorf("Expected buffer capacity >= 128, got %d", cap(buf2))
	}

	bufferPool.Put(buf2)
}

// BenchmarkReadAddresses benchmarks reading addresses from file
func BenchmarkReadAddresses(b *testing.B) {
	// Create test file with addresses
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench-addresses.txt")

	// Generate 1000 test addresses
	content := ""
	for i := 0; i < 1000; i++ {
		// Use a simple pattern for benchmarking
		content += "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
	}
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to create benchmark file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := readAddresses(testFile)
		if err != nil {
			b.Fatalf("readAddresses failed: %v", err)
		}
	}
}

// BenchmarkGenerateKeyAndAddress benchmarks key and address generation
func BenchmarkGenerateKeyAndAddress(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := generateKeyAndAddress()
		if err != nil {
			b.Fatalf("generateKeyAndAddress failed: %v", err)
		}
	}
}
