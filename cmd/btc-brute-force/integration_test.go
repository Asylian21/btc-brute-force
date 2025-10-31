//go:build integration
// +build integration

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestBinaryExecution tests that the binary can be executed
func TestBinaryExecution(t *testing.T) {
	// Build the binary first
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "btc-brute-force-test")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = "."
	if err := cmd.Run(); err != nil {
		t.Skipf("Skipping integration test: failed to build binary: %v", err)
	}

	// Test invalid arguments (should exit with code 1)
	cmd = exec.Command(binaryPath, "invalid", "args")
	if err := cmd.Run(); err == nil {
		t.Error("Expected error for invalid arguments, got nil")
	}
}

// TestBinaryWithMockData tests binary execution with mock address file
func TestBinaryWithMockData(t *testing.T) {
	// Build the binary
	buildDir := t.TempDir()
	binaryPath := filepath.Join(buildDir, "btc-brute-force-test")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if err := cmd.Run(); err != nil {
		t.Skipf("Skipping integration test: failed to build binary: %v", err)
	}

	// Create temporary directory for test files
	tmpDir := t.TempDir()
	addressFile := filepath.Join(tmpDir, "test-addresses.txt")
	outputFile := filepath.Join(tmpDir, "output.txt")

	// Create test address file
	testAddresses := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
	if err := os.WriteFile(addressFile, []byte(testAddresses), 0644); err != nil {
		t.Fatalf("Failed to create test address file: %v", err)
	}

	// Run binary with timeout (it runs indefinitely, so we'll kill it)
	cmd = exec.Command(binaryPath, "1", outputFile, addressFile)
	cmd.Dir = tmpDir

	// Start the process
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start binary: %v", err)
	}

	// Let it run for a short time
	time.Sleep(2 * time.Second)

	// Kill the process (it runs indefinitely)
	if err := cmd.Process.Kill(); err != nil {
		t.Logf("Warning: failed to kill process: %v", err)
	}

	// Wait for process to exit
	cmd.Wait()

	// Verify output file was created (even if empty)
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}
