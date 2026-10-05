//go:build integration
// +build integration

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func buildTestBinary(t *testing.T, binaryPath string) {
	t.Helper()

	root := filepath.Join("..", "..")
	ldflags := "-s -w"
	if runtime.GOOS == "darwin" {
		ldflags += " -linkmode=external"
	}

	cmd := exec.Command("go", "build", "-ldflags="+ldflags, "-o", binaryPath, ".")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build integration binary: %v\n%s", err, output)
	}
}

// TestBinaryExecution tests that the binary can be executed
func TestBinaryExecution(t *testing.T) {
	// Build the binary first
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "btc-brute-force-test")
	buildTestBinary(t, binaryPath)

	// Test invalid arguments (should exit with code 1)
	cmd := exec.Command(binaryPath, "invalid", "args")
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("Expected exit code 1 for invalid arguments, got %v", err)
	}
}

// TestBinaryWithMockData tests binary execution with mock address file
func TestBinaryWithMockData(t *testing.T) {
	// Build the binary
	buildDir := t.TempDir()
	binaryPath := filepath.Join(buildDir, "btc-brute-force-test")
	buildTestBinary(t, binaryPath)

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
	// Exercise the CPU libraries directly. GPU auto-tuning can exceed this
	// test's run window and has separate on-device integration coverage.
	cmd := exec.Command(binaryPath, "--gpu=off", "1", outputFile, addressFile)
	cmd.Dir = tmpDir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

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
		t.Fatalf("Output file was not created:\n%s", output.String())
	}
}
