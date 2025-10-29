/*
Bitcoin Wallet Bruteforce - Offline Version

Description:
	This program performs brute-force generation of Bitcoin private keys and addresses,
	checking them against a pre-loaded database of existing Bitcoin addresses.
	It generates Legacy P2PKH addresses (starting with '1') using compressed public keys.

Algorithm:
	1. Load target addresses into memory (hash map for O(1) lookup)
	2. Generate random private keys using cryptographically secure RNG
	3. Derive public key from private key (SECP256k1 elliptic curve)
	4. Create P2PKH address: Base58(version + RIPEMD160(SHA256(pubkey)) + checksum)
	5. Check if generated address exists in target database
	6. Save matches to output file

Address Database:
	Use any Bitcoin address database (e.g., http://alladdresses.loyce.club/)
	The database should contain one address per line in plain text format.

Performance Optimizations:
	- SIMD-accelerated SHA256 hashing (minio/sha256-simd)
	- Compressed public keys (33 bytes vs 65 bytes)
	- Buffer pooling to reduce memory allocations
	- Inline checksum calculation
	- Multi-threaded worker pool
	- Atomic counters with batch updates
	- Non-blocking match writing

Security Note:
	This is for educational/research purposes only. The probability of finding
	a match with funded addresses is astronomically low (1 in 2^160 for P2PKH).

Author: David Zita
License: MIT
*/

package main

import (
	"bufio"        // Buffered I/O for efficient file reading/writing
	"encoding/hex" // Hex encoding for private key output
	"fmt"          // Formatted I/O
	"log"          // Logging errors
	"os"           // OS operations (file handling, arguments)
	"runtime"      // Runtime information (CPU cores)
	"strconv"      // String to integer conversion
	"sync"         // Synchronization primitives (WaitGroup, Pool)
	"sync/atomic"  // Atomic operations for thread-safe counters
	"time"         // Time operations for statistics

	"github.com/btcsuite/btcd/btcec/v2"       // Bitcoin SECP256k1 elliptic curve operations
	"github.com/btcsuite/btcutil"             // Bitcoin utility functions (Hash160)
	"github.com/btcsuite/btcutil/base58"      // Base58 encoding for addresses
	sha256simd "github.com/minio/sha256-simd" // SIMD-accelerated SHA256 (2-3x faster)
)

// ============================================================================
// MEMORY OPTIMIZATION: Buffer Pool
// ============================================================================

/*
bufferPool is a sync.Pool for byte slices used in address generation.

Purpose:

	Reduces memory allocations by reusing byte buffers across goroutines.
	Each worker goroutine can borrow a buffer, use it, and return it to the pool.

Performance Impact:

	Without pooling: Millions of allocations per second → high GC pressure
	With pooling: Buffers are reused → minimal GC overhead

Buffer Size:

	Pre-allocated with 128 bytes capacity (sufficient for address generation):
	- 1 byte: version (0x00)
	- 20 bytes: Hash160
	- 4 bytes: checksum
	Total: 25 bytes (128 allows for growth without reallocation)
*/
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 128)
	},
}

// ============================================================================
// FILE OPERATIONS: Address Database Loading
// ============================================================================

/*
readAddresses loads Bitcoin addresses from a file into a hash map.

Parameters:

	filePath - Path to text file containing Bitcoin addresses (one per line)

Returns:
  - map[string]bool: Hash map for O(1) address lookup
  - error: Any error that occurred during file reading

Implementation Details:
  - Uses bufio.Scanner for efficient line-by-line reading
  - Stores addresses as map keys (bool value is unused, just for set semantics)
  - Memory usage: ~50-100 bytes per address depending on length

Performance:
  - Reading 1M addresses takes ~1-2 seconds
  - Hash map lookup is O(1) - constant time regardless of database size
  - Memory overhead: ~50MB per 1M addresses

Error Handling:

	Returns error if:
	- File doesn't exist
	- Permission denied
	- File is corrupted
	- I/O errors during reading
*/
func readAddresses(filePath string) (map[string]bool, error) {
	// Initialize empty hash map (will grow dynamically)
	addresses := make(map[string]bool)

	// Open file with read-only access
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close() // Ensure file is closed when function returns

	// Use buffered scanner for efficient line-by-line reading
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Add address to hash map (value 'true' is arbitrary, we only need the key)
		addresses[scanner.Text()] = true
	}

	// Check if scanner encountered any errors
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return addresses, nil
}

// ============================================================================
// CORE ALGORITHM: Bitcoin Key and Address Generation
// ============================================================================

/*
generateKeyAndAddress generates a random Bitcoin private key and corresponding P2PKH address.

Returns:
  - *btcec.PrivateKey: The generated private key (256-bit random number)
  - string: Legacy P2PKH Bitcoin address (Base58-encoded, starts with '1')
  - error: Any error during generation (extremely rare)

Bitcoin Address Generation Process:
 1. Generate random 256-bit private key using crypto/rand (CSPRNG)
 2. Derive public key via SECP256k1 elliptic curve multiplication: PubKey = PrivKey * G
 3. Compress public key: 33 bytes (prefix + x-coordinate) vs 65 bytes (uncompressed)
 4. Hash public key: Hash160 = RIPEMD160(SHA256(PubKey)) → 20 bytes
 5. Add version byte: 0x00 for mainnet P2PKH
 6. Calculate checksum: first 4 bytes of SHA256(SHA256(version + hash160))
 7. Encode with Base58: human-readable address (26-35 characters)

Address Format (P2PKH):

	┌─────────────┬──────────────┬─────────────┐
	│ Version (1) │ Hash160 (20) │ Checksum(4) │
	└─────────────┴──────────────┴─────────────┘
	       ↓              ↓              ↓
	    0x00        Public Key Hash   SHA256²(payload)[:4]

	Result: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (example)

Performance Optimizations:
  - Compressed public keys: 33 bytes vs 65 bytes (faster hashing)
  - SIMD SHA256: 2-3x faster than standard library implementation
  - Buffer pooling: Eliminates allocation overhead
  - Inline checksum: No intermediate allocations

Cryptographic Security:
  - Private key space: 2^256 possible keys (~10^77)
  - Address space: 2^160 possible addresses (~10^48)
  - Collision probability: negligible (similar to finding a specific atom in the universe)
*/
func generateKeyAndAddress() (*btcec.PrivateKey, string, error) {
	// STEP 1: Generate cryptographically secure random private key (256 bits)
	// Uses crypto/rand internally - secure random number generator
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, "", err
	}

	// STEP 2: Derive public key from private key using SECP256k1 curve
	// STEP 3: Use compressed format (33 bytes instead of 65 bytes)
	// Format: 0x02/0x03 (prefix indicating y-coordinate parity) + x-coordinate (32 bytes)
	pubKeyBytes := privateKey.PubKey().SerializeCompressed()

	// STEP 4: Create Hash160 (RIPEMD160(SHA256(pubkey)))
	// This is the actual "address" - a 20-byte hash of the public key
	hash160 := btcutil.Hash160(pubKeyBytes)

	// Get reusable buffer from pool (reduces GC pressure)
	buf := bufferPool.Get().([]byte)[:0]
	// Return buffer to pool when done
	// Note: Slices are already reference types (contain pointer to underlying array)
	// The SA6002 staticcheck warning here is a known false positive:
	// - Slices are already reference types (internally contain pointer to array)
	// - Wrapping in pointer would add overhead without benefit
	// - sync.Pool.Put() signature accepts interface{}, which boxes the value anyway
	defer bufferPool.Put(buf)

	// STEP 5: Build versioned payload for Base58 encoding
	buf = append(buf, 0x00)       // Version byte: 0x00 = mainnet P2PKH (addresses start with '1')
	buf = append(buf, hash160...) // Append 20-byte public key hash

	// STEP 6: Calculate checksum using double SHA256
	// Checksum = SHA256(SHA256(version + hash160))[:4]
	// Using SIMD-accelerated implementation for 2-3x speedup
	h1 := sha256simd.Sum256(buf)   // First SHA256 hash
	h2 := sha256simd.Sum256(h1[:]) // Second SHA256 hash (double-SHA256)

	// STEP 7: Append first 4 bytes of double-hash as checksum
	buf = append(buf, h2[:4]...)
	// Buffer now contains: [version(1) + hash160(20) + checksum(4)] = 25 bytes

	// STEP 8: Encode to Base58 (Bitcoin's address encoding)
	// Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
	// (excludes 0, O, I, l to avoid confusion)
	address := base58.Encode(buf)

	return privateKey, address, nil
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/*
MatchResult represents a successful match between generated and target address.

Fields:
  - privateKey: The private key that generated the matching address
  - address: The matching Bitcoin address (P2PKH format)

Purpose:

	This struct is sent through a channel from worker goroutines to the
	matchWriter goroutine for asynchronous file writing.
*/
type MatchResult struct {
	privateKey *btcec.PrivateKey
	address    string
}

// ============================================================================
// WORKER POOL: Multi-threaded Brute Force
// ============================================================================

/*
worker is a goroutine that continuously generates Bitcoin addresses and checks for matches.

Parameters:
  - id: Worker thread identifier (for logging)
  - wg: WaitGroup for coordinating shutdown (currently runs indefinitely)
  - btcAddresses: Hash map of target addresses to search for
  - matchChan: Channel to send matches to the writer goroutine
  - counter: Shared atomic counter for statistics tracking

Algorithm:
 1. Generate random private key and address
 2. Check if address exists in target database (O(1) hash map lookup)
 3. If match found, send to matchWriter via channel
 4. Update global counter periodically (batch updates for performance)
 5. Repeat indefinitely

Performance Optimizations:
  - Local counter: Batches atomic operations (10,000 keys per update)
  - Atomic operations are expensive (CPU cache synchronization)
  - Batching reduces contention and improves throughput
  - Non-blocking match sending: Channel has buffer to prevent blocking
  - Continue on error: Rare errors don't stop the worker

Concurrency Model:
  - Multiple workers run in parallel (typically numCPUs or numCPUs*2)
  - Each worker operates independently with its own RNG state
  - Shared state: btcAddresses (read-only), counter (atomic), matchChan (buffered)

Statistics:
  - Batch size: 10,000 keys (updateInterval)
  - Atomic updates reduce contention by 10,000x compared to updating every iteration
  - Typical throughput: 10,000-50,000 keys/sec per core (CPU-dependent)
*/
func worker(id int, wg *sync.WaitGroup, btcAddresses map[string]bool, matchChan chan<- MatchResult, counter *uint64) {
	defer wg.Done() // Signal completion when function returns (never in this case)

	// Local counter for batching atomic updates
	localCounter := uint64(0)
	const updateInterval = 10000 // Update global counter every 10k iterations

	// Infinite loop: continuously generate and check addresses
	for {
		// Generate new random private key and corresponding address
		privateKey, publicAddress, err := generateKeyAndAddress()
		if err != nil {
			// This should be extremely rare (only if RNG fails)
			log.Printf("Worker %d: Failed to generate key and address: %s", id, err)
			continue // Skip this iteration and try again
		}

		// Increment local counter
		localCounter++

		// Batch update: Only update global counter every 10,000 iterations
		// This reduces expensive atomic operations and cache synchronization
		if localCounter%updateInterval == 0 {
			atomic.AddUint64(counter, updateInterval) // Thread-safe increment
			localCounter = 0                          // Reset local counter
		}

		// Check if generated address exists in target database
		// Hash map lookup is O(1) - constant time regardless of database size
		if _, exists := btcAddresses[publicAddress]; exists {
			// *** MATCH FOUND! ***
			// This is an extremely rare event (probability: 1 in 2^160 per address)
			fmt.Printf("\n*** MATCH FOUND! ***\nAddress: %s\n\n", publicAddress)

			// Send match to writer goroutine via buffered channel
			// Non-blocking if buffer has space
			matchChan <- MatchResult{privateKey: privateKey, address: publicAddress}
		}
	}
}

// ============================================================================
// FILE I/O: Asynchronous Match Writing
// ============================================================================

/*
matchWriter is a dedicated goroutine that writes found matches to a file.

Parameters:
  - matchChan: Receive-only channel for MatchResult structs from workers
  - outputFile: Path to output file for saving matches
  - wg: WaitGroup to signal completion when channel closes

Architecture:

	This function runs in a separate goroutine, decoupling file I/O from
	the hot path of address generation. Workers send matches via channel
	and continue generating without waiting for disk writes.

Output Format:

	Each line: <private_key_hex>:<bitcoin_address>
	Example: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

File Operations:
  - Opens file in append mode (preserves existing matches)
  - Creates file if doesn't exist
  - Sets permissions to 0644 (owner: rw, group/others: r)
  - Uses buffered writer for efficient disk I/O
  - Flushes after each write to prevent data loss

Performance:
  - Buffered I/O: Reduces system calls
  - Immediate flush: Ensures data is saved even if program crashes
  - Channel-based: Non-blocking for worker goroutines

Error Handling:
  - Fatal error if file can't be opened (can't save results)
  - Log error if individual write fails, but continue processing
  - Graceful shutdown when channel is closed
*/
func matchWriter(matchChan <-chan MatchResult, outputFile string, wg *sync.WaitGroup) {
	defer wg.Done() // Signal completion when function returns

	// Open output file with append mode (creates if doesn't exist)
	// Flags: O_APPEND (append to end), O_CREATE (create if needed), O_WRONLY (write-only)
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %s", err)
	}
	defer file.Close() // Ensure file is closed on exit

	// Use buffered writer for efficient disk I/O (reduces system calls)
	writer := bufio.NewWriter(file)
	defer writer.Flush() // Ensure all buffered data is written on exit

	// Process matches as they arrive via channel
	// Loop exits when channel is closed
	for match := range matchChan {
		// Convert private key to hexadecimal format (64 hex characters = 256 bits)
		// This conversion is done here (not in hot path) to avoid slowing down workers
		privKeyBytes := match.privateKey.Serialize()
		privKeyHex := hex.EncodeToString(privKeyBytes)

		// Write to file in format: <privkey_hex>:<address>
		if _, err := writer.WriteString(fmt.Sprintf("%s:%s\n", privKeyHex, match.address)); err != nil {
			log.Printf("Failed to write match to file: %s", err)
		}

		// Flush immediately to ensure data is saved (important for rare matches)
		writer.Flush()

		// Also print to console for immediate visibility
		fmt.Printf("SAVED TO FILE: %s:%s\n\n", privKeyHex, match.address)
	}
}

// ============================================================================
// STATISTICS: Real-time Performance Monitoring
// ============================================================================

/*
statsReporter is a goroutine that periodically displays performance statistics.

Parameters:
  - counter: Pointer to shared atomic counter (total keys generated across all workers)
  - startTime: Program start time for calculating overall runtime

Output:

	Prints statistics every 10 seconds:
	- Total keys generated since start
	- Overall rate: Average keys/sec since program started
	- Current rate: Instantaneous keys/sec (last 10 seconds)
	- Runtime: Total elapsed time in seconds

Metrics Explained:
  - Total: Cumulative count of all generated addresses
  - Overall Rate: total / elapsed_time (smoothed average)
  - Current Rate: interval_keys / interval_time (real-time performance)
  - Runtime: Time since program started

Performance Analysis:
  - Current rate higher than overall: Performance improving (CPU warming up)
  - Current rate lower than overall: Performance degrading (thermal throttling, contention)
  - Current rate fluctuating: Normal due to OS scheduling, GC pauses, etc.

Typical Performance:
  - Modern CPU (2020+): 20,000-50,000 keys/sec per core
  - Total throughput: rate * num_workers
  - Example: 8 cores × 30,000 keys/sec = 240,000 keys/sec total

Thread Safety:
  - Uses atomic.LoadUint64() for thread-safe counter reading
  - No locks required (read-only access to shared counter)
*/
func statsReporter(counter *uint64, startTime time.Time) {
	// Create ticker that fires every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop() // Clean up ticker when function returns

	// Track previous values for calculating instantaneous rate
	lastTotal := uint64(0)
	lastTime := startTime

	// Wait for ticker events (every 10 seconds)
	for range ticker.C {
		// Read current counter value (thread-safe atomic operation)
		total := atomic.LoadUint64(counter)
		now := time.Now()

		// Calculate overall statistics (since program start)
		elapsed := time.Since(startTime).Seconds()
		overallRate := float64(total) / elapsed

		// Calculate instantaneous rate (last 10 seconds only)
		intervalKeys := total - lastTotal           // Keys generated in last interval
		intervalTime := now.Sub(lastTime).Seconds() // Time elapsed in last interval
		instantRate := float64(intervalKeys) / intervalTime

		// Display statistics
		fmt.Printf("[Stats] Total: %d | Overall: %.0f keys/sec | Current: %.0f keys/sec | Runtime: %.0fs\n",
			total, overallRate, instantRate, elapsed)

		// Update tracking variables for next iteration
		lastTotal = total
		lastTime = now
	}
}

// ============================================================================
// MAIN: Program Entry Point and Orchestration
// ============================================================================

/*
main orchestrates the entire brute-force operation.

Program Flow:
 1. Parse command-line arguments
 2. Configure runtime (GOMAXPROCS)
 3. Load target address database into memory
 4. Initialize shared data structures (counter, channels, waitgroups)
 5. Start matchWriter goroutine (file I/O)
 6. Start statsReporter goroutine (monitoring)
 7. Start worker pool goroutines (brute force)
 8. Wait for completion (runs indefinitely until interrupted)

Command-line Arguments:
 1. threads: Number of worker goroutines (typically numCPUs or numCPUs*2)
 2. output-file.txt: File to save matches (created if doesn't exist, appended if exists)
 3. btc-address-file.txt: Database of target addresses (one per line)

Usage Examples:

	./bitcoin-wallet-bruteforce-offline 8 matches.txt addresses.txt
	./bitcoin-wallet-bruteforce-offline 16 output.txt attack-addresses-p2pkh.txt

Architecture:

	┌──────────────┐
	│ Main Thread  │
	└──────┬───────┘
	       │
	       ├──> [Match Writer] ──> output.txt
	       ├──> [Stats Reporter] ──> console (every 10s)
	       ├──> [Worker 1] ─┐
	       ├──> [Worker 2] ─┤
	       ├──> [Worker 3] ─┼──> matchChan ──> Match Writer
	       └──> [Worker N] ─┘

Concurrency Model:
  - N worker goroutines: Generate and check addresses (CPU-bound)
  - 1 match writer goroutine: Write matches to file (I/O-bound)
  - 1 stats reporter goroutine: Display statistics (timer-based)
  - Communication via buffered channel (100 slots)
  - Synchronization via WaitGroups and atomic counter

Memory Usage:
  - Address database: ~50MB per 1M addresses
  - Per-worker overhead: minimal (mostly stack space)
  - Buffer pool: reused across workers
  - Channel buffer: 100 * sizeof(MatchResult) ≈ 10KB

Performance Tuning:
  - Optimal threads: Usually equals number of CPU cores
  - Too few threads: CPU underutilized
  - Too many threads: Context switching overhead, diminishing returns
  - Monitor "Current rate" in stats to find sweet spot
*/
func main() {
	// ========================================================================
	// ARGUMENT PARSING AND VALIDATION
	// ========================================================================

	// Check if correct number of arguments provided
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./bitcoin-wallet-bruteforce-offline <threads> <output-file.txt> <btc-address-file.txt>")
		fmt.Println()
		fmt.Println("Arguments:")
		fmt.Println("  threads            - Number of worker threads (recommend: num CPU cores)")
		fmt.Println("  output-file.txt    - Output file for saving matches")
		fmt.Println("  btc-address-file.txt - Input file with target Bitcoin addresses")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline 8 matches.txt attack-addresses-p2pkh.txt")
		os.Exit(1)
	}

	// Parse number of worker threads
	numThreads, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid number of threads: %s", err)
	}

	// Validate thread count
	if numThreads < 1 {
		log.Fatalf("Number of threads must be at least 1")
	}

	// ========================================================================
	// RUNTIME CONFIGURATION
	// ========================================================================

	// Configure Go runtime to use all available CPU cores
	// GOMAXPROCS controls how many OS threads can execute Go code simultaneously
	runtime.GOMAXPROCS(runtime.NumCPU())

	// ========================================================================
	// BANNER AND SYSTEM INFORMATION
	// ========================================================================

	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Bitcoin Wallet Bruteforce - Optimized Edition            ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("CPU Cores: %d | Worker Threads: %d\n", runtime.NumCPU(), numThreads)
	fmt.Printf("SHA256: Hardware Accelerated (SIMD)\n")
	fmt.Printf("Public Key: Compressed (33 bytes)\n")
	fmt.Printf("Address Type: Legacy P2PKH (starts with '1')\n\n")

	// ========================================================================
	// FILE ARGUMENT EXTRACTION
	// ========================================================================

	outputFile := os.Args[2]       // Where to save matches
	btcAddressesFile := os.Args[3] // Database of target addresses

	// ========================================================================
	// ADDRESS DATABASE LOADING
	// ========================================================================

	fmt.Printf("Loading addresses from %s...\n", btcAddressesFile)
	btcAddresses, err := readAddresses(btcAddressesFile)
	if err != nil {
		log.Fatalf("Failed to read BTC addresses: %s", err)
	}
	fmt.Printf("✓ Loaded %d addresses to check against\n\n", len(btcAddresses))

	// ========================================================================
	// SHARED STATE INITIALIZATION
	// ========================================================================

	// Atomic counter for total keys generated (shared across all workers)
	var counter uint64

	// Buffered channel for sending matches from workers to file writer
	// Buffer size: 100 (prevents blocking if matches found in bursts)
	matchChan := make(chan MatchResult, 100)

	// WaitGroups for coordinating goroutine shutdown
	var workerWg sync.WaitGroup // Tracks worker goroutines
	var writerWg sync.WaitGroup // Tracks writer goroutine

	// ========================================================================
	// GOROUTINE STARTUP
	// ========================================================================

	// Start match writer goroutine (handles file I/O asynchronously)
	writerWg.Add(1)
	go matchWriter(matchChan, outputFile, &writerWg)

	// Start stats reporter goroutine (displays performance metrics)
	startTime := time.Now()
	go statsReporter(&counter, startTime)

	// Start worker pool (brute force address generation)
	fmt.Printf("Starting brute force...\n")
	fmt.Printf("════════════════════════════════════════════════════════════\n\n")
	for i := 0; i < numThreads; i++ {
		workerWg.Add(1)
		go worker(i, &workerWg, btcAddresses, matchChan, &counter)
	}

	// ========================================================================
	// MAIN LOOP (BLOCKING)
	// ========================================================================

	// Wait for all workers to complete (never happens in current implementation)
	// Workers run indefinitely until program is interrupted (Ctrl+C)
	workerWg.Wait()

	// Close match channel to signal writer to finish
	close(matchChan)

	// Wait for writer to finish processing remaining matches
	writerWg.Wait()

	// Note: Program typically runs until manually interrupted
	// To implement graceful shutdown, add signal handling (SIGINT, SIGTERM)
}
