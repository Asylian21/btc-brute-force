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
	- Batched affine EC walk: one scalar multiplication per worker, then whole
	  batches of keys via group addition P+iG against a precomputed table of
	  multiples of G (no per-key scalar mult, no Jacobian->affine conversion)
	- Batched (Montgomery) field inversion: a single inversion per 1024 keys
	  amortizes the only division in the affine addition formula
	- SIMD-accelerated SHA256 hashing (minio/sha256-simd)
	- Specialized single-block RIPEMD160 (fixed 32-byte input; no streaming/interface overhead)
	- Alloc-free hot path: reused per-worker scratch buffers
	- Compressed public keys (33 bytes vs 65 bytes)
	- Hash160-only lookups (Base58 deferred to the rare match path)
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
	"bufio"           // Buffered I/O for efficient file reading/writing
	"crypto/rand"     // CSPRNG for the per-worker random starting scalar
	"encoding/binary" // Encode the per-worker key offset into a scalar
	"encoding/hex"    // Hex encoding for private key output
	"encoding/json"   // Checkpoint serialization (resume support)
	"flag"            // CLI flag parsing (--checkpoint, --resume)
	"fmt"             // Formatted I/O
	"log"             // Logging errors
	"math/bits"       // Hardware rotate (RotateLeft32) for the RIPEMD160 core
	"os"              // OS operations (file handling, arguments)
	"os/signal"       // Graceful shutdown: final checkpoint on SIGINT/SIGTERM
	"runtime"         // Runtime information (CPU cores)
	"runtime/debug"   // GC tuning for sustained throughput
	"strconv"         // String to integer conversion
	"sync"            // Synchronization primitives (WaitGroup, Pool)
	"sync/atomic"     // Atomic operations for thread-safe counters
	"syscall"         // Signal constants (SIGINT/SIGTERM) for graceful shutdown
	"time"            // Time operations for statistics

	"github.com/btcsuite/btcd/btcec/v2"              // Bitcoin SECP256k1 elliptic curve operations
	"github.com/btcsuite/btcutil"                    // Bitcoin utility functions (Hash160, reference path)
	"github.com/btcsuite/btcutil/base58"             // Base58 encoding for addresses
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4" // Low-level EC point arithmetic (incremental walk)
	sha256simd "github.com/minio/sha256-simd"        // SIMD-accelerated SHA256 (2-3x faster)
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

// hash160Set is the target database keyed by 20-byte pubkey hashes (not Base58 strings).
type hash160Set map[[20]byte]struct{}

/*
readTargetHashes loads Bitcoin P2PKH addresses and stores their Hash160 for O(1) lookup.

The hot path compares 20-byte hashes only — Base58 encoding and checksum SHA256 run solely on
the extremely rare match path, not on every generated key.
*/
func readTargetHashes(filePath string) (hash160Set, error) {
	targets := make(hash160Set)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		addr := scanner.Text()
		if addr == "" {
			continue
		}

		decoded := base58.Decode(addr)
		// P2PKH mainnet: version(1) + hash160(20) + checksum(4)
		if len(decoded) != 25 || decoded[0] != 0x00 {
			log.Printf("Skipping invalid P2PKH address at line %d: %s", lineNum, addr)
			continue
		}

		var h [20]byte
		copy(h[:], decoded[1:21])
		targets[h] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// ============================================================================
// CORE ALGORITHM: Bitcoin Key and Address Generation
// ============================================================================

/*
generateKeyAndHash160 is the hot-path primitive: random key + compressed pubkey + Hash160.

Base58 and checksum are deferred to encodeP2PKH, which runs only when a Hash160 hits the target set.
*/
func generateKeyAndHash160() (*btcec.PrivateKey, [20]byte, error) {
	// NewPrivateKey() uses ecdsa.GenerateKey (scalar mult) then PubKey() repeats it.
	// PrivKeyFromBytes + returned PublicKey avoids the duplicate curve operation.
	var privBytes [32]byte
	if _, err := rand.Read(privBytes[:]); err != nil {
		return nil, [20]byte{}, err
	}

	privateKey, pubKey := btcec.PrivKeyFromBytes(privBytes[:])
	pubKeyBytes := pubKey.SerializeCompressed()
	digest := btcutil.Hash160(pubKeyBytes)

	var hash160 [20]byte
	copy(hash160[:], digest)
	return privateKey, hash160, nil
}

// encodeP2PKH builds a legacy mainnet P2PKH Base58 address from a Hash160 (match path only).
func encodeP2PKH(hash160 [20]byte) string {
	buf := bufferPool.Get().([]byte)[:0]
	defer bufferPool.Put(buf)

	buf = append(buf, 0x00)
	buf = append(buf, hash160[:]...)

	h1 := sha256simd.Sum256(buf)
	h2 := sha256simd.Sum256(h1[:])
	buf = append(buf, h2[:4]...)
	return base58.Encode(buf)
}

// ============================================================================
// HOT PATH PRIMITIVE: RIPEMD160 of a single 32-byte block
// ============================================================================
//
// Hash160 = RIPEMD160(SHA256(pubkey)); the RIPEMD160 input is therefore ALWAYS
// exactly the 32-byte SHA256 digest. The generic streaming hasher
// (golang.org/x/crypto/ripemd160, a pure-Go, now-deprecated package) pays on
// EVERY call for interface dispatch, an internal 64-byte buffer copy, message-
// length bookkeeping and padding. With a fixed 32-byte input all of that is
// constant: the padded 512-bit block is the 32 message bytes, a 0x80 byte, zero
// padding, and the bit length 256 — so the whole hash collapses to a single
// compression-function evaluation started from the standard initial state.
//
// ripemd160Hash32 reproduces the exact algorithm of x/crypto's _Block (the
// digest is bit-identical: verified directly by TestRIPEMD160Hash32 against the
// reference implementation, and end-to-end by TestKeyStreamMatchesReference
// against btcutil.Hash160) while stripping all per-call overhead from the hot
// loop, which runs this once per generated key.

// RIPEMD160 initial state h0..h4.
const (
	ripemd160H0 = 0x67452301
	ripemd160H1 = 0xefcdab89
	ripemd160H2 = 0x98badcfe
	ripemd160H3 = 0x10325476
	ripemd160H4 = 0xc3d2e1f0
)

// Per-step message-word selection (n*) and left-rotate amounts (r*) for the two
// parallel RIPEMD160 lines, exactly as specified by the algorithm.
var (
	ripemd160nLeft = [80]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	ripemd160rLeft = [80]uint8{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	ripemd160nRight = [80]uint8{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	ripemd160rRight = [80]uint8{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
)

// ripemd160Hash32 writes RIPEMD160(msg) into out[:20] for a fixed 32-byte msg
// (a SHA-256 digest). out must have length >= 20.
func ripemd160Hash32(msg *[32]byte, out []byte) {
	// 16-word schedule of the single padded block: 8 data words, then the 0x80
	// padding byte (word 8 == 0x00000080), zeros, and the 64-bit message length
	// 256 bits in the low length word (word 14). Words 9..13 and 15 stay zero.
	var x [16]uint32
	x[0] = binary.LittleEndian.Uint32(msg[0:4])
	x[1] = binary.LittleEndian.Uint32(msg[4:8])
	x[2] = binary.LittleEndian.Uint32(msg[8:12])
	x[3] = binary.LittleEndian.Uint32(msg[12:16])
	x[4] = binary.LittleEndian.Uint32(msg[16:20])
	x[5] = binary.LittleEndian.Uint32(msg[20:24])
	x[6] = binary.LittleEndian.Uint32(msg[24:28])
	x[7] = binary.LittleEndian.Uint32(msg[28:32])
	x[8] = 0x80
	x[14] = 256

	a, b, c, d, e := uint32(ripemd160H0), uint32(ripemd160H1), uint32(ripemd160H2), uint32(ripemd160H3), uint32(ripemd160H4)
	aa, bb, cc, dd, ee := a, b, c, d, e
	var alpha, beta uint32

	// The &15 masks let the compiler drop the bounds checks on x (the table
	// values are always 0..15); rotates use math/bits for a single hardware
	// ROL, matching x/crypto's well-tuned core.
	i := 0
	for i < 16 { // round 1: f1 (left), f5 (right)
		alpha = a + (b ^ c ^ d) + x[ripemd160nLeft[i]&15]
		alpha = bits.RotateLeft32(alpha, int(ripemd160rLeft[i])) + e
		beta = bits.RotateLeft32(c, 10)
		a, b, c, d, e = e, alpha, b, beta, d

		alpha = aa + (bb ^ (cc | ^dd)) + x[ripemd160nRight[i]&15] + 0x50a28be6
		alpha = bits.RotateLeft32(alpha, int(ripemd160rRight[i])) + ee
		beta = bits.RotateLeft32(cc, 10)
		aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd
		i++
	}
	for i < 32 { // round 2: f2 (left), f4 (right)
		alpha = a + (b&c | ^b&d) + x[ripemd160nLeft[i]&15] + 0x5a827999
		alpha = bits.RotateLeft32(alpha, int(ripemd160rLeft[i])) + e
		beta = bits.RotateLeft32(c, 10)
		a, b, c, d, e = e, alpha, b, beta, d

		alpha = aa + (bb&dd | cc&^dd) + x[ripemd160nRight[i]&15] + 0x5c4dd124
		alpha = bits.RotateLeft32(alpha, int(ripemd160rRight[i])) + ee
		beta = bits.RotateLeft32(cc, 10)
		aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd
		i++
	}
	for i < 48 { // round 3: f3 (left), f3 (right)
		alpha = a + (b | ^c ^ d) + x[ripemd160nLeft[i]&15] + 0x6ed9eba1
		alpha = bits.RotateLeft32(alpha, int(ripemd160rLeft[i])) + e
		beta = bits.RotateLeft32(c, 10)
		a, b, c, d, e = e, alpha, b, beta, d

		alpha = aa + (bb | ^cc ^ dd) + x[ripemd160nRight[i]&15] + 0x6d703ef3
		alpha = bits.RotateLeft32(alpha, int(ripemd160rRight[i])) + ee
		beta = bits.RotateLeft32(cc, 10)
		aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd
		i++
	}
	for i < 64 { // round 4: f4 (left), f2 (right)
		alpha = a + (b&d | c&^d) + x[ripemd160nLeft[i]&15] + 0x8f1bbcdc
		alpha = bits.RotateLeft32(alpha, int(ripemd160rLeft[i])) + e
		beta = bits.RotateLeft32(c, 10)
		a, b, c, d, e = e, alpha, b, beta, d

		alpha = aa + (bb&cc | ^bb&dd) + x[ripemd160nRight[i]&15] + 0x7a6d76e9
		alpha = bits.RotateLeft32(alpha, int(ripemd160rRight[i])) + ee
		beta = bits.RotateLeft32(cc, 10)
		aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd
		i++
	}
	for i < 80 { // round 5: f5 (left), f1 (right)
		alpha = a + (b ^ (c | ^d)) + x[ripemd160nLeft[i]&15] + 0xa953fd4e
		alpha = bits.RotateLeft32(alpha, int(ripemd160rLeft[i])) + e
		beta = bits.RotateLeft32(c, 10)
		a, b, c, d, e = e, alpha, b, beta, d

		alpha = aa + (bb ^ cc ^ dd) + x[ripemd160nRight[i]&15]
		alpha = bits.RotateLeft32(alpha, int(ripemd160rRight[i])) + ee
		beta = bits.RotateLeft32(cc, 10)
		aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd
		i++
	}

	// Single-block combine from the standard initial state (h0..h4 constants).
	dd += c + uint32(ripemd160H1)
	binary.LittleEndian.PutUint32(out[0:4], dd)
	binary.LittleEndian.PutUint32(out[4:8], uint32(ripemd160H2)+d+ee)
	binary.LittleEndian.PutUint32(out[8:12], uint32(ripemd160H3)+e+aa)
	binary.LittleEndian.PutUint32(out[12:16], uint32(ripemd160H4)+a+bb)
	binary.LittleEndian.PutUint32(out[16:20], uint32(ripemd160H0)+b+cc)
}

// ============================================================================
// HOT PATH: Batched Affine EC Walk ("giant step" group addition)
// ============================================================================
//
// A full scalar multiplication (k*G) costs ~256 EC operations and dominates
// runtime. Instead of paying that per key, each worker performs ONE scalar
// multiplication to land on a random affine base point P = k0*G, then derives a
// whole batch of consecutive keys with a single field inversion.
//
// The trick: a fixed table holds the affine multiples 1*G, 2*G, ..., N*G. For a
// batch we want P+1G, P+2G, ..., P+NG. Affine point addition P+Q needs one
// division by (x_Q - x_P). Because every x_{iG} is a precomputed constant and
// x_P is fixed for the batch, ALL N denominators are known up front, so they are
// inverted together with Montgomery's trick (one Inverse + ~3 mults per key).
// Each key then costs only ~2 mults + 1 square for the slope and new coordinates
// — roughly 3x fewer field multiplications than walking in Jacobian form and
// converting every point back to affine (which needs X/Z^2 and Y/Z^3 per key).
//
// Degenerate cases (P == ±iG, i.e. a zero denominator) are ignored: for a random
// 256-bit base point the probability is ~N/2^256 and a single wrong key out of
// 2^256 is irrelevant to a brute-force search.

// keyBatchSize is the number of keys produced per field inversion. It is also
// the size of the precomputed multiples-of-G table. Larger batches amortize the
// single inversion over more keys, but the per-worker scratch and the shared
// table eventually spill out of cache. Benchmarks on Apple M3 show a clear
// minimum at 2048 (587 ns/key vs 637 at 1024 and 635 at 4096).
const keyBatchSize = 2048

// Precomputed affine multiples of the base point: mulGx[j]/mulGy[j] = ((j+1)*G).
// mulGnegX[j] = -mulGx[j] (normalized) so the hot loop can compute x3 = λ²-x_P-x_Q
// with plain additions. The table is read-only and shared across all workers.
var (
	mulGx    [keyBatchSize]secp.FieldVal
	mulGy    [keyBatchSize]secp.FieldVal
	mulGnegX [keyBatchSize]secp.FieldVal
)

func init() {
	var s secp.ModNScalar
	var p secp.JacobianPoint
	for j := 0; j < keyBatchSize; j++ {
		s.SetInt(uint32(j + 1))
		secp.ScalarBaseMultNonConst(&s, &p)
		p.ToAffine() // Z=1, X/Y normalized to magnitude 1
		mulGx[j].Set(&p.X)
		mulGy[j].Set(&p.Y)
		mulGnegX[j].NegateVal(&p.X, 1)
		mulGnegX[j].Normalize()
	}
}

/*
keyStream produces consecutive Bitcoin keys for a single worker.

It owns all scratch buffers so the hot loop performs zero heap allocations.
The starting scalar is drawn from crypto/rand once; from then on keys are
generated by batched EC point addition with no further RNG calls.

Invariant: at the start of each batch the affine point (px, py) equals
(base + offset)*G, so out[j] in nextBatch corresponds to private scalar
base + start + j.
*/
type keyStream struct {
	base     secp.ModNScalar // starting private scalar k0
	px, py   secp.FieldVal   // running base point P = (base+offset)*G, affine (mag 1)
	offset   uint64          // number of keys produced so far (base == offset 0)
	dx       []secp.FieldVal // scratch: denominators (x_iG - x_P) then their inverses
	pre      []secp.FieldVal // scratch: Montgomery prefix products
	degenIdx []int           // batch indices where P == ±iG (zero denominator)
	pub      [33]byte        // stable compressed-pubkey scratch (avoids per-key alloc)
	shaBuf   [32]byte        // stable SHA256 scratch (digest fed into ripemd160Hash32)
}

// setBase derives the affine starting point P = base*G from a 32-byte seed,
// reducing the seed mod N. Used by both the production and test constructors.
func (ks *keyStream) setBase(seed [32]byte) {
	ks.base.SetBytes(&seed)
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&ks.base, &p)
	p.ToAffine()
	ks.px.Set(&p.X)
	ks.py.Set(&p.Y)
}

// newKeyStream seeds a worker's key stream from the system CSPRNG.
func newKeyStream() (*keyStream, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return newKeyStreamFromSeed(seed), nil
}

// newKeyStreamFromSeed builds a key stream that starts at a known scalar instead
// of a random one. It is used by --resume: the saved "next private key" becomes
// the new base, so generation continues exactly where the previous run stopped.
func newKeyStreamFromSeed(seed [32]byte) *keyStream {
	ks := &keyStream{
		dx:       make([]secp.FieldVal, keyBatchSize),
		pre:      make([]secp.FieldVal, keyBatchSize),
		degenIdx: make([]int, 0, 4),
	}
	ks.setBase(seed)
	return ks
}

// affineAt computes the affine point (base + absOffset)*G into (x, y). Used only
// on the rare degenerate path where the fast batched addition divides by zero.
func (ks *keyStream) affineAt(absOffset uint64, x, y *secp.FieldVal) {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], absOffset)
	var add, res secp.ModNScalar
	add.SetBytes(&addBytes)
	res.Set(&ks.base).Add(&add)
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&res, &p)
	p.ToAffine()
	x.Set(&p.X)
	y.Set(&p.Y)
}

// hashPoint writes Hash160(compressed pubkey) of the affine point (x, y) into
// out. Both x and y MUST be normalized. It allocates nothing: pub and shaBuf
// live on the heap-resident stream.
func (ks *keyStream) hashPoint(x, y *secp.FieldVal, out []byte) {
	ks.pub[0] = 0x02 | byte(y.IsOddBit())
	x.PutBytesUnchecked(ks.pub[1:33])
	ks.shaBuf = sha256simd.Sum256(ks.pub[:])
	ripemd160Hash32(&ks.shaBuf, out)
}

/*
nextBatch advances the stream by len(out) keys and writes their Hash160s to out.

It returns the absolute key offset of out[0] (i.e. out[j] corresponds to private
scalar base + start + j), which lets the caller reconstruct the private key for
any match without tracking per-key scalars in the hot loop.

Math per key (P is the batch base point, Q = (j+1)*G from the table):

	λ  = (y_Q - y_P) / (x_Q - x_P)
	x3 = λ² - x_P - x_Q
	y3 = λ(x_P - x3) - y_P

The N divisions share a single inversion via Montgomery's trick.
*/
func (ks *keyStream) nextBatch(out [][20]byte) uint64 {
	n := len(out)
	start := ks.offset

	// out[0] is the current base point P (already affine and normalized).
	ks.hashPoint(&ks.px, &ks.py, out[0][:])

	// -x_P and -y_P are reused for every key in this batch.
	var negPx, negPy secp.FieldVal
	negPx.NegateVal(&ks.px, 1) // mag 2
	negPy.NegateVal(&ks.py, 1) // mag 2

	// Denominators dx[j] = x_{(j+1)G} - x_P (mag 3). When x_{(j+1)G} == x_P the
	// denominator is zero (P == ±(j+1)G); since one zero would poison the whole
	// shared inversion, substitute 1 and remember the index for an exact fixup.
	// Both operands are normalized, so Equals is an exact zero-denominator test.
	ks.degenIdx = ks.degenIdx[:0]
	for j := 0; j < n; j++ {
		if mulGx[j].Equals(&ks.px) {
			ks.dx[j].SetInt(1)
			ks.degenIdx = append(ks.degenIdx, j)
			continue
		}
		ks.dx[j].Add2(&mulGx[j], &negPx)
	}

	// Montgomery batch inversion: pre[j] = dx[0]*..*dx[j], invert the full
	// product once, then a backward pass peels off each individual 1/dx[j].
	ks.pre[0].Set(&ks.dx[0])
	for j := 1; j < n; j++ {
		ks.pre[j].Mul2(&ks.pre[j-1], &ks.dx[j])
	}
	var inv secp.FieldVal
	inv.Set(&ks.pre[n-1]).Inverse()
	for j := n - 1; j > 0; j-- {
		var invdx secp.FieldVal
		invdx.Mul2(&inv, &ks.pre[j-1]) // 1/dx[j] = inv * (dx[0]..dx[j-1])
		inv.Mul(&ks.dx[j])             // fold dx[j] back out for the next index
		ks.dx[j].Set(&invdx)           // dx[j] now holds 1/dx[j]
	}
	ks.dx[0].Set(&inv) // 1/dx[0]

	// Compute each Q = P + (j+1)*G. The last one (j == n-1) becomes the base
	// point for the next batch; the rest are hashed into out[1..n-1].
	var lam, lamSq, x3, negX3, t, num, y3 secp.FieldVal
	for j := 0; j < n; j++ {
		num.Add2(&mulGy[j], &negPy)                  // y_Q - y_P (mag 3)
		lam.Mul2(&num, &ks.dx[j])                    // λ (mag 1)
		lamSq.SquareVal(&lam)                        // λ² (mag 1)
		x3.Set(&lamSq).Add(&negPx).Add(&mulGnegX[j]) // λ² - x_P - x_Q (mag 4)
		negX3.NegateVal(&x3, 4)                      // -x3 (mag 5)
		t.Add2(&ks.px, &negX3)                       // x_P - x3 (mag 6)
		y3.Mul2(&lam, &t).Add(&negPy)                // λ(x_P - x3) - y_P (mag 3)

		x3.Normalize()
		y3.Normalize()

		if j < n-1 {
			ks.hashPoint(&x3, &y3, out[j+1][:])
		} else {
			ks.px.Set(&x3) // advance base point to P + n*G
			ks.py.Set(&y3)
		}
	}

	// Exact fixup for any zero-denominator indices (computed via direct scalar
	// multiplication). This runs essentially never for random starting points.
	for _, j := range ks.degenIdx {
		var x, y secp.FieldVal
		ks.affineAt(start+uint64(j)+1, &x, &y)
		if j < n-1 {
			ks.hashPoint(&x, &y, out[j+1][:])
		} else {
			ks.px.Set(&x)
			ks.py.Set(&y)
		}
	}

	ks.offset += uint64(n)
	return start
}

// privateKeyAt reconstructs the private key for a given absolute offset in the
// stream (base + offset, mod N). Only used on the rare match path.
func (ks *keyStream) privateKeyAt(absOffset uint64) *btcec.PrivateKey {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], absOffset)
	var add, res secp.ModNScalar
	add.SetBytes(&addBytes)
	res.Set(&ks.base).Add(&add)
	keyBytes := res.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(keyBytes[:])
	return priv
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

func formatMatchResult(match MatchResult) string {
	privKeyHex := hex.EncodeToString(match.privateKey.Serialize())
	return fmt.Sprintf("%s:%s", privKeyHex, match.address)
}

func printMatchResult(match MatchResult) {
	line := formatMatchResult(match)
	fmt.Printf("\n*** MATCH FOUND! ***\n%s\n\n", line)
}

// checkedSample is one key+address recently verified against the target set (console only).
type checkedSample struct {
	privKeyHex string
	address    string
}

// lastCheckedSample holds the latest sample from worker 0 (atomic, off hot path for other workers).
var lastCheckedSample atomic.Value

func publishCheckedSample(privateKey *btcec.PrivateKey, hash160 [20]byte) {
	lastCheckedSample.Store(&checkedSample{
		privKeyHex: hex.EncodeToString(privateKey.Serialize()),
		address:    encodeP2PKH(hash160),
	})
}

// ============================================================================
// CHECKPOINT: Resumable Progress (every-10s JSON snapshot)
// ============================================================================
//
// Each worker walks a private-key SEGMENT starting from its own random base
// scalar: base, base+1, base+2, ... So "where we stopped" is fully described,
// per segment, by the NEXT private key it would process (base + keys produced).
// The checkpoint stores that key for every segment; --resume seeds each worker
// from its saved key and generation continues exactly where it left off.
//
// Storing a single value (e.g. the console sample) is NOT enough: that sample
// comes only from worker 0, while every segment advances independently.
//
// SEGMENTS ARE DECOUPLED FROM THREADS so the thread count can change between
// runs (e.g. 4 -> 8 -> 12 -> 4) without losing or corrupting anything:
//   - threads  > saved segments: resume all saved, ADD fresh random segments.
//   - threads == saved segments: resume all (the common case).
//   - threads  < saved segments: resume the first `threads`, and PRESERVE the
//     surplus segments untouched ("frozen") so a later higher-thread run picks
//     them up exactly where they were. Nothing is dropped.

// checkpointVersion lets future format changes be detected when resuming.
const checkpointVersion = 1

// checkpointMu serializes checkpoint writes (the stats ticker and the shutdown
// handler can both write), so the temp-file + rename is never interleaved.
var checkpointMu sync.Mutex

// workerState exposes a segment's resumable position to the checkpoint writer
// without sharing the (non-thread-safe) keyStream itself. base is fixed for the
// segment's lifetime; offset is published atomically after every batch. Frozen
// segments (more saved than threads) keep offset == 0 so their saved key and
// cumulative count are rewritten unchanged every checkpoint.
type workerState struct {
	base      [32]byte // starting scalar (constant once the stream is created)
	offset    uint64   // atomic: keys produced THIS run (next key = base + offset)
	priorKeys uint64   // keys this segment processed in previous runs (for cumulative count)
}

// workerCheckpoint is the saved position of a single segment.
type workerCheckpoint struct {
	ID             int    `json:"id"`
	NextPrivateKey string `json:"next_private_key"` // 64 hex chars; where this segment resumes
	KeysProcessed  uint64 `json:"keys_processed"`   // cumulative keys processed by this segment
}

// checkpointFile is the full on-disk JSON snapshot. len(Workers) is the number
// of segments tracked, which may exceed Threads (the active worker count of the
// run that wrote the file) when a later run used fewer threads.
type checkpointFile struct {
	Version      int                `json:"version"`
	UpdatedAt    string             `json:"updated_at"`
	Threads      int                `json:"threads"`  // active workers in the writing run
	Segments     int                `json:"segments"` // total segments tracked (== len(workers))
	KeyBatchSize int                `json:"key_batch_size"`
	TotalKeys    uint64             `json:"total_keys"` // cumulative across all resumes
	Workers      []workerCheckpoint `json:"workers"`
}

// privateKeyHexFromBase returns hex(base + offset mod N): the absolute private
// key at a given offset in a worker's sequence. Same math as privateKeyAt, but
// callable from the checkpoint writer, which does not own the keyStream.
func privateKeyHexFromBase(base [32]byte, offset uint64) string {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], offset)
	var b, add, res secp.ModNScalar
	b.SetBytes(&base)
	add.SetBytes(&addBytes)
	res.Set(&b).Add(&add)
	keyBytes := res.Bytes()
	return hex.EncodeToString(keyBytes[:])
}

// parsePrivateKeyHex decodes a 32-byte hex private key from a checkpoint file.
func parsePrivateKeyHex(s string) ([32]byte, error) {
	var seed [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return seed, fmt.Errorf("invalid hex: %w", err)
	}
	if len(raw) != 32 {
		return seed, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(seed[:], raw)
	return seed, nil
}

// writeCheckpoint atomically saves the current position of every segment. It
// writes to a temp file then renames, so a crash mid-write never corrupts the
// existing checkpoint. activeThreads is the number of segments being advanced by
// workers (the rest are frozen); baseTotal is the cumulative key count carried
// over from a resumed run (0 for a fresh run).
func writeCheckpoint(path string, states []*workerState, counter *uint64, baseTotal uint64, activeThreads int) error {
	cp := checkpointFile{
		Version:      checkpointVersion,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Threads:      activeThreads,
		Segments:     len(states),
		KeyBatchSize: keyBatchSize,
		TotalKeys:    baseTotal + atomic.LoadUint64(counter),
		Workers:      make([]workerCheckpoint, len(states)),
	}
	for i, ws := range states {
		offset := atomic.LoadUint64(&ws.offset)
		cp.Workers[i] = workerCheckpoint{
			ID:             i,
			NextPrivateKey: privateKeyHexFromBase(ws.base, offset),
			KeysProcessed:  ws.priorKeys + offset,
		}
	}

	data, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return err
	}

	checkpointMu.Lock()
	defer checkpointMu.Unlock()

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readCheckpoint loads and validates a checkpoint file for --resume.
func readCheckpoint(path string) (*checkpointFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cp checkpointFile
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("invalid checkpoint JSON: %w", err)
	}
	if cp.Version != checkpointVersion {
		return nil, fmt.Errorf("unsupported checkpoint version %d (expected %d)", cp.Version, checkpointVersion)
	}
	if len(cp.Workers) == 0 {
		return nil, fmt.Errorf("checkpoint has no worker positions")
	}
	return &cp, nil
}

// buildStreams sets up the segments for a run, tolerant of a changed thread
// count between runs. It returns:
//   - streams: one keyStream per ACTIVE worker (len == numThreads); streams[i]
//     pairs with states[i].
//   - states: one workerState per SEGMENT (len == max(numThreads, savedSegments)).
//     Indices [0, numThreads) are active (advanced by workers); indices
//     [numThreads, len) are frozen (preserved unchanged, no worker).
//
// Mapping rules (saved = resume.Workers):
//   - i < len(saved): resume segment i from its saved key (active if i < numThreads,
//     otherwise frozen so it is not lost).
//   - i >= len(saved): a brand-new random segment (only when numThreads > len(saved),
//     hence always active).
func buildStreams(numThreads int, resume *checkpointFile) ([]*keyStream, []*workerState, error) {
	var saved []workerCheckpoint
	if resume != nil {
		saved = resume.Workers
	}

	totalSegments := numThreads
	if len(saved) > totalSegments {
		totalSegments = len(saved)
	}

	streams := make([]*keyStream, numThreads)
	states := make([]*workerState, totalSegments)

	for i := 0; i < totalSegments; i++ {
		ws := &workerState{}
		if i < len(saved) {
			// Resume an existing segment exactly where it stopped.
			seed, err := parsePrivateKeyHex(saved[i].NextPrivateKey)
			if err != nil {
				return nil, nil, fmt.Errorf("segment %d: %w", i, err)
			}
			ws.base = seed
			ws.priorKeys = saved[i].KeysProcessed
			if i < numThreads {
				streams[i] = newKeyStreamFromSeed(seed) // active
			}
			// else: frozen — no stream, offset stays 0, key rewritten unchanged.
		} else {
			// New random segment (only reached when numThreads > len(saved)).
			s, err := newKeyStream()
			if err != nil {
				return nil, nil, err
			}
			ws.base = s.base.Bytes()
			streams[i] = s
		}
		states[i] = ws
	}
	return streams, states, nil
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
 1. Seed a per-worker keyStream from crypto/rand (one scalar multiplication)
 2. Pull a batch of keyBatchSize consecutive Hash160s via the EC walk
 3. Check each Hash160 against the target database (O(1) hash map lookup)
 4. On a match, reconstruct the private key and send it to matchWriter
 5. Advance the global counter by the batch size and repeat indefinitely

Performance Optimizations:
  - Batched affine EC walk: avoids a per-key scalar multiplication entirely
  - Batched (Montgomery) inversion: one field inversion per keyBatchSize keys
  - Allocation-free hot loop: all scratch buffers are owned by the keyStream
  - One atomic counter update per batch (keyBatchSize keys) minimizes contention
  - Non-blocking match sending: channel has buffer to prevent blocking

Concurrency Model:
  - Multiple workers run in parallel (typically numCPUs or numCPUs*2)
  - Each worker operates independently with its own RNG state
  - Shared state: btcAddresses (read-only), counter (atomic), matchChan (buffered)

Statistics:
  - One atomic counter update per batch (keyBatchSize keys) instead of per key,
    cutting counter contention by a factor of keyBatchSize
  - Typical throughput: ~1.5-1.7M keys/sec per fast core (Apple M3)
*/
func worker(id int, wg *sync.WaitGroup, targets hash160Set, matchChan chan<- MatchResult, counter *uint64, stream *keyStream, state *workerState, stop <-chan struct{}) {
	defer wg.Done()

	hashes := make([][20]byte, keyBatchSize)
	// Worker 0 publishes a console sample roughly every ~100k keys.
	// (+1 guarantees a non-zero interval even if keyBatchSize >= 100000.)
	const sampleEvery = 1 + 100000/keyBatchSize // batches between samples
	batchNum := 0

	for {
		// Cooperative shutdown: checked once per batch (every keyBatchSize keys),
		// so it costs nothing on the hot path. Lets main write a final checkpoint.
		select {
		case <-stop:
			return
		default:
		}

		start := stream.nextBatch(hashes)

		// One atomic per batch (every keyBatchSize keys) keeps contention low.
		atomic.AddUint64(counter, uint64(len(hashes)))

		// Publish the resumable position. stream.offset now counts every key
		// produced so far, so base + offset is the next unprocessed key. Stored
		// after nextBatch, it can only lag the truth, never lead it — a resume
		// re-does at most one batch and never skips keys.
		atomic.StoreUint64(&state.offset, stream.offset)

		if id == 0 && (batchNum == 0 || batchNum%sampleEvery == 0) {
			publishCheckedSample(stream.privateKeyAt(start), hashes[0])
		}
		batchNum++

		for j := range hashes {
			if _, exists := targets[hashes[j]]; exists {
				privateKey := stream.privateKeyAt(start + uint64(j))
				publicAddress := encodeP2PKH(hashes[j])
				match := MatchResult{privateKey: privateKey, address: publicAddress}
				printMatchResult(match) // Print before enqueueing so the key is visible even if file I/O fails.
				matchChan <- match
			}
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
		matchLine := formatMatchResult(match)

		// Write to file in format: <privkey_hex>:<address>
		if _, err := writer.WriteString(matchLine + "\n"); err != nil {
			log.Printf("Failed to write match to file: %s", err)
		}

		// Flush immediately to ensure data is saved (important for rare matches)
		if err := writer.Flush(); err != nil {
			log.Printf("Failed to flush match to file: %s", err)
		}

		// Also print to console for immediate visibility
		fmt.Printf("SAVED TO FILE: %s\n\n", matchLine)
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
	- One sample privkey:address from recent checks (worker 0, ~every 100k keys on that worker)

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
  - Apple M3 (2024): ~1.5-1.7M keys/sec per fast core with the batched affine walk
  - Total throughput: rate * num_workers
  - Example: 8 cores ≈ 8-9M keys/sec total (P/E core mix)

Thread Safety:
  - Uses atomic.LoadUint64() for thread-safe counter reading
  - No locks required (read-only access to shared counter)
*/
func statsReporter(counter *uint64, startTime time.Time, states []*workerState, checkpointPath string, baseTotal uint64, activeThreads int) {
	// Create ticker that fires every 10 seconds (one sample line per interval)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop() // Clean up ticker when function returns

	// Track previous values for calculating instantaneous rate
	lastTotal := uint64(0)
	lastTime := startTime

	// Wait for ticker events (every 10 seconds)
	for range ticker.C {
		// Read current counter value (thread-safe atomic operation)
		total := atomic.LoadUint64(counter) // keys generated this run
		now := time.Now()

		// Calculate overall statistics (since program start)
		elapsed := time.Since(startTime).Seconds()
		overallRate := float64(total) / elapsed

		// Calculate instantaneous rate (last 10 seconds only)
		intervalKeys := total - lastTotal           // Keys generated in last interval
		intervalTime := now.Sub(lastTime).Seconds() // Time elapsed in last interval
		instantRate := float64(intervalKeys) / intervalTime

		// Display statistics. "Total" is cumulative across resumes; the rates are
		// computed from this run only so a resume doesn't distort throughput.
		fmt.Printf("[Stats] Total: %d | Overall: %.0f keys/sec | Current: %.0f keys/sec | Runtime: %.0fs\n",
			baseTotal+total, overallRate, instantRate, elapsed)
		if v := lastCheckedSample.Load(); v != nil {
			s := v.(*checkedSample)
			fmt.Printf("[Sample] %s:%s\n", s.privKeyHex, s.address)
		}

		// Persist resumable progress on the same 10s cadence as the stats line.
		if checkpointPath != "" {
			if err := writeCheckpoint(checkpointPath, states, counter, baseTotal, activeThreads); err != nil {
				log.Printf("Failed to write checkpoint: %s", err)
			}
		}

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
 1. Parse command-line flags and positional arguments
 2. Configure runtime (GOMAXPROCS)
 3. Load target address database into memory
 4. Build per-worker key streams (fresh random, or resumed from a checkpoint)
 5. Initialize shared data structures (counter, channels, waitgroups)
 6. Start matchWriter goroutine (file I/O)
 7. Start statsReporter goroutine (monitoring + 10s checkpoint writes)
 8. Start worker pool goroutines (brute force)
 9. Wait for completion (runs until interrupted; SIGINT writes a final checkpoint)

Positional Arguments:
 1. threads: Number of worker goroutines (typically numCPUs or numCPUs*2)
 2. output-file.txt: File to save matches (created if doesn't exist, appended if exists)
 3. btc-address-file.txt: Database of target addresses (one per line)

Flags (must come before the positional arguments):

	--checkpoint=path  JSON file where progress is saved every 10s (default: checkpoint.json)
	--resume           Continue from the checkpoint instead of fresh random keys

Usage Examples:

	./bitcoin-wallet-bruteforce-offline 8 matches.txt addresses.txt
	./bitcoin-wallet-bruteforce-offline --resume 8 matches.txt addresses.txt
	./bitcoin-wallet-bruteforce-offline --checkpoint=run1.json 16 output.txt attack-addresses-p2pkh.txt

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

	checkpointPath := flag.String("checkpoint", "checkpoint.json", "JSON file where progress is saved every 10s")
	resume := flag.Bool("resume", false, "continue from the checkpoint file instead of fresh random keys")
	flag.Usage = func() {
		fmt.Println("Usage: ./bitcoin-wallet-bruteforce-offline [--checkpoint=path] [--resume] <threads> <output-file.txt> <btc-address-file.txt>")
		fmt.Println()
		fmt.Println("Positional arguments:")
		fmt.Println("  threads              - Number of worker threads (recommend: num CPU cores)")
		fmt.Println("  output-file.txt      - Output file for saving matches")
		fmt.Println("  btc-address-file.txt - Input file with target Bitcoin addresses")
		fmt.Println()
		fmt.Println("Flags (must come BEFORE the positional arguments):")
		fmt.Println("  --checkpoint=path    - JSON checkpoint file (default: checkpoint.json)")
		fmt.Println("  --resume             - Continue from the checkpoint instead of starting fresh")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline 8 matches.txt attack-addresses-p2pkh.txt")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline --resume 8 matches.txt attack-addresses-p2pkh.txt")
	}
	flag.Parse()

	// Positional arguments follow the flags.
	args := flag.Args()
	if len(args) != 3 {
		flag.Usage()
		os.Exit(1)
	}

	// Parse and validate the worker thread count.
	numThreads, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("Invalid number of threads: %s", err)
	}
	if numThreads < 1 {
		log.Fatalf("Number of threads must be at least 1")
	}

	outputFile := args[1]       // Where to save matches
	btcAddressesFile := args[2] // Database of target addresses

	// ========================================================================
	// RUNTIME CONFIGURATION
	// ========================================================================

	// Match scheduler threads to worker count (user may set threads > NumCPU for experiments)
	runtime.GOMAXPROCS(numThreads)

	// Optional: BTC_BRUTE_GC=400 lowers GC frequency on long runs (can hurt short benchmarks)
	if gc := os.Getenv("BTC_BRUTE_GC"); gc != "" {
		if n, err := strconv.Atoi(gc); err == nil && n > 0 {
			debug.SetGCPercent(n)
		}
	}

	// ========================================================================
	// BANNER AND SYSTEM INFORMATION
	// ========================================================================

	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Bitcoin Wallet Bruteforce - Optimized Edition            ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("CPU Cores: %d | Worker Threads: %d\n", runtime.NumCPU(), numThreads)
	fmt.Printf("Key Gen: Batched affine EC walk + Montgomery inversion (%d/batch)\n", keyBatchSize)
	fmt.Printf("SHA256: Hardware Accelerated (SIMD)\n")
	fmt.Printf("Public Key: Compressed (33 bytes)\n")
	fmt.Printf("Lookup: Hash160 (Base58 only on match)\n")
	fmt.Printf("Address Type: Legacy P2PKH (starts with '1')\n\n")

	// ========================================================================
	// ADDRESS DATABASE LOADING
	// ========================================================================

	fmt.Printf("Loading addresses from %s...\n", btcAddressesFile)
	targets, err := readTargetHashes(btcAddressesFile)
	if err != nil {
		log.Fatalf("Failed to read BTC addresses: %s", err)
	}
	fmt.Printf("✓ Loaded %d target hashes to check against\n\n", len(targets))

	// ========================================================================
	// KEY STREAM SETUP (fresh or resumed)
	// ========================================================================

	var resumeData *checkpointFile
	if *resume {
		resumeData, err = readCheckpoint(*checkpointPath)
		if err != nil {
			log.Fatalf("Failed to load checkpoint %q for --resume: %s", *checkpointPath, err)
		}
		savedN := len(resumeData.Workers)
		fmt.Printf("Resuming from %s (%d saved segment(s), %d total keys done)\n",
			*checkpointPath, savedN, resumeData.TotalKeys)
		switch {
		case numThreads > savedN:
			fmt.Printf("  Threads (%d) > saved segments (%d): resuming all %d, adding %d new random segment(s).\n",
				numThreads, savedN, savedN, numThreads-savedN)
		case numThreads < savedN:
			fmt.Printf("  Threads (%d) < saved segments (%d): resuming the first %d; preserving %d frozen segment(s)\n",
				numThreads, savedN, numThreads, savedN-numThreads)
			fmt.Printf("  (they keep their saved position and resume when you run with >= %d threads).\n", savedN)
		}
		fmt.Println()
	}

	streams, states, err := buildStreams(numThreads, resumeData)
	if err != nil {
		log.Fatalf("Failed to initialize key streams: %s", err)
	}
	frozen := len(states) - numThreads
	if frozen < 0 {
		frozen = 0
	}

	// Cumulative key count carried over from a resumed run (0 for fresh runs).
	// The live counter always starts at 0 so this run's rates are accurate.
	var baseTotal uint64
	if resumeData != nil {
		baseTotal = resumeData.TotalKeys
	}

	// Write an initial checkpoint so the file exists and reflects the starting
	// positions immediately, even before the first 10s tick.
	if err := writeCheckpoint(*checkpointPath, states, new(uint64), baseTotal, numThreads); err != nil {
		log.Printf("Failed to write initial checkpoint: %s", err)
	} else {
		fmt.Printf("Checkpoint: %s | segments: %d (%d active, %d frozen) | saved every 10s\n\n",
			*checkpointPath, len(states), numThreads, frozen)
	}

	// ========================================================================
	// SHARED STATE INITIALIZATION
	// ========================================================================

	// Atomic counter for keys generated THIS run (shared across all workers).
	var counter uint64

	// Buffered channel for sending matches from workers to file writer
	// Buffer size: 100 (prevents blocking if matches found in bursts)
	matchChan := make(chan MatchResult, 100)

	// WaitGroups for coordinating goroutine shutdown
	var workerWg sync.WaitGroup // Tracks worker goroutines
	var writerWg sync.WaitGroup // Tracks writer goroutine

	// stop is closed on SIGINT/SIGTERM so workers exit at a batch boundary,
	// letting main write one final, fully up-to-date checkpoint.
	stop := make(chan struct{})

	// ========================================================================
	// GRACEFUL SHUTDOWN (SIGINT / SIGTERM)
	// ========================================================================

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\nInterrupt received — stopping workers and saving final checkpoint...\n")
		close(stop)
		// A second interrupt forces immediate exit (skips the graceful flush).
		<-sigChan
		fmt.Printf("\nSecond interrupt — exiting now.\n")
		os.Exit(1)
	}()

	// ========================================================================
	// GOROUTINE STARTUP
	// ========================================================================

	// Start match writer goroutine (handles file I/O asynchronously)
	writerWg.Add(1)
	go matchWriter(matchChan, outputFile, &writerWg)

	// Start stats reporter goroutine (metrics + 10s checkpoint writes)
	startTime := time.Now()
	go statsReporter(&counter, startTime, states, *checkpointPath, baseTotal, numThreads)

	// Start worker pool (brute force address generation)
	fmt.Printf("Starting brute force...\n")
	fmt.Printf("════════════════════════════════════════════════════════════\n\n")
	for i := 0; i < numThreads; i++ {
		workerWg.Add(1)
		go worker(i, &workerWg, targets, matchChan, &counter, streams[i], states[i], stop)
	}

	// ========================================================================
	// MAIN LOOP (BLOCKING)
	// ========================================================================

	// Runs until interrupted: SIGINT/SIGTERM closes stop, workers exit at the
	// next batch boundary, and the WaitGroup unblocks.
	workerWg.Wait()

	// Close match channel to signal writer to finish, then wait for it to drain.
	close(matchChan)
	writerWg.Wait()

	// Final checkpoint capturing the exact stopping positions (graceful shutdown).
	if err := writeCheckpoint(*checkpointPath, states, &counter, baseTotal, numThreads); err != nil {
		log.Printf("Failed to write final checkpoint: %s", err)
	} else {
		fmt.Printf("Final checkpoint saved to %s\n", *checkpointPath)
	}
}
