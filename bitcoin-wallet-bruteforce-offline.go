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
	- GLV endomorphism + point negation: every affine point (x, y) yields SIX
	  valid keys — the three endomorphism x-values (x, beta*x, beta^2*x), each in
	  both y-parities — for 2 field multiplies total (negation is only the 02/03
	  prefix flip, since y is never serialized), so the field inversion and EC
	  addition amortize over 6 keys instead of 1
	- Batched (Montgomery) field inversion: a single inversion per batch
	  amortizes the only division in the affine addition formula
	- Fused multi-buffer HASH160 over the whole batch (github.com/Asylian21/sha256mb +
	  github.com/Asylian21/ripemd160-asm): multi-buffer SHA-256 (arm64 hardware-SHA
	  interleave, scalar fallback) feeds multi-buffer RIPEMD-160 (4-lane NEON on arm64),
	  the two hashes being the largest CPU cost after the EC field math, so both are
	  vectorized across lanes in a single pass per batch
	- Zero-copy Hash160: the HASH160 pass writes its 20-byte digests straight into the
	  caller's [][20]byte result slice (hash160mb.Size == 20), so the batch needs
	  no intermediate output buffer and no per-key scatter copy
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
	"crypto/rand"     // CSPRNG for the educational generateKeyAndHash160 primitive
	"encoding/binary" // Encode the per-worker key offset into a scalar
	"encoding/hex"    // Hex encoding for private key output
	"encoding/json"   // Checkpoint serialization (resume support)
	"flag"            // CLI flag parsing (--checkpoint, --resume)
	"fmt"             // Formatted I/O
	"log"             // Logging errors
	"os"              // OS operations (file handling, arguments)
	"os/signal"       // Graceful shutdown: final checkpoint on SIGINT/SIGTERM
	"runtime"         // Runtime information (CPU cores)
	"runtime/debug"   // GC tuning for sustained throughput
	"strconv"         // String to integer conversion
	"sync"            // Synchronization primitives (WaitGroup, Pool)
	"sync/atomic"     // Atomic operations for thread-safe counters
	"syscall"         // Signal constants (SIGINT/SIGTERM) for graceful shutdown
	"time"            // Time operations for statistics
	"unsafe"          // Reinterpret out's [][20]byte backing as []byte for zero-copy Hash160

	ripemd160mb "github.com/Asylian21/ripemd160-asm"    // Multi-buffer SIMD RIPEMD160 (NEON 4-lane on arm64)
	field "github.com/Asylian21/secp256k1-field"        // Fast secp256k1 Fp arithmetic (5x52 limbs, arm64/amd64 asm)
	sha256mb "github.com/Asylian21/sha256mb"            // Multi-buffer SHA-256 (arm64 HW-SHA interleave, scalar fallback)
	hash160mb "github.com/Asylian21/sha256mb/hash160mb" // Fused multi-buffer HASH160 = RIPEMD160(SHA256(pubkey))
	"github.com/btcsuite/btcd/btcec/v2"                 // Bitcoin SECP256k1 elliptic curve operations
	"github.com/btcsuite/btcutil"                       // Bitcoin utility functions (Hash160, reference path)
	"github.com/btcsuite/btcutil/base58"                // Base58 encoding for addresses
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"    // Low-level EC point arithmetic (incremental walk)
	sha256simd "github.com/minio/sha256-simd"           // SIMD-accelerated SHA256 (2-3x faster)

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal" // Apple Metal GPU pipeline: GLV+Hash160+Bloom (no-op stub off darwin/cgo)
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

// keyBatchSize is the number of LINEAR walk steps amortized by a single field
// inversion; each step yields endoFactor (6) keys. It is also the size of the
// precomputed multiples-of-G table. Larger batches spread the one inversion over
// more steps, but the per-worker scratch (notably pubBuf, which is
// endoFactor*keyBatchSize*pubStride bytes) and the shared table eventually spill
// out of cache. With endoFactor=6 the per-key cost is dominated by hashing rather than
// the inversion, so single-thread cost is essentially flat across 512..2048
// (~140 ns/key on Apple M3). 1024 is chosen because its smaller working set gives
// the best sustained multi-worker throughput (latest measured 37,038,393 keys/sec
// on an 8-core M3) while keeping the inversion well amortized (256 already regresses).
const keyBatchSize = 1024

// Precomputed affine multiples of the base point: mulGx[j]/mulGy[j] = ((j+1)*G).
// mulGnegX[j] = -mulGx[j] (normalized) so the hot loop can compute x3 = λ²-x_P-x_Q
// with plain additions. The table is read-only and shared across all workers.
var (
	mulGx    [keyBatchSize]field.Val
	mulGy    [keyBatchSize]field.Val
	mulGnegX [keyBatchSize]field.Val
)

// Coarse table for the on-GPU walk (Phase 3): coarseMGx[j]/coarseMGy[j] =
// ((j+1)*ECWalkBatch)*G, with coarseMGnegX[j] = -coarseMGx[j]. The GPU walk has
// each thread own ECWalkBatch consecutive scalars, so the host only needs to seed
// ONE affine start point per thread (the coarse walk steps by ECWalkBatch*G);
// the GPU fine-walks the ECWalkBatch points itself. fillStartPoints uses this
// table to produce a chunk's thread-start points with a single Montgomery
// inversion, the same trick as the per-key CPU walk but 1/ECWalkBatch the work.
var (
	coarseMGx    [keyBatchSize]field.Val
	coarseMGy    [keyBatchSize]field.Val
	coarseMGnegX [keyBatchSize]field.Val
)

// gpuWalkThreadsPerChunk is the number of GPU threads (thread-start points) one
// chunk maps to: each thread covers ECWalkBatch linear keys, so a chunk's
// chunkSteps keys need chunkSteps/ECWalkBatch threads. With the current
// constants this equals keyBatchSize, so fillStartPoints reuses the keyStream's
// keyBatchSize-sized Montgomery scratch. An init sanity check pins the relation.
const gpuWalkThreadsPerChunk = chunkSteps / gpumetal.ECWalkBatch

// gpuStartBytesPerChunk is the byte size of one chunk's thread-start points: each
// point is an affine (x, y) as 16 little-endian 32-bit limbs (64 bytes), the
// layout ec_walk_glv_kernel reads from buffer(0).
const gpuStartBytesPerChunk = gpuWalkThreadsPerChunk * 16 * 4

// ============================================================================
// secp256k1 GLV endomorphism
// ============================================================================
//
// secp256k1 admits an efficiently computable endomorphism: for any curve point
// P = (x, y), the point (beta*x mod p, y) is also on the curve (because
// (beta*x)^3 + 7 = beta^3*x^3 + 7 = x^3 + 7 = y^2 when beta^3 == 1) and equals
// lambda*P, where beta is a nontrivial cube root of unity in the base field Fp
// and lambda is the matching cube root of unity in the scalar field Fn.
//
// So for the cost of ONE field multiply (beta*x) the affine walk yields a second
// valid key that shares the same y — hence the same 02/03 compressed prefix —
// whose private scalar is lambda*k mod n. Applied twice, beta^2*x gives a THIRD
// x-value: (beta^2*x, y) == lambda^2*P, scalar lambda^2*k mod n. Each of these
// three points can also be negated (-P = (x, -y)); because y is never serialized
// (only its parity picks the prefix), negation is a free 02/03 flip with scalar
// n-k. One computed affine point therefore yields SIX valid keys for just 2 field
// multiplies (beta*x, beta^2*x), amortizing the EC addition, slope, y3,
// normalization, and the shared Montgomery inversion across 6 candidates instead
// of 1. The (beta, lambda) pair below is libsecp256k1's, for which
// (beta*x, y) == lambda*P (verified by verifyHashPipeline and tests).
const (
	betaHex   = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"
	lambdaHex = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"
)

// endoFactor is the number of keys produced per linear walk step. Each computed
// affine point (x, y) yields 6 valid keys: the three GLV endomorphism x-values
// (x, beta*x, beta^2*x), each taken in both point-negation parities (y and -y,
// i.e. the 02/03 compressed-prefix flip). Each batch therefore checks
// endoFactor*keyBatchSize keys against the target set, amortizing the expensive
// EC addition + Montgomery inversion over 6 keys instead of 2. The marginal cost
// of the extra keys is only hashing (plus 2 field muls per step) — no further
// scalar multiplication or inversion.
const endoFactor = 6

var (
	betaVal       field.Val       // beta: cube root of unity in Fp (normalized, magnitude 1)
	lambdaScalar  secp.ModNScalar // lambda: matching cube root of unity in Fn
	lambda2Scalar secp.ModNScalar // lambda^2 mod n: scalar for the beta^2*x endomorphism image
)

// mustDecodeScalar32 decodes a 64-char hex string into a 32-byte big-endian
// array. It panics on malformed input; callers pass fixed compile-time constants.
func mustDecodeScalar32(s string) [32]byte {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		panic(fmt.Sprintf("invalid 32-byte hex constant %q", s))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

// fieldFromDcrd converts a dcrd field element into the fast field.Val used by
// the hot loop, via the canonical 32-byte big-endian encoding. The source is
// normalized defensively so any magnitude is accepted; the result is the unique
// residue in [0, p) at magnitude 1. This bridge runs only where dcrd produces a
// point (init, setBase, and the rare degenerate fixup), never per generated key.
func fieldFromDcrd(src *secp.FieldVal) field.Val {
	var t secp.FieldVal
	t.Set(src)
	t.Normalize()
	b := t.Bytes()
	var dst field.Val
	dst.SetBytes(b)
	return dst
}

func init() {
	// Parse the endomorphism constants once. beta < p and lambda < n, so the
	// SetBytes overflow flags are expected to be zero and are ignored.
	bb := mustDecodeScalar32(betaHex)
	betaVal.SetBytes(&bb)
	betaVal.Normalize()
	lb := mustDecodeScalar32(lambdaHex)
	lambdaScalar.SetBytes(&lb)
	// lambda^2 mod n pairs with beta^2*x: (beta^2*x, y) == lambda^2 * P. Derived
	// from lambda (no new hex constant needed); lambda^3 == 1 so this is also
	// lambda's modular inverse, but we use it purely as the second image scalar.
	lambda2Scalar.Set(&lambdaScalar)
	lambda2Scalar.Square()

	var s secp.ModNScalar
	var p secp.JacobianPoint
	for j := 0; j < keyBatchSize; j++ {
		s.SetInt(uint32(j + 1))
		secp.ScalarBaseMultNonConst(&s, &p)
		p.ToAffine() // Z=1, X/Y normalized to magnitude 1
		mulGx[j] = fieldFromDcrd(&p.X)
		mulGy[j] = fieldFromDcrd(&p.Y)
		mulGnegX[j].NegateVal(&mulGx[j], 1)
		mulGnegX[j].Normalize()
	}

	// Coarse table: ((j+1)*ECWalkBatch)*G for the GPU walk's thread-start fill.
	// The relation chunkSteps == gpuWalkThreadsPerChunk*ECWalkBatch and
	// gpuWalkThreadsPerChunk <= keyBatchSize must hold so a chunk's start points
	// line up exactly with the kernel's thread->scalar mapping and fit the
	// keyBatchSize Montgomery scratch; pin it here rather than fail subtly later.
	if chunkSteps%gpumetal.ECWalkBatch != 0 || gpuWalkThreadsPerChunk > keyBatchSize {
		panic(fmt.Sprintf("GPU walk config invalid: chunkSteps=%d ECWalkBatch=%d threadsPerChunk=%d keyBatchSize=%d",
			chunkSteps, gpumetal.ECWalkBatch, gpuWalkThreadsPerChunk, keyBatchSize))
	}
	for j := 0; j < keyBatchSize; j++ {
		s.SetInt(uint32((j + 1) * gpumetal.ECWalkBatch))
		secp.ScalarBaseMultNonConst(&s, &p)
		p.ToAffine()
		coarseMGx[j] = fieldFromDcrd(&p.X)
		coarseMGy[j] = fieldFromDcrd(&p.Y)
		coarseMGnegX[j].NegateVal(&coarseMGx[j], 1)
		coarseMGnegX[j].Normalize()
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
// pubStride is the per-pubkey slot width in keyStream.pubBuf. A compressed
// pubkey is 33 bytes; the slot is padded to 64 so each message sits wholly
// within one 64-byte cache line. The multi-buffer HASH160 kernels load 16+16
// bytes plus a single trailing byte per message, and a cache-line-aligned slot
// avoids the line-split penalty those loads would otherwise pay at a packed
// 33-byte stride (measured ~5% per-key). Bytes 33..63 of each slot are stale
// and never read — the kernels use a fixed 33-byte single-block SHA-256 padding.
const pubStride = 64

type keyStream struct {
	base     secp.ModNScalar // starting private scalar k0
	px, py   field.Val       // running base point P = (base+offset)*G, affine (mag 1)
	offset   uint64          // number of keys produced so far (base == offset 0)
	dx       []field.Val     // scratch: denominators (x_iG - x_P) then their inverses
	pre      []field.Val     // scratch: Montgomery prefix products
	degenIdx []int           // batch indices where P == ±iG (zero denominator)
	pubBuf   []byte          // batch scratch: endoFactor*keyBatchSize compressed pubkeys at pubStride, fed to multi-buffer HASH160
}

// setBase derives the affine starting point P = base*G from a 32-byte seed,
// reducing the seed mod N, and resets the walk offset to 0. It is used both to
// construct a stream and to REBASE an existing stream to a new chunk start, so
// the worker can reuse one stream's scratch buffers across many chunks.
func (ks *keyStream) setBase(seed [32]byte) {
	ks.base.SetBytes(&seed)
	ks.offset = 0 // fresh walk from this base (rebasing for a new chunk)
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&ks.base, &p)
	p.ToAffine()
	ks.px = fieldFromDcrd(&p.X)
	ks.py = fieldFromDcrd(&p.Y)
}

// newKeyStreamFromSeed builds a key stream that starts at a known scalar instead
// of a random one. It is used by --resume: the saved "next private key" becomes
// the new base, so generation continues exactly where the previous run stopped.
func newKeyStreamFromSeed(seed [32]byte) *keyStream {
	ks := &keyStream{
		dx:       make([]field.Val, keyBatchSize),
		pre:      make([]field.Val, keyBatchSize),
		degenIdx: make([]int, 0, 4),
		pubBuf:   make([]byte, endoFactor*keyBatchSize*pubStride),
	}
	ks.setBase(seed)
	return ks
}

// affineAt computes the affine point (base + absOffset)*G into (x, y). Used only
// on the rare degenerate path where the fast batched addition divides by zero.
func (ks *keyStream) affineAt(absOffset uint64, x, y *field.Val) {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], absOffset)
	var add, res secp.ModNScalar
	add.SetBytes(&addBytes)
	res.Set(&ks.base).Add(&add)
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&res, &p)
	p.ToAffine()
	*x = fieldFromDcrd(&p.X)
	*y = fieldFromDcrd(&p.Y)
}

// writeSextet serializes the 6 compressed public keys for the GLV+negation
// variants of the affine point (x, y) into the batch pubkey buffer. For step p
// of m linear walk steps, variant v lands in slot v*m+p (pubBuf[(v*m+p)*pubStride:]):
//
//	v0 (x, +y)         v1 (x, -y)
//	v2 (beta*x, +y)    v3 (beta*x, -y)
//	v4 (beta^2*x, +y)  v5 (beta^2*x, -y)
//
// The three x-values are the GLV endomorphism images (beta^2*x = beta*(beta*x)):
// (x, y) = k*G, (beta*x, y) = lambda*P, (beta^2*x, y) = lambda^2*P. The negation
// variants (-y) are the point negations -P, whose private scalar is n-k; because
// y is never serialized (only its parity selects the 02/03 prefix), negation is
// just the prefix flip pfx^1 and costs zero field operations. The marginal cost
// over a single key is therefore 2 field muls (beta*x, beta^2*x) plus the byte
// serialization; BOTH hashes of Hash160 then run later in one fused multi-buffer
// pass over the whole batch (see nextBatch), which is where the SIMD speedup
// comes from.
//
// It allocates nothing: x is serialized once into a stack scratch and copied
// into both parity slots (which share the same x, differing only in prefix).
// Written as straight-line code (no closure) to guarantee zero heap allocations
// and full inlining of the per-variant work. Only bytes [0,33) of each slot are
// written; the slot padding up to pubStride is left untouched and never read by
// the HASH160 kernel.
//
// Preconditions: x and y MUST be normalized — PutBytesUnchecked needs canonical
// limbs, and IsOddBit needs the canonical low bit for the prefix. beta*x and
// beta^2*x are normalized here before serialization.
func (ks *keyStream) writeSextet(x, y *field.Val, p, m int) {
	pfx := byte(0x02) | byte(y.IsOddBit())
	flip := pfx ^ 0x01
	var xb [32]byte

	// v0/v1: identity x in both parities (x, +/-y).
	x.PutBytesUnchecked(xb[:])
	o := (0*m + p) * pubStride
	ks.pubBuf[o] = pfx
	copy(ks.pubBuf[o+1:o+33], xb[:])
	o = (1*m + p) * pubStride
	ks.pubBuf[o] = flip
	copy(ks.pubBuf[o+1:o+33], xb[:])

	// v2/v3: first endomorphism image (beta*x, +/-y). Same y, so reuse pfx/flip.
	var bx field.Val
	bx.Mul2(&betaVal, x)
	bx.Normalize()
	bx.PutBytesUnchecked(xb[:])
	o = (2*m + p) * pubStride
	ks.pubBuf[o] = pfx
	copy(ks.pubBuf[o+1:o+33], xb[:])
	o = (3*m + p) * pubStride
	ks.pubBuf[o] = flip
	copy(ks.pubBuf[o+1:o+33], xb[:])

	// v4/v5: second endomorphism image (beta^2*x, +/-y) = beta*(beta*x).
	var b2x field.Val
	b2x.Mul2(&betaVal, &bx)
	b2x.Normalize()
	b2x.PutBytesUnchecked(xb[:])
	o = (4*m + p) * pubStride
	ks.pubBuf[o] = pfx
	copy(ks.pubBuf[o+1:o+33], xb[:])
	o = (5*m + p) * pubStride
	ks.pubBuf[o] = flip
	copy(ks.pubBuf[o+1:o+33], xb[:])
}

// writeBasePubkey serializes ONLY the base point's compressed pubkey (variant 0:
// (x, +y)) into slot p of the batch buffer — the GPU GLV path's per-step output.
// The five other GLV+negation variants are derived on-device by glv_filter_kernel
// (beta*x, beta^2*x, and the two parity/negation prefixes), so the host neither
// computes the two endomorphism field muls nor serializes 6x the bytes. The slot
// index is just p (one pubkey per step), and the candidate id the kernel emits,
// v*m+p, still maps back through privateKeyForVariantFromBase exactly as the old
// full v*m+p slot layout did.
//
// Precondition: x and y MUST be normalized (PutBytesUnchecked needs canonical
// limbs; IsOddBit needs the canonical low bit for the prefix).
func (ks *keyStream) writeBasePubkey(x, y *field.Val, p int) {
	pfx := byte(0x02) | byte(y.IsOddBit())
	var xb [32]byte
	x.PutBytesUnchecked(xb[:])
	o := p * pubStride
	ks.pubBuf[o] = pfx
	copy(ks.pubBuf[o+1:o+33], xb[:])
}

/*
fillPubkeysSteps advances the stream by m linear walk steps and serializes the
endoFactor*m compressed public keys (all GLV + negation variants) into ks.pubBuf
at pubStride. It performs NO hashing — that is the caller's job (the CPU path
runs a fused multi-buffer HASH160; the GPU path dispatches a Metal kernel over
the same bytes). The pubkey destination is ks.pubBuf, which the GPU producer
repoints at a shared (unified-memory) Metal buffer for zero-copy fills, while the
CPU path leaves it as the stream's own scratch buffer.

It returns the absolute LINEAR key offset of step 0. Slot v*m+i holds the key
whose linear scalar is k = base + start + i and whose variant scalar follows
privateKeyForVariant (v0:k, v1:n-k, v2:λk, v3:n-λk, v4:λ²k, v5:n-λ²k mod N). This
lets the caller reconstruct the private key for any match without tracking
per-key scalars in the hot loop.

Math per linear step (P is the batch base point, Q = (j+1)*G from the table):

	λ  = (y_Q - y_P) / (x_Q - x_P)
	x3 = λ² - x_P - x_Q
	y3 = λ(x_P - x3) - y_P

The m divisions share a single inversion via Montgomery's trick. Each computed
point (x3, y3) then yields all 6 GLV+negation keys via writeSextet for 2 extra
field multiplies (beta*x3, beta^2*x3) — no extra inversion.
*/
func (ks *keyStream) fillPubkeysSteps(m int) uint64 {
	return ks.fillStepsInto(m, false)
}

// fillBasePubkeysSteps is fillPubkeysSteps for the on-GPU GLV path: it advances
// the stream by m linear walk steps but serializes only ONE compressed pubkey per
// step (the base point, variant 0) at slot p, leaving the GLV+negation expansion
// to glv_filter_kernel. It writes m pubkeys (not endoFactor*m) and skips the two
// per-step endomorphism field muls (beta*x, beta^2*x), so the host fills 1/6 the
// bytes and does strictly less work; the device makes up the difference. The
// returned base offset and the kernel's v*m+p candidate ids reconstruct through
// privateKeyForVariantFromBase identically to the full-buffer path.
func (ks *keyStream) fillBasePubkeysSteps(m int) uint64 {
	return ks.fillStepsInto(m, true)
}

// fillStepsInto is the shared EC walk for both fill paths. baseOnly selects the
// per-step serialization: false writes all 6 GLV+negation variants (writeSextet,
// CPU hot path), true writes only the base pubkey (writeBasePubkey, GPU GLV
// path). The secp256k1 arithmetic — point additions, the single shared Montgomery
// inversion, and the degenerate-denominator fixup — is identical either way, so
// both fills stay bit-exact against each other and against privateKeyForVariant.
func (ks *keyStream) fillStepsInto(m int, baseOnly bool) uint64 {
	start := ks.offset

	// Phase 1: serialize the current base point P (already affine, normalized). In
	// full mode writeSextet emits all 6 variant pubkeys to slots v*m; in base-only
	// mode writeBasePubkey emits just P to slot 0 and the GPU derives the rest.
	if baseOnly {
		ks.writeBasePubkey(&ks.px, &ks.py, 0)
	} else {
		ks.writeSextet(&ks.px, &ks.py, 0, m)
	}

	// -x_P and -y_P are reused for every key in this batch.
	var negPx, negPy field.Val
	negPx.NegateVal(&ks.px, 1) // mag 2
	negPy.NegateVal(&ks.py, 1) // mag 2

	// Denominators dx[j] = x_{(j+1)G} - x_P (mag 3). When x_{(j+1)G} == x_P the
	// denominator is zero (P == ±(j+1)G); since one zero would poison the whole
	// shared inversion, substitute 1 and remember the index for an exact fixup.
	// Both operands are normalized, so Equals is an exact zero-denominator test.
	ks.degenIdx = ks.degenIdx[:0]
	for j := 0; j < m; j++ {
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
	for j := 1; j < m; j++ {
		ks.pre[j].Mul2(&ks.pre[j-1], &ks.dx[j])
	}
	var inv field.Val
	inv.Set(&ks.pre[m-1]).Inverse()
	for j := m - 1; j > 0; j-- {
		var invdx field.Val
		invdx.Mul2(&inv, &ks.pre[j-1]) // 1/dx[j] = inv * (dx[0]..dx[j-1])
		inv.Mul(&ks.dx[j])             // fold dx[j] back out for the next index
		ks.dx[j].Set(&invdx)           // dx[j] now holds 1/dx[j]
	}
	ks.dx[0].Set(&inv) // 1/dx[0]

	// Compute each Q = P + (j+1)*G at position p = j+1 and serialize all 6 variants
	// (pubkey of variant v -> slot v*m+p). The last one (j == m-1, position m)
	// becomes the base point for the next batch and is not emitted this round.
	var lam, lamSq, x3, negX3, t, num, y3 field.Val
	for j := 0; j < m; j++ {
		num.Add2(&mulGy[j], &negPy)                  // y_Q - y_P (mag 3)
		lam.Mul2(&num, &ks.dx[j])                    // λ (mag 1)
		lamSq.SquareVal(&lam)                        // λ² (mag 1)
		x3.Set(&lamSq).Add(&negPx).Add(&mulGnegX[j]) // λ² - x_P - x_Q (mag 4)
		negX3.NegateVal(&x3, 4)                      // -x3 (mag 5)
		t.Add2(&ks.px, &negX3)                       // x_P - x3 (mag 6)
		y3.Mul2(&lam, &t).Add(&negPy)                // λ(x_P - x3) - y_P (mag 3)

		x3.Normalize()
		y3.Normalize()

		if j < m-1 {
			if baseOnly {
				ks.writeBasePubkey(&x3, &y3, j+1)
			} else {
				ks.writeSextet(&x3, &y3, j+1, m)
			}
		} else {
			ks.px.Set(&x3) // advance base point to P + m*G
			ks.py.Set(&y3)
		}
	}

	// Exact fixup for any zero-denominator indices (computed via direct scalar
	// multiplication). This runs essentially never for random starting points.
	for _, j := range ks.degenIdx {
		var x, y field.Val
		ks.affineAt(start+uint64(j)+1, &x, &y)
		if j < m-1 {
			if baseOnly {
				ks.writeBasePubkey(&x, &y, j+1)
			} else {
				ks.writeSextet(&x, &y, j+1, m)
			}
		} else {
			ks.px.Set(&x)
			ks.py.Set(&y)
		}
	}

	ks.offset += uint64(m)
	return start
}

// putLimbsFromBE writes a 32-byte big-endian field element as eight
// little-endian 32-bit limbs into dst[0:32] (limb 0 least significant), the limb
// layout ec_walk_glv_kernel reads. Limb j packs big-endian bytes [28-4j,32-4j).
func putLimbsFromBE(dst, be []byte) {
	for j := 0; j < 8; j++ {
		hi := 28 - 4*j
		limb := uint32(be[hi])<<24 | uint32(be[hi+1])<<16 | uint32(be[hi+2])<<8 | uint32(be[hi+3])
		binary.LittleEndian.PutUint32(dst[j*4:], limb)
	}
}

// putAffineLE serializes an affine point (x, y) as 16 little-endian limbs into
// dst[0:64] (x at [0:32], y at [32:64]). Both coordinates MUST be normalized.
func putAffineLE(dst []byte, x, y *field.Val) {
	var xb, yb [32]byte
	x.PutBytesUnchecked(xb[:])
	y.PutBytesUnchecked(yb[:])
	putLimbsFromBE(dst[0:32], xb[:])
	putLimbsFromBE(dst[32:64], yb[:])
}

// fillStartPoints produces this chunk's GPU thread-start points into dst: point
// gid (gid = 0..gpuWalkThreadsPerChunk-1) is (base + gid*ECWalkBatch)*G, written
// as 16 little-endian limbs at dst[gid*64:]. The GPU then fine-walks ECWalkBatch
// points from each start. It is the coarse analogue of fillStepsInto: gid 0 is
// the current base P; gids 1..n-1 are P + gid*(ECWalkBatch*G) via the coarse
// table, all sharing ONE Montgomery inversion. So the host does only
// 1/ECWalkBatch of the EC point additions (and zero pubkey serialization — the
// GPU derives every pubkey), versus the old per-key base-pubkey fill.
//
// Precondition: setBase has put (px, py) at this chunk's base and offset 0.
func (ks *keyStream) fillStartPoints(dst []byte) {
	const n = gpuWalkThreadsPerChunk
	nd := n - 1 // chord additions for gids 1..n-1 (gid 0 is P itself)

	// gid 0: the base point P.
	putAffineLE(dst[0:64], &ks.px, &ks.py)

	var negPx, negPy field.Val
	negPx.NegateVal(&ks.px, 1)
	negPy.NegateVal(&ks.py, 1)

	// Denominators d[i] = x_{(i+1)*M*G} - x_P; substitute 1 at any zero
	// denominator (P == ±(i+1)*M*G) and fix those points up exactly afterwards.
	ks.degenIdx = ks.degenIdx[:0]
	for i := 0; i < nd; i++ {
		if coarseMGx[i].Equals(&ks.px) {
			ks.dx[i].SetInt(1)
			ks.degenIdx = append(ks.degenIdx, i)
			continue
		}
		ks.dx[i].Add2(&coarseMGx[i], &negPx)
	}

	// One shared Montgomery inversion over the nd denominators.
	ks.pre[0].Set(&ks.dx[0])
	for i := 1; i < nd; i++ {
		ks.pre[i].Mul2(&ks.pre[i-1], &ks.dx[i])
	}
	var inv field.Val
	inv.Set(&ks.pre[nd-1]).Inverse()
	for i := nd - 1; i > 0; i-- {
		var invdx field.Val
		invdx.Mul2(&inv, &ks.pre[i-1])
		inv.Mul(&ks.dx[i])
		ks.dx[i].Set(&invdx)
	}
	ks.dx[0].Set(&inv)

	// gid i+1 = P + (i+1)*M*G via the chord with precomputed 1/d[i].
	var lam, lamSq, x3, negX3, t, num, y3 field.Val
	for i := 0; i < nd; i++ {
		num.Add2(&coarseMGy[i], &negPy)
		lam.Mul2(&num, &ks.dx[i])
		lamSq.SquareVal(&lam)
		x3.Set(&lamSq).Add(&negPx).Add(&coarseMGnegX[i])
		negX3.NegateVal(&x3, 4)
		t.Add2(&ks.px, &negX3)
		y3.Mul2(&lam, &t).Add(&negPy)
		x3.Normalize()
		y3.Normalize()
		putAffineLE(dst[(i+1)*64:(i+2)*64], &x3, &y3)
	}

	// Exact fixup for any degenerate gid (runs essentially never).
	for _, i := range ks.degenIdx {
		gid := i + 1
		var x, y field.Val
		ks.affineAt(uint64(gid)*uint64(gpumetal.ECWalkBatch), &x, &y)
		putAffineLE(dst[gid*64:(gid+1)*64], &x, &y)
	}
}

// nextBatch fills one batch of pubkeys (len(out)/endoFactor linear steps) and
// runs the fused multi-buffer HASH160 over them, writing len(out) Hash160s
// straight into out. This is the CPU hot path and stays bit-identical to the
// previous implementation. The GPU path instead calls fillPubkeysSteps directly
// (into a shared Metal buffer) and hashes whole multi-chunk buffers on-device.
func (ks *keyStream) nextBatch(out [][20]byte) uint64 {
	total := len(out)
	start := ks.fillPubkeysSteps(total / endoFactor)

	// A single fused multi-buffer HASH160 pass — multi-buffer SHA-256 (sha256mb)
	// feeding multi-buffer RIPEMD-160 (ripemd160-asm) — over all `total`
	// compressed pubkeys, written STRAIGHT into the caller's slice. out's backing
	// array is total*20 contiguous bytes and hash160mb.Size == 20, so each digest
	// lands exactly on out[i] (no intermediate buffer, no scatter copy). Only the
	// first 33 bytes of each pubStride slot are read; bit-identical to a per-key
	// btcutil.Hash160.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(&out[0])), total*hash160mb.Size)
	hash160mb.FromPubkeys33(dst, ks.pubBuf, total, pubStride)
	return start
}

// privateKeyForVariant reconstructs the private key for GLV+negation variant v at
// a given absolute LINEAR offset. The base linear scalar is k = base + absOffset
// (mod N); the variant scalar is then:
//
//	v0: k           v1: n-k
//	v2: lambda*k    v3: n-lambda*k
//	v4: lambda^2*k  v5: n-lambda^2*k
//
// lambda*k / lambda^2*k are the endomorphism images' scalars; the odd variants
// are the point negations -P, whose scalar is n-k (ModNScalar.Negate). v%2==1
// selects the negated parity. This mirrors the slot layout produced by writeSextet
// (variant v of step p lands in out[v*m+p]). Only used on the rare match path, so
// the extra scalar multiply/negate is irrelevant to throughput.
func (ks *keyStream) privateKeyForVariant(absOffset uint64, v int) *btcec.PrivateKey {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], absOffset)
	var add, k secp.ModNScalar
	add.SetBytes(&addBytes)
	k.Set(&ks.base).Add(&add) // k = base + offset (mod N)
	switch v {
	case 2, 3:
		k.Mul(&lambdaScalar) // lambda*k (first endomorphism image)
	case 4, 5:
		k.Mul(&lambda2Scalar) // lambda^2*k (second endomorphism image)
	}
	if v%2 == 1 {
		k.Negate() // negation variant -P: n - k (mod N)
	}
	kb := k.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(kb[:])
	return priv
}

// privateKeyForVariantFromBase reconstructs the private key for GLV+negation
// variant v at a linear offset, given an explicit 32-byte base seed instead of a
// live keyStream. It mirrors privateKeyForVariant exactly (k = base+offset, then
// the lambda image and negation by variant). The GPU scan path uses it because
// one dispatch covers many chunks and the producer's keyStream no longer holds
// the base of the chunk a match landed in. Match-path only, so cost is moot.
func privateKeyForVariantFromBase(baseSeed [32]byte, absOffset uint64, v int) *btcec.PrivateKey {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], absOffset)
	var base, add, k secp.ModNScalar
	base.SetBytes(&baseSeed)
	add.SetBytes(&addBytes)
	k.Set(&base).Add(&add)
	switch v {
	case 2, 3:
		k.Mul(&lambdaScalar)
	case 4, 5:
		k.Mul(&lambda2Scalar)
	}
	if v%2 == 1 {
		k.Negate()
	}
	kb := k.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(kb[:])
	return priv
}

// verifyHashPipeline runs a handful of keys through the full production hot path
// (EC walk -> GLV endomorphism -> negation -> SHA-256 -> multi-buffer RIPEMD-160)
// and checks every result against the independent btcutil.Hash160 reference. It
// validates ALL 6 GLV+negation variants of every step against
// privateKeyForVariant, so it ties the beta (field) and lambda/lambda^2 (scalar)
// constants together end to end and pins the slot layout. A wrong or mispaired
// constant, a slot-index mismatch, or an architecture-specific SIMD RIPEMD-160
// kernel that is wrong on this CPU makes the program fail fast here instead of
// silently missing every real match for a whole run.
func verifyHashPipeline() {
	var seed [32]byte
	seed[0] = 0x2a
	seed[31] = 0x9f
	ks := newKeyStreamFromSeed(seed)

	const m = 64 // larger than the lane width: exercises the SIMD body and tail
	out := make([][20]byte, endoFactor*m)
	start := ks.nextBatch(out)
	for p := 0; p < m; p++ {
		for v := 0; v < endoFactor; v++ {
			priv := ks.privateKeyForVariant(start+uint64(p), v)
			var want [20]byte
			copy(want[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
			if out[v*m+p] != want {
				log.Fatalf("Hash160 pipeline self-test FAILED at variant %d step %d (RIPEMD160 backend %q): got %x, want %x — refusing to run",
					v, p, ripemd160mb.Backend(), out[v*m+p], want)
			}
		}
	}
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
// CHECKPOINT: Resumable, gap-free systematic scan (every-10s JSON snapshot)
// ============================================================================
//
// The key space is scanned SYSTEMATICALLY from private key 1 upward, with a hard
// guarantee that no key is ever skipped — no matter how many worker threads are
// used, and even if that count changes between runs.
//
// To stay correct under a changing thread count, work is NOT split into one
// fixed range per thread. Instead the space is divided into fixed contiguous
// CHUNKS of chunkSteps linear keys each (chunk c covers private keys
// [startKey + c*chunkSteps, startKey + (c+1)*chunkSteps)). A single global cursor
// hands out the next chunk; every worker simply claims the next unclaimed chunk
// and walks it in order. Threads are therefore interchangeable: with N workers,
// N chunks are processed at once — change N and only the parallelism changes,
// never the set of keys covered.
//
// THE RESUME POSITION IS A SINGLE FRONTIER. Chunks are handed out in increasing
// order and each is walked start-to-finish, so the lowest chunk still being
// processed by any active worker is the "frontier": every key below it is
// guaranteed done. The checkpoint stores exactly that frontier key. On resume
// the cursor restarts there, re-checking at most (threads-1) already-finished
// chunks (cheap, idempotent) and NEVER skipping a key.
//
// The GLV endomorphism still emits endoFactor (6) keys per linear step, but only
// the linear key (variant 0) advances the contiguous frontier; the other 5
// variants are bonus checks of scattered keys that can never create a gap.

// checkpointVersion lets the format be detected on resume. v2 is the
// single-frontier systematic-scan format (v1 was the old per-segment format).
const checkpointVersion = 2

// chunkBatches is the number of nextBatch calls in one work-stealing chunk;
// chunkSteps is the linear keys it spans. Each chunk costs ONE base rebase (a
// scalar multiplication) amortized over chunkSteps*endoFactor keys, so a larger
// chunk lowers that overhead and global-cursor contention, while a smaller chunk
// shrinks the work re-done on resume (at most threads*chunkSteps linear keys).
// 16 batches keeps the rebase overhead well under 1% and a resume re-check tiny.
const (
	chunkBatches = 16
	chunkSteps   = chunkBatches * keyBatchSize
)

// startKeyOne is private key 1: the first valid secp256k1 scalar and the
// historical default start of the systematic scan. (Key 0 is the point at
// infinity — an invalid private key that breaks the affine walk — so the scan
// begins at 1, never 0.)
var startKeyOne = [32]byte{31: 0x01}

// startKeySeed is the live base of the scan window: the absolute private key
// that linear offset 0 maps to. Every generated key is startKeySeed + offset
// (mod N), so the whole scan is a contiguous 2^64-key window anchored here. It
// defaults to key 1 (the original behavior) and is overridden ONCE in main —
// before any worker starts — by --start-key (fresh run) or by the start_key
// saved in the checkpoint (--resume). Because it is set before the goroutines
// launch and only read afterwards, no synchronization is needed.
var startKeySeed = startKeyOne

// checkpointMu serializes checkpoint writes (the stats ticker and the shutdown
// handler can both write), so the temp-file + rename is never interleaved.
var checkpointMu sync.Mutex

// scanState is the shared, thread-count-agnostic scan cursor: nextChunk is the
// index of the next chunk to hand out. Workers claim chunks with one atomic add,
// so each chunk is processed by exactly one worker and the space is covered
// exactly once regardless of how many workers run.
type scanState struct {
	nextChunk uint64 // atomic
}

// frontierTracker is the GPU-mode scan cursor + gap-free frontier. The GPU
// pipeline completes whole multi-chunk dispatches OUT OF ORDER (a producer that
// claimed a later range may finish before an earlier one), so the simple
// "min currentChunk over workers" rule used by the CPU path is not enough. The
// tracker hands out contiguous chunk ranges (claim) and, as ranges complete,
// advances `frontier` only across a contiguous prefix of completed chunks
// (complete). The checkpoint stores `frontier`, so every key below it is
// guaranteed done and a resume can re-scan at most the in-flight ranges above it
// without ever skipping a key. All methods are safe for concurrent use.
type frontierTracker struct {
	mu       sync.Mutex
	next     uint64          // next chunk index to hand out
	frontier uint64          // lowest chunk not yet known complete
	done     map[uint64]bool // completed chunks at or above frontier
}

func newFrontierTracker(start uint64) *frontierTracker {
	return &frontierTracker{next: start, frontier: start, done: make(map[uint64]bool)}
}

// claim reserves n contiguous chunks and returns the first index of the range.
func (f *frontierTracker) claim(n uint64) uint64 {
	f.mu.Lock()
	s := f.next
	f.next += n
	f.mu.Unlock()
	return s
}

// complete marks the n-chunk range [start, start+n) done and advances the
// frontier across every now-contiguous completed chunk.
func (f *frontierTracker) complete(start, n uint64) {
	f.mu.Lock()
	for i := uint64(0); i < n; i++ {
		f.done[start+i] = true
	}
	for f.done[f.frontier] {
		delete(f.done, f.frontier)
		f.frontier++
	}
	f.mu.Unlock()
}

// frontierChunk returns the lowest chunk not yet guaranteed complete.
func (f *frontierTracker) frontierChunk() uint64 {
	f.mu.Lock()
	v := f.frontier
	f.mu.Unlock()
	return v
}

// workerProgress publishes the chunk a single worker is currently processing
// (claimed, possibly unfinished). The checkpoint frontier is the minimum of
// these over active workers, so it never sits above an unfinished chunk. The
// padding keeps each worker's counter on its own cache line (no false sharing).
type workerProgress struct {
	currentChunk uint64 // atomic
	_            [7]uint64
}

// chunkBaseSeed returns the 32-byte private key at the start of chunk c:
// startKeySeed + c*chunkSteps (mod N). With the default base (key 1) this equals
// 1 + c*chunkSteps, exactly as before; with a custom --start-key it anchors the
// window anywhere on the curve. Within practical limits a uint64 of linear
// offset is astronomically more scanning than is physically feasible.
func chunkBaseSeed(c uint64) [32]byte {
	return addOffsetToSeed(startKeySeed, c*chunkSteps)
}

// linearOffsetFromKeys returns the linear offset of a frontier key within the
// scan window anchored at base: (frontier - base) mod N. The window spans 2^64
// keys, so the difference must fit in 64 bits; a frontier below the base (or
// more than 2^64 keys above it) is rejected rather than silently wrapping. This
// is the inverse of "frontier = base + offset" used when writing a checkpoint.
func linearOffsetFromKeys(base, frontier [32]byte) (uint64, error) {
	var b, f, diff secp.ModNScalar
	b.SetBytes(&base)
	f.SetBytes(&frontier)
	b.Negate()              // -base (mod N)
	diff.Set(&f).Add(&b)    // frontier - base (mod N)
	d := diff.Bytes()
	for i := 0; i < 24; i++ {
		if d[i] != 0 {
			return 0, fmt.Errorf("frontier key is below the start key or more than 2^64 keys past it (outside the supported scan window)")
		}
	}
	return binary.BigEndian.Uint64(d[24:]), nil
}

// checkpointFile is the on-disk JSON snapshot of the systematic scan. The scan
// covers a 2^64-key window anchored at StartKey; the position within it is a
// SINGLE frontier (NextPrivateKey): every key from StartKey up to the frontier
// has been checked, and the scan resumes there with ANY thread count. StartKey
// is omitted/empty on old checkpoints, which then default to private key 1.
type checkpointFile struct {
	Version        int    `json:"version"`
	UpdatedAt      string `json:"updated_at"`
	Threads        int    `json:"threads"`     // active workers in the writing run (informational)
	ChunkSteps     uint64 `json:"chunk_steps"` // linear keys per chunk (informational)
	KeyBatchSize   int    `json:"key_batch_size"`
	StartKey       string `json:"start_key"`        // base of the scan window (offset 0); empty = key 1
	NextPrivateKey string `json:"next_private_key"` // frontier: lowest key not yet guaranteed done
	TotalKeys      uint64 `json:"total_keys"`       // keys checked up to the frontier (endoFactor per linear key)
}

// addOffsetToSeed returns the 32-byte big-endian encoding of base + offset
// (mod N): the absolute private key at a given LINEAR offset from a base seed.
// It is the single place the scan turns a (base, offset) pair into a key, used
// both by the per-chunk rebase (chunkBaseSeed) and the checkpoint writer.
func addOffsetToSeed(base [32]byte, offset uint64) [32]byte {
	var addBytes [32]byte
	binary.BigEndian.PutUint64(addBytes[24:], offset)
	var b, add, res secp.ModNScalar
	b.SetBytes(&base)
	add.SetBytes(&addBytes)
	res.Set(&b).Add(&add)
	return res.Bytes()
}

// privateKeyHexFromBase returns hex(base + offset mod N): the absolute private
// key at a given LINEAR offset in a worker's sequence (variant 0, same math as
// privateKeyForVariant), but callable from the checkpoint writer, which does not
// own the keyStream. The checkpoint stores the linear walk position; the other 5
// GLV+negation variants are re-derived on resume.
func privateKeyHexFromBase(base [32]byte, offset uint64) string {
	keyBytes := addOffsetToSeed(base, offset)
	return hex.EncodeToString(keyBytes[:])
}

// validateStartKey rejects a custom scan start key that is not a usable
// secp256k1 private key: it must be in [1, N). Key 0 is the point at infinity
// (the affine walk divides by zero) and a value >= N wraps, so both are refused.
func validateStartKey(seed [32]byte) error {
	var s secp.ModNScalar
	if s.SetBytes(&seed) == 1 {
		return fmt.Errorf("start key must be less than the secp256k1 curve order N")
	}
	if s.IsZero() {
		return fmt.Errorf("start key must be >= 1 (key 0 is the point at infinity)")
	}
	return nil
}

// parsePrivateKeyHex decodes a 32-byte hex private key from a checkpoint file or
// the --start-key flag. A private key is EXACTLY 64 hex characters (32 bytes);
// the length is validated FIRST so a wrong-length or odd-length string (a common
// hand-editing slip) gives a clear, actionable message instead of the cryptic
// "encoding/hex: odd length hex string" the decoder would otherwise return.
func parsePrivateKeyHex(s string) ([32]byte, error) {
	var seed [32]byte
	if len(s) != 64 {
		return seed, fmt.Errorf("private key must be exactly 64 hex characters (32 bytes), got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return seed, fmt.Errorf("invalid hex: %w", err)
	}
	copy(seed[:], raw)
	return seed, nil
}

// writeCheckpoint atomically saves the scan frontier. It writes to a temp file
// then renames, so a crash mid-write never corrupts the existing checkpoint.
//
// The frontier chunk is the lowest chunk any active worker is still processing;
// every key below it is done. Resuming there can re-check at most
// threads*chunkSteps keys but can NEVER skip a key. The stored next_private_key
// is the first key of that frontier chunk, and total_keys is the keys checked up
// to it (endoFactor per linear key).
// cpuFrontierChunk computes the CPU-mode frontier: the lowest chunk any active
// worker is still processing (workers hold their chunk until fully walked), or
// the cursor if none is below it. This is the historic min-over-workers rule.
func cpuFrontierChunk(scan *scanState, progress []workerProgress) uint64 {
	frontier := atomic.LoadUint64(&scan.nextChunk) // upper bound before any claim
	for i := range progress {
		if cc := atomic.LoadUint64(&progress[i].currentChunk); cc < frontier {
			frontier = cc
		}
	}
	return frontier
}

func writeCheckpoint(path string, frontierChunk uint64, activeThreads int) error {
	frontierOffset := frontierChunk * chunkSteps // linear keys fully covered

	cp := checkpointFile{
		Version:        checkpointVersion,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
		Threads:        activeThreads,
		ChunkSteps:     chunkSteps,
		KeyBatchSize:   keyBatchSize,
		StartKey:       hex.EncodeToString(startKeySeed[:]),
		NextPrivateKey: privateKeyHexFromBase(startKeySeed, frontierOffset),
		TotalKeys:      frontierOffset * endoFactor,
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
		return nil, fmt.Errorf("unsupported checkpoint version %d (expected %d); delete the file to start a fresh scan", cp.Version, checkpointVersion)
	}
	if cp.NextPrivateKey == "" {
		return nil, fmt.Errorf("checkpoint has no frontier key (next_private_key)")
	}
	return &cp, nil
}

// resumeBaseSeed returns the scan-window base (the absolute key at linear offset
// 0) to resume from.
//
// When the checkpoint records an explicit start_key, that is the window base and
// next_private_key is the frontier somewhere inside the 2^64-key window above it.
//
// When start_key is ABSENT — an old checkpoint, or one hand-written to start the
// scan at a chosen key (the minimal "{ next_private_key: KEY }" form the README
// documents) — the window is anchored at the frontier key itself and the scan
// resumes from offset 0. Every key below the frontier is treated as already done,
// so this both continues a legacy key-1 scan correctly AND lets a custom
// checkpoint begin ANYWHERE on the curve, without the frontier having to fall
// within 2^64 of key 1 (which silently broke far-away custom start positions).
func resumeBaseSeed(cp *checkpointFile) ([32]byte, error) {
	if cp.StartKey == "" {
		seed, err := parsePrivateKeyHex(cp.NextPrivateKey)
		if err != nil {
			return seed, fmt.Errorf("next_private_key: %w", err)
		}
		if err := validateStartKey(seed); err != nil {
			return seed, fmt.Errorf("next_private_key: %w", err)
		}
		return seed, nil
	}
	seed, err := parsePrivateKeyHex(cp.StartKey)
	if err != nil {
		return seed, fmt.Errorf("start_key: %w", err)
	}
	if err := validateStartKey(seed); err != nil {
		return seed, fmt.Errorf("start_key: %w", err)
	}
	return seed, nil
}

// resumeStartChunk turns a loaded checkpoint into the chunk index the scan
// should restart from, relative to base (the window's start key). It decodes the
// frontier key, computes its linear offset from base, and floors that to a chunk
// boundary — so even a hand-edited key resumes at or below where it stopped,
// re-scanning a partial chunk at worst, never skipping keys. When the checkpoint
// had no start_key, resumeBaseSeed anchored base AT the frontier, so the offset
// is 0 and the scan restarts at chunk 0 of that window.
func resumeStartChunk(cp *checkpointFile, base [32]byte) (uint64, error) {
	frontier, err := parsePrivateKeyHex(cp.NextPrivateKey)
	if err != nil {
		return 0, fmt.Errorf("next_private_key: %w", err)
	}
	offset, err := linearOffsetFromKeys(base, frontier)
	if err != nil {
		return 0, err
	}
	return offset / chunkSteps, nil
}

// ============================================================================
// WORKER POOL: Multi-threaded Brute Force
// ============================================================================

/*
worker is a goroutine that systematically scans contiguous chunks of the key
space and checks every generated Hash160 against the target set.

Parameters:
  - id: Worker thread identifier (worker 0 also publishes console samples)
  - wg: WaitGroup for coordinating shutdown
  - targets: Hash map of target address hashes to search for
  - matchChan: Channel to send matches to the writer goroutine
  - counter: Shared atomic counter for statistics tracking
  - ks: This worker's keyStream (owns all scratch buffers; rebased per chunk)
  - scan: Shared cursor handing out the next chunk
  - progress: This worker's published current-chunk (for the checkpoint frontier)

Algorithm:
 1. Claim the next contiguous chunk from the shared cursor (one atomic add)
 2. Publish it, then rebase the keyStream to the chunk's first key
 3. Walk the chunk in order (chunkBatches batches of the EC walk), checking
    every Hash160 against the target database (O(1) hash map lookup)
 4. On a match, reconstruct the private key and send it to matchWriter
 5. Repeat. Because chunks are handed out in increasing order and walked in
    full, the lowest in-progress chunk is a frontier below which nothing is
    skipped — and any number of workers can cooperate on the same cursor.

Performance Optimizations:
  - Batched affine EC walk: avoids a per-key scalar multiplication entirely
  - Batched (Montgomery) inversion: one field inversion per keyBatchSize keys
  - Allocation-free hot loop: all scratch buffers are owned by the keyStream
  - One scalar-mult rebase per chunk (amortized over chunkSteps*endoFactor keys)
  - One atomic counter update per batch minimizes contention
*/
func worker(id int, wg *sync.WaitGroup, targets hash160Set, matchChan chan<- MatchResult, counter *uint64, ks *keyStream, scan *scanState, progress *workerProgress, stop <-chan struct{}) {
	defer wg.Done()

	// Each batch yields endoFactor (6) keys per linear walk step. The layout is
	// variant-major (see writeSextet): hashes[v*keyBatchSize+p] holds GLV+negation
	// variant v in {0..5} at linear step p in [0,keyBatchSize).
	hashes := make([][20]byte, endoFactor*keyBatchSize)
	// Worker 0 publishes a console sample roughly every ~100k keys.
	// (+1 guarantees a non-zero interval even if keyBatchSize >= 100000.)
	const sampleEvery = 1 + 100000/keyBatchSize // batches between samples
	batchNum := 0

	for {
		// Cooperative shutdown between chunks.
		select {
		case <-stop:
			return
		default:
		}

		// Claim the next contiguous chunk and PUBLISH it before walking, so the
		// checkpoint frontier (min currentChunk over workers) never sits above an
		// unfinished chunk. A resume re-checks at most one chunk per worker.
		c := atomic.AddUint64(&scan.nextChunk, 1) - 1
		atomic.StoreUint64(&progress.currentChunk, c)

		// Rebase to the chunk's first key (one scalar multiplication, amortized
		// over the whole chunk), then walk the chunk in strict order.
		ks.setBase(chunkBaseSeed(c))

		for b := 0; b < chunkBatches; b++ {
			// Mid-chunk shutdown is safe: currentChunk still points at c, so the
			// whole chunk is re-walked on resume (no key skipped).
			select {
			case <-stop:
				return
			default:
			}

			start := ks.nextBatch(hashes)

			// One atomic per batch keeps contention low. len(hashes) counts both
			// the identity and endomorphism keys actually checked.
			atomic.AddUint64(counter, uint64(len(hashes)))

			if id == 0 && (batchNum == 0 || batchNum%sampleEvery == 0) {
				// hashes[0] is variant 0 (the identity key at this batch's start).
				publishCheckedSample(ks.privateKeyForVariant(start, 0), hashes[0])
			}
			batchNum++

			for j := range hashes {
				if _, exists := targets[hashes[j]]; exists {
					// Variant-major slot layout: hashes[v*keyBatchSize+p] is the
					// GLV+negation variant v at linear step p (see writeSextet).
					// Recover (v, p) and rebuild the exact private key.
					v := j / keyBatchSize
					p := j % keyBatchSize
					privateKey := ks.privateKeyForVariant(start+uint64(p), v)
					publicAddress := encodeP2PKH(hashes[j])
					match := MatchResult{privateKey: privateKey, address: publicAddress}
					printMatchResult(match) // Print before enqueueing so the key is visible even if file I/O fails.
					matchChan <- match
				}
			}
		}
	}
}

// ============================================================================
// GPU PIPELINE: hybrid Metal (CPU EC walk -> on-device GLV + Hash160 + Bloom)
// ============================================================================
//
// Measured split of the CPU hot path: hashing (SHA-256 + RIPEMD-160) is ~80% of
// the per-key cost, the secp256k1 walk ~20%. The production GPU pipeline keeps
// the elite CPU EC walk (its single shared field inversion amortizes over a
// 1,024-step batch — cheaper than any per-thread GPU inversion) and offloads the
// embarrassingly parallel work — GLV+negation expansion, Hash160, and the target
// membership test — to the Metal device:
//
//   - N producer goroutines each claim a contiguous range of chunks, run the
//     batched affine walk to fill a large SHARED (unified-memory) Metal buffer
//     with ONE base pubkey per linear step (zero copy), then dispatch one kernel
//     that derives the six GLV+negation variants per base, hashes them, and
//     probes each digest against an on-device Bloom filter built from the targets.
//   - The kernel atomically compacts only the rare candidate ids; the CPU reads
//     back the candidate count (usually zero), re-hashes each with btcutil, and
//     confirms it by an exact target lookup. The Bloom filter (FPR ~1e-6, zero
//     false negatives) is a pure accelerator: it can never miss or fake a match.
//   - One dispatch spans gpuChunksPerDispatch chunks so the GPU runs at a batch
//     size that saturates it (a single 98k-key chunk is too small). While one
//     producer waits on the GPU, the others keep the CPU cores filling buffers,
//     so the CPU walk and the GPU GLV+hash overlap.
//   - The frontierTracker keeps the gap-free resume guarantee under the
//     out-of-order completion this parallelism creates.
//
// A full on-GPU EC walk (gpu/metal/ec_walk.metal, GLVWalk) is also implemented
// and kept as an experiment — bit-exact and CPU-free — but on the M3 reference it
// is slower than this hybrid because the field inversion amortizes over only a
// per-thread ECWalkBatch (<=128) instead of the CPU's 1,024-step batch. It may
// win on larger GPUs; --gpu=auto always measures and picks the faster path.

// gpuSubBatchBaseBytes is the on-GPU GLV path's per-sub-batch input footprint:
// only the keyBatchSize base pubkeys (one per linear walk step) are serialized at
// pubStride. glv_filter_kernel derives the endoFactor GLV+negation variants
// on-device, so the host fills 1/endoFactor the bytes (and skips the two per-step
// endomorphism field muls) of the old full-variant layout. A chunk is
// chunkBatches such sub-batches.
const gpuSubBatchBaseBytes = keyBatchSize * pubStride

// gpuBloomFPR is the target false-positive rate of the on-GPU Bloom filter. A
// false positive only costs one extra CPU confirmation (an exact target lookup),
// and there are NO false negatives, so this trades a little device memory for a
// near-zero CPU confirm rate.
const gpuBloomFPR = 1e-6

// newKeyStreamForGPU builds a keyStream without its own pubBuf: the GPU producer
// repoints ks.pubBuf at slices of the shared Metal buffer before each fill.
func newKeyStreamForGPU() *keyStream {
	return &keyStream{
		dx:       make([]field.Val, keyBatchSize),
		pre:      make([]field.Val, keyBatchSize),
		degenIdx: make([]int, 0, 4),
	}
}

// gpuProducer claims chunk ranges, fills shared pubkey buffers via the elite CPU
// EC walk (one base pubkey per linear step), dispatches the on-device GLV+negation
// expansion + Hash160 + Bloom filter, confirms only the rare compacted candidates
// against the real target set, and advances the frontier. It returns when stop is
// closed (at a dispatch boundary).
//
// This is the hybrid pipeline: the CPU keeps the Montgomery-batched affine walk
// (one inversion amortized over keyBatchSize keys — far better amortization than a
// per-thread GPU batch), and the GPU does the GLV expansion (beta*x, beta^2*x),
// the six-way Hash160, and the Bloom membership test. On Apple M-series this is
// measurably faster than walking on the GPU too, because the device field
// inversion is the bottleneck there (see TestGPUPhase2BThroughput vs the
// experimental on-GPU ec_walk path). The Bloom filter runs the per-key membership
// test on the device, so the CPU reads back only the (typically zero) candidate
// ids per dispatch; each is re-hashed with btcutil.Hash160 and confirmed by an
// exact `targets` lookup, so the filter is a pure accelerator that can never cause
// a missed or false match.
func gpuProducer(id int, wg *sync.WaitGroup, hasher *gpumetal.Hasher, chunksPerDispatch int, bloom *gpumetal.Buffer, bloomMask, bloomK uint32, targets hash160Set, matchChan chan<- MatchResult, counter *uint64, tracker *frontierTracker, stop <-chan struct{}) {
	defer wg.Done()

	// One dispatch spans chunksPerDispatch chunks; each chunk is chunkBatches
	// sub-batches of keyBatchSize base pubkeys. baseCount = the base points fed to
	// the GPU; keyCount = baseCount*endoFactor keys scanned (the rate counter).
	subBatchesPerChunk := chunkBatches
	subBatches := chunksPerDispatch * subBatchesPerChunk
	baseCount := subBatches * keyBatchSize // == chunksPerDispatch * chunkSteps
	keyCount := baseCount * endoFactor

	// Shared (unified-memory) input buffer of base pubkeys; the keyStream fills
	// slices of it in place (zero copy), one compressed pubkey per linear step.
	in, err := hasher.NewBuffer(subBatches * gpuSubBatchBaseBytes)
	if err != nil {
		log.Printf("GPU producer %d: input buffer alloc failed: %s", id, err)
		return
	}
	defer in.Free()
	// mcount: one atomic candidate counter (padded). mdata: candidate ids; Bloom
	// hits are far rarer than baseCount, so a baseCount-slot buffer never overflows
	// (the kernel also caps writes at the candidate count).
	mcount, err := hasher.NewBuffer(16)
	if err != nil {
		log.Printf("GPU producer %d: counter buffer alloc failed: %s", id, err)
		return
	}
	defer mcount.Free()
	mdata, err := hasher.NewBuffer(baseCount * 4)
	if err != nil {
		log.Printf("GPU producer %d: candidate buffer alloc failed: %s", id, err)
		return
	}
	defer mdata.Free()
	// Each producer dispatches on its own command queue so the GPU overlaps work
	// from all producers instead of running one globally-serialized dispatch at a
	// time (no global mutex held across the multi-millisecond GPU wait).
	stream, err := hasher.NewStream()
	if err != nil {
		log.Printf("GPU producer %d: stream alloc failed: %s", id, err)
		return
	}
	defer stream.Free()
	inBytes := in.Bytes()
	mcountBytes := mcount.Bytes()
	mdataBytes := mdata.Bytes()

	ks := newKeyStreamForGPU()
	var h160 [20]byte
	dispatchNum := 0

	for {
		select {
		case <-stop:
			return
		default:
		}

		// Claim a contiguous range and publish nothing until it completes: the
		// frontier only advances past fully-scanned ranges (see frontierTracker).
		startChunk := tracker.claim(uint64(chunksPerDispatch))

		// Fill the base pubkeys for every chunk/sub-batch into the shared buffer.
		// setBase rebases the walk to the chunk and resets offset to 0, so the
		// b-th sub-batch holds linear steps [b*keyBatchSize, (b+1)*keyBatchSize).
		for k := 0; k < chunksPerDispatch; k++ {
			ks.setBase(chunkBaseSeed(startChunk + uint64(k)))
			for b := 0; b < subBatchesPerChunk; b++ {
				sub := k*subBatchesPerChunk + b
				ks.pubBuf = inBytes[sub*gpuSubBatchBaseBytes : sub*gpuSubBatchBaseBytes+gpuSubBatchBaseBytes]
				ks.fillBasePubkeysSteps(keyBatchSize)
			}
		}

		// On-GPU GLV+negation expansion + Hash160 + Bloom (blocks this producer;
		// others keep filling). Reset the candidate counter first (zero copy).
		binary.LittleEndian.PutUint32(mcountBytes[:4], 0)
		if err := stream.GLVFilterStream(in, bloom, mcount, mdata, baseCount, pubStride, bloomMask, bloomK); err != nil {
			log.Fatalf("GPU dispatch failed: %s — aborting (a silent GLV/hash error would miss matches)", err)
		}
		atomic.AddUint64(counter, uint64(keyCount))

		// Worker 0 publishes a liveness sample (dispatch base, variant 0). The key
		// is reconstructed and hashed on the CPU (rare path, off the hot loop).
		if id == 0 && dispatchNum%8 == 0 {
			sampleKey := privateKeyForVariantFromBase(chunkBaseSeed(startChunk), 0, 0)
			copy(h160[:], btcutil.Hash160(sampleKey.PubKey().SerializeCompressed()))
			publishCheckedSample(sampleKey, h160)
		}
		dispatchNum++

		// Confirm: decode and re-derive only the compacted candidates. With FPR
		// ~1e-6 over ~keyCount keys this is well under one candidate per dispatch.
		// The matched variant pubkey is not in any buffer (the GPU derived it), so
		// each candidate id v*baseCount + gid is decoded: gid is the base index in
		// fill order = chunkOffset*chunkSteps + step, so the key is reconstructed
		// at chunk startChunk+chunkOffset, linear offset step, variant v.
		nCand := binary.LittleEndian.Uint32(mcountBytes[:4])
		if int(nCand) > baseCount {
			nCand = uint32(baseCount)
		}
		for i := uint32(0); i < nCand; i++ {
			id := int(binary.LittleEndian.Uint32(mdataBytes[i*4 : i*4+4]))
			v := id / baseCount   // GLV+negation variant in [0, endoFactor)
			gid := id % baseCount // base pubkey index within the dispatch
			chunkOff := gid / chunkSteps
			step := gid % chunkSteps
			privateKey := privateKeyForVariantFromBase(chunkBaseSeed(startChunk+uint64(chunkOff)), uint64(step), v)
			copy(h160[:], btcutil.Hash160(privateKey.PubKey().SerializeCompressed()))
			if _, exists := targets[h160]; exists {
				publicAddress := encodeP2PKH(h160)
				match := MatchResult{privateKey: privateKey, address: publicAddress}
				printMatchResult(match)
				matchChan <- match
			}
		}

		tracker.complete(startChunk, uint64(chunksPerDispatch))
	}
}

// runGPU starts the GPU producer pool and blocks until all producers exit.
func runGPU(hasher *gpumetal.Hasher, numProducers, chunksPerDispatch int, bloom *gpumetal.Buffer, bloomMask, bloomK uint32, targets hash160Set, matchChan chan<- MatchResult, counter *uint64, tracker *frontierTracker, stop <-chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go gpuProducer(i, &wg, hasher, chunksPerDispatch, bloom, bloomMask, bloomK, targets, matchChan, counter, tracker, stop)
	}
	wg.Wait()
}

// gpuSelfTest hashes real secp256k1 public keys on the GPU and checks every
// digest against btcutil.Hash160, then validates the on-GPU GLV+negation
// expansion the production path relies on (gpuGLVSelfTest). A mismatch means the
// device/kernel is not bit-correct here, so the program must refuse the GPU path
// rather than silently miss every match for the whole run (same contract as
// verifyHashPipeline).
func gpuSelfTest(hasher *gpumetal.Hasher) error {
	const n = 4096
	in, err := hasher.NewBuffer(n * pubStride)
	if err != nil {
		return err
	}
	defer in.Free()
	out, err := hasher.NewBuffer(n * 20)
	if err != nil {
		return err
	}
	defer out.Free()

	src := in.Bytes()
	for i := 0; i < n; i++ {
		var priv [32]byte
		binary.BigEndian.PutUint64(priv[24:], uint64(i+1))
		_, pub := btcec.PrivKeyFromBytes(priv[:])
		copy(src[i*pubStride:i*pubStride+33], pub.SerializeCompressed())
	}
	if err := hasher.Hash160(in, out, n, pubStride); err != nil {
		return err
	}
	res := out.Bytes()
	for i := 0; i < n; i++ {
		var got, want [20]byte
		copy(got[:], res[i*20:i*20+20])
		copy(want[:], btcutil.Hash160(src[i*pubStride:i*pubStride+33]))
		if got != want {
			return fmt.Errorf("GPU Hash160 mismatch at key %d: got %x want %x", i+1, got, want)
		}
	}
	return gpuGLVSelfTest(hasher)
}

// gpuGLVSelfTest validates the on-GPU GLV+negation expansion (glv_filter_kernel)
// the production scan path now uses. It fills base pubkeys, builds a Bloom filter
// from a sparse subset of (step, variant) targets computed the canonical CPU way
// (privateKeyForVariantFromBase -> btcutil.Hash160), dispatches the kernel, and
// requires every target to be compacted at its v*count+step candidate id (zero
// false negatives). A miss means the device beta/beta^2 multiply, the negation
// parity flip, or the candidate-id mapping is wrong here — which would silently
// drop real matches — so the program must refuse the GPU path.
func gpuGLVSelfTest(hasher *gpumetal.Hasher) error {
	const (
		nb         = 4096 // base pubkeys = GPU threads
		stepStride = 16   // every 16th base is a 6-variant target (6*256 < nb cap)
	)
	seedFor := func(i int) [32]byte {
		var s [32]byte
		binary.BigEndian.PutUint64(s[24:], uint64(i+1))
		return s
	}

	in, err := hasher.NewBuffer(nb * pubStride)
	if err != nil {
		return err
	}
	defer in.Free()
	src := in.Bytes()
	for i := 0; i < nb; i++ {
		priv := privateKeyForVariantFromBase(seedFor(i), 0, 0)
		copy(src[i*pubStride:i*pubStride+33], priv.PubKey().SerializeCompressed())
	}

	targets := make(hash160Set)
	want := make(map[uint32]struct{})
	for i := 0; i < nb; i += stepStride {
		for v := 0; v < endoFactor; v++ {
			priv := privateKeyForVariantFromBase(seedFor(i), 0, v)
			var h [20]byte
			copy(h[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
			targets[h] = struct{}{}
			want[uint32(v*nb+i)] = struct{}{}
		}
	}

	bf := newBloomFromTargets(targets, gpuBloomFPR)
	bloom, err := hasher.NewBuffer(bf.byteLen())
	if err != nil {
		return err
	}
	defer bloom.Free()
	bf.writeTo(bloom.Bytes())

	mcount, err := hasher.NewBuffer(16)
	if err != nil {
		return err
	}
	defer mcount.Free()
	mdata, err := hasher.NewBuffer(nb * 4)
	if err != nil {
		return err
	}
	defer mdata.Free()

	binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
	if err := hasher.GLVFilter(in, bloom, mcount, mdata, nb, pubStride, bf.mask, bf.k); err != nil {
		return err
	}

	nCand := int(binary.LittleEndian.Uint32(mcount.Bytes()[:4]))
	if nCand > nb {
		return fmt.Errorf("GPU GLV candidate counter %d exceeds cap %d (compaction overflow)", nCand, nb)
	}
	got := make(map[uint32]bool, nCand)
	md := mdata.Bytes()
	for i := 0; i < nCand; i++ {
		got[binary.LittleEndian.Uint32(md[i*4:i*4+4])] = true
	}
	for id := range want {
		if !got[id] {
			return fmt.Errorf("GPU GLV expansion missed variant %d step %d (candidate id %d) — device beta/parity/mapping is wrong",
				int(id)/nb, int(id)%nb, id)
		}
	}
	// The production pipeline is the hybrid (CPU EC walk + on-device GLV+Hash160+
	// Bloom), so the backend-selection gate ends here: Hash160 and GLV expansion
	// are the on-device steps it relies on. The full on-GPU EC walk is kept as an
	// experiment (ec_walk.metal / GLVWalk) and is validated separately by
	// gpuECWalkSelfTest and TestGPUECWalk, not on the production startup path.
	return nil
}

// gpuECWalkSelfTest validates the EXPERIMENTAL full on-GPU EC-walk pipeline
// (ec_walk.metal / GLVWalk): the host fills only one start point per thread (the
// coarse walk), the GPU fine-walks ECWalkBatch points per thread, expands each to
// its six GLV+negation variants, hashes, and Bloom-filters them. It builds the
// filter from a sparse subset of (offset, variant) targets computed the canonical
// CPU way (privateKeyForVariantFromBase -> btcutil.Hash160) over a non-degenerate
// chunk, dispatches ec_walk_glv_kernel, and requires every target to be compacted
// at its v*L+linearIdx candidate id (zero false negatives). This is NOT on the
// production startup gate (production uses the faster hybrid path); it backs the
// on-GPU walk experiment and is exercised by TestGPUECWalkSelfTest / TestGPUECWalk
// so the kept experimental kernel stays bit-exact against btcutil.
func gpuECWalkSelfTest(hasher *gpumetal.Hasher) error {
	const offStride = 53 // sparse offsets; 53 is coprime with ECWalkBatch so it hits varied j
	// Use chunk 1 (base scalar >= chunkSteps) so no thread hits the scan-start
	// degenerate region (start scalar in [1, ECWalkBatch)).
	const selfChunk = 1
	gthreads := gpuWalkThreadsPerChunk
	L := gpuWalkThreadsPerChunk * gpumetal.ECWalkBatch
	seed := chunkBaseSeed(selfChunk)

	starts, err := hasher.NewBuffer(gthreads * 16 * 4)
	if err != nil {
		return err
	}
	defer starts.Free()
	ks := newKeyStreamForGPU()
	ks.setBase(seed)
	ks.fillStartPoints(starts.Bytes())

	txX, err := hasher.NewBuffer((gpumetal.ECWalkBatch - 1) * 8 * 4)
	if err != nil {
		return err
	}
	defer txX.Free()
	txY, err := hasher.NewBuffer((gpumetal.ECWalkBatch - 1) * 8 * 4)
	if err != nil {
		return err
	}
	defer txY.Free()
	xb, yb := txX.Bytes(), txY.Bytes()
	for i := 0; i < gpumetal.ECWalkBatch-1; i++ {
		var bx, by [32]byte
		mulGx[i].PutBytesUnchecked(bx[:])
		mulGy[i].PutBytesUnchecked(by[:])
		putLimbsFromBE(xb[i*32:i*32+32], bx[:])
		putLimbsFromBE(yb[i*32:i*32+32], by[:])
	}

	targets := make(hash160Set)
	want := make(map[uint32]struct{})
	for idx := 0; idx < L; idx += offStride {
		for v := 0; v < endoFactor; v++ {
			pk := privateKeyForVariantFromBase(seed, uint64(idx), v)
			var h [20]byte
			copy(h[:], btcutil.Hash160(pk.PubKey().SerializeCompressed()))
			targets[h] = struct{}{}
			want[uint32(v*L+idx)] = struct{}{}
		}
	}

	bf := newBloomFromTargets(targets, gpuBloomFPR)
	bloom, err := hasher.NewBuffer(bf.byteLen())
	if err != nil {
		return err
	}
	defer bloom.Free()
	bf.writeTo(bloom.Bytes())

	mcount, err := hasher.NewBuffer(16)
	if err != nil {
		return err
	}
	defer mcount.Free()
	mdata, err := hasher.NewBuffer(L * 4)
	if err != nil {
		return err
	}
	defer mdata.Free()

	binary.LittleEndian.PutUint32(mcount.Bytes()[:4], 0)
	if err := hasher.GLVWalk(starts, txX, txY, bloom, mcount, mdata, gthreads, bf.mask, bf.k); err != nil {
		return err
	}

	nCand := int(binary.LittleEndian.Uint32(mcount.Bytes()[:4]))
	if nCand > L {
		return fmt.Errorf("GPU walk candidate counter %d exceeds cap %d (compaction overflow)", nCand, L)
	}
	got := make(map[uint32]bool, nCand)
	md := mdata.Bytes()
	for i := 0; i < nCand; i++ {
		got[binary.LittleEndian.Uint32(md[i*4:i*4+4])] = true
	}
	for id := range want {
		if !got[id] {
			return fmt.Errorf("GPU EC walk missed variant %d offset %d (candidate id %d) — device walk/expansion/mapping is wrong",
				int(id)/L, int(id)%L, id)
		}
	}
	return nil
}

// calibrateCPUKeysPerSec measures the full CPU hot path (EC walk + fused
// multi-buffer HASH160, no target scan) across `threads` workers for d.
func calibrateCPUKeysPerSec(d time.Duration, threads int) float64 {
	var counter uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(seedByte byte) {
			defer wg.Done()
			var seed [32]byte
			seed[0] = seedByte
			seed[31] = 0x01
			ks := newKeyStreamFromSeed(seed)
			hashes := make([][20]byte, endoFactor*keyBatchSize)
			for {
				select {
				case <-stop:
					return
				default:
				}
				ks.nextBatch(hashes)
				atomic.AddUint64(&counter, uint64(len(hashes)))
			}
		}(byte(i + 1))
	}
	start := time.Now()
	time.Sleep(d)
	close(stop)
	wg.Wait()
	return float64(atomic.LoadUint64(&counter)) / time.Since(start).Seconds()
}

// calibrateGPUKeysPerSec measures the production GPU pipeline (host CPU EC-walk
// base-pubkey fill + on-device GLV expansion + Hash160 + Bloom probe, no target
// scan) across `producers` producers for d. It mirrors gpuProducer exactly — same
// per-sub-batch fill, same GLVFilterStream dispatch — so --gpu=auto compares the
// REAL production path against the CPU. Producers walk disjoint throwaway chunk
// ranges and use a zeroed Bloom filter (every probe misses, so the kernel does the
// full per-key work but compacts nothing), isolating the fill + GLV + hash cost.
func calibrateGPUKeysPerSec(d time.Duration, hasher *gpumetal.Hasher, producers, chunksPerDispatch int) float64 {
	var counter uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	subBatchesPerChunk := chunkBatches
	subBatches := chunksPerDispatch * subBatchesPerChunk
	baseCount := subBatches * keyBatchSize
	keyCount := baseCount * endoFactor

	// A representative zeroed Bloom filter (1<<20 bits, k=20) so the probe memory
	// pattern matches production; nothing matches, so no compaction occurs.
	const calibBloomBits = 1 << 20
	const calibBloomMask = calibBloomBits - 1
	const calibBloomK = 20

	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			in, err := hasher.NewBuffer(subBatches * gpuSubBatchBaseBytes)
			if err != nil {
				return
			}
			defer in.Free()
			bloom, err := hasher.NewBuffer(calibBloomBits / 8)
			if err != nil {
				return
			}
			defer bloom.Free()
			mcount, err := hasher.NewBuffer(16)
			if err != nil {
				return
			}
			defer mcount.Free()
			mdata, err := hasher.NewBuffer(baseCount * 4)
			if err != nil {
				return
			}
			defer mdata.Free()
			stream, err := hasher.NewStream()
			if err != nil {
				return
			}
			defer stream.Free()
			inBytes := in.Bytes()
			mcountBytes := mcount.Bytes()
			ks := newKeyStreamForGPU()
			chunk := uint64(pid) * uint64(chunksPerDispatch)
			stride := uint64(producers) * uint64(chunksPerDispatch)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for k := 0; k < chunksPerDispatch; k++ {
					ks.setBase(chunkBaseSeed(chunk + uint64(k)))
					for b := 0; b < subBatchesPerChunk; b++ {
						sub := k*subBatchesPerChunk + b
						ks.pubBuf = inBytes[sub*gpuSubBatchBaseBytes : sub*gpuSubBatchBaseBytes+gpuSubBatchBaseBytes]
						ks.fillBasePubkeysSteps(keyBatchSize)
					}
				}
				binary.LittleEndian.PutUint32(mcountBytes[:4], 0)
				if err := stream.GLVFilterStream(in, bloom, mcount, mdata, baseCount, pubStride, calibBloomMask, calibBloomK); err != nil {
					return
				}
				atomic.AddUint64(&counter, uint64(keyCount))
				chunk += stride
			}
		}(i)
	}
	start := time.Now()
	time.Sleep(d)
	close(stop)
	wg.Wait()
	return float64(atomic.LoadUint64(&counter)) / time.Since(start).Seconds()
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
func statsReporter(counter *uint64, startTime time.Time, frontierChunk func() uint64, checkpointPath string, baseTotal uint64, activeThreads int) {
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
			if err := writeCheckpoint(checkpointPath, frontierChunk(), activeThreads); err != nil {
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
 4. Set up the systematic scan cursor (fresh from key 1, or resumed from a saved frontier) and per-worker key streams
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
	--resume           Continue the scan from the saved frontier instead of starting fresh from key 1

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
	resume := flag.Bool("resume", false, "continue the scan from the checkpoint frontier instead of starting fresh from key 1")
	startKeyHex := flag.String("start-key", "", "64-hex-char private key where a FRESH scan begins (default: key 1); ignored with --resume (the checkpoint's start key is used)")
	gpuMode := flag.String("gpu", "auto", "GPU (Apple Metal) pipeline [GLV+Hash160+Bloom]: auto (use if faster), on (force), off (CPU only)")
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
		fmt.Println("  --start-key=HEX      - 64-hex-char private key where a fresh scan begins (default: key 1); ignored with --resume")
		fmt.Println("  --gpu=auto|on|off    - Apple Metal GPU pipeline: GLV+Hash160+Bloom (default: auto; on=force, off=CPU only)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline 8 matches.txt attack-addresses-p2pkh.txt")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline --resume 8 matches.txt attack-addresses-p2pkh.txt")
		fmt.Println("  ./bitcoin-wallet-bruteforce-offline --start-key=A7F31C92B04D0210000000000000000000000000000000000000000000000001 8 matches.txt attack-addresses-p2pkh.txt")
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
	fmt.Printf("Key Gen: Batched affine EC walk + GLV endomorphism + point negation + Montgomery inversion (%d keys/batch)\n", endoFactor*keyBatchSize)
	fmt.Printf("SHA256: %s backend, %d lane(s) [sha256mb multi-buffer]\n", sha256mb.Backend(), sha256mb.Lanes())
	fmt.Printf("RIPEMD160: %s backend, %d lane(s) [ripemd160-asm multi-buffer]\n", ripemd160mb.Backend(), ripemd160mb.Lanes())
	fmt.Printf("HASH160: %s\n", hash160mb.Backend())
	fmt.Printf("Public Key: Compressed (33 bytes)\n")
	fmt.Printf("Lookup: Hash160 (Base58 only on match)\n")
	fmt.Printf("Address Type: Legacy P2PKH (starts with '1')\n\n")

	// Fail fast if the Hash160 pipeline (including the architecture-specific SIMD
	// RIPEMD-160 backend) is not bit-correct on this CPU: a silent hash bug would
	// make every real match be missed for the entire run.
	verifyHashPipeline()

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

	// Resolve the scan window base (startKeySeed). A fresh run may begin anywhere
	// via --start-key; a resumed run always continues from the start key recorded
	// in the checkpoint, so --start-key is ignored (with a note) when both are set.
	if *startKeyHex != "" {
		seed, perr := parsePrivateKeyHex(*startKeyHex)
		if perr != nil {
			log.Fatalf("Invalid --start-key: %s", perr)
		}
		if verr := validateStartKey(seed); verr != nil {
			log.Fatalf("Invalid --start-key: %s", verr)
		}
		if *resume {
			log.Printf("Note: --start-key is ignored with --resume; using the start key saved in %q.", *checkpointPath)
		} else {
			startKeySeed = seed
		}
	}

	// Determine where the systematic scan starts: a saved frontier (--resume) or
	// the window base, key 1 by default (fresh). scan.nextChunk is the shared
	// global cursor; baseTotal is the keys-checked count carried over for display.
	scan := &scanState{}
	var baseTotal uint64
	if *resume {
		resumeData, rerr := readCheckpoint(*checkpointPath)
		if rerr != nil {
			log.Fatalf("Failed to load checkpoint %q for --resume: %s", *checkpointPath, rerr)
		}
		base, berr := resumeBaseSeed(resumeData)
		if berr != nil {
			log.Fatalf("Invalid checkpoint %q: %s", *checkpointPath, berr)
		}
		startKeySeed = base
		startChunk, rerr := resumeStartChunk(resumeData, base)
		if rerr != nil {
			log.Fatalf("Invalid checkpoint %q: %s", *checkpointPath, rerr)
		}
		scan.nextChunk = startChunk
		baseTotal = resumeData.TotalKeys
		fmt.Printf("Resuming systematic scan from %s\n", *checkpointPath)
		fmt.Printf("  Start key    : %s\n", hex.EncodeToString(startKeySeed[:]))
		fmt.Printf("  Frontier key : %s\n", resumeData.NextPrivateKey)
		fmt.Printf("  Keys checked : %d (every key below the frontier is done)\n", resumeData.TotalKeys)
		fmt.Printf("  Threads now  : %d — thread-count agnostic, so no key is skipped.\n\n", numThreads)
	}

	// ========================================================================
	// BACKEND SELECTION (hybrid GPU Metal GLV+Hash160+Bloom vs CPU)
	// ========================================================================

	// GPU pipeline tunables (overridable for measurement / constrained RAM).
	gpuProducers := runtime.NumCPU()
	if v := os.Getenv("BTC_GPU_PRODUCERS"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			gpuProducers = n
		}
	}
	gpuChunksPerDispatch := 6 // ~590k keys/dispatch: near the GPU saturation knee
	if v := os.Getenv("BTC_GPU_CHUNKS"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			gpuChunksPerDispatch = n
		}
	}

	useGPU, hasher := selectBackend(*gpuMode, numThreads, gpuProducers, gpuChunksPerDispatch)
	if useGPU {
		fmt.Printf("Active backend: GPU — %s (Apple Metal) | %d producer(s) x %d chunks/dispatch = %d keys/dispatch\n",
			hasher.Name(), gpuProducers, gpuChunksPerDispatch, gpuChunksPerDispatch*chunkBatches*endoFactor*keyBatchSize)
	} else {
		fmt.Printf("Active backend: CPU — multi-buffer HASH160 | %d worker thread(s)\n", numThreads)
	}
	fmt.Printf("Checkpoint: %s | systematic scan from key %s | chunk = %d keys | saved every 10s\n\n",
		*checkpointPath, hex.EncodeToString(startKeySeed[:]), uint64(chunkSteps)*endoFactor)

	// ========================================================================
	// SHARED STATE INITIALIZATION
	// ========================================================================

	// Atomic counter for keys generated THIS run (shared across all workers).
	var counter uint64

	// Buffered channel for sending matches from workers/producers to file writer
	// Buffer size: 100 (prevents blocking if matches found in bursts)
	matchChan := make(chan MatchResult, 100)

	// WaitGroups for coordinating goroutine shutdown
	var workerWg sync.WaitGroup // Tracks CPU worker goroutines
	var writerWg sync.WaitGroup // Tracks writer goroutine

	// stop is closed on SIGINT/SIGTERM so workers/producers exit at a batch
	// boundary, letting main write one final, fully up-to-date checkpoint.
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

	// Start match writer goroutine (handles file I/O asynchronously).
	writerWg.Add(1)
	go matchWriter(matchChan, outputFile, &writerWg)

	startTime := time.Now()
	fmt.Printf("Starting brute force...\n")
	fmt.Printf("════════════════════════════════════════════════════════════\n\n")

	// frontierChunk yields the resume-safe scan frontier; its source differs by
	// mode (CPU: min chunk over workers; GPU: the out-of-order frontierTracker).
	var frontierChunk func() uint64

	if useGPU {
		// GPU mode: a frontierTracker hands contiguous chunk ranges to the
		// producers and advances the gap-free frontier as ranges complete out
		// of order. All cores act as EC producers feeding one GPU.
		tracker := newFrontierTracker(scan.nextChunk)
		frontierChunk = tracker.frontierChunk

		// Encode the target set into an on-GPU Bloom filter so the membership
		// test runs on the device and only candidate gids return to the CPU.
		bf := newBloomFromTargets(targets, gpuBloomFPR)
		bloomBuf, berr := hasher.NewBuffer(bf.byteLen())
		if berr != nil {
			log.Fatalf("GPU Bloom buffer alloc failed: %s", berr)
		}
		bf.writeTo(bloomBuf.Bytes())
		fmt.Printf("GPU Bloom filter: %d bits, k=%d probes, %.1f MiB (FPR target %.0e)\n",
			uint64(bf.mask)+1, bf.k, float64(bf.byteLen())/(1<<20), gpuBloomFPR)

		if err := writeCheckpoint(*checkpointPath, frontierChunk(), numThreads); err != nil {
			log.Printf("Failed to write initial checkpoint: %s", err)
		}
		go statsReporter(&counter, startTime, frontierChunk, *checkpointPath, baseTotal, numThreads)
		runGPU(hasher, gpuProducers, gpuChunksPerDispatch, bloomBuf, bf.mask, bf.k, targets, matchChan, &counter, tracker, stop)
		bloomBuf.Free()
		hasher.Close()
	} else {
		// CPU mode: one keyStream per worker (owns its scratch buffers; rebased
		// to each claimed chunk) plus a per-worker progress slot feeding the
		// checkpoint frontier. Until a worker claims its first chunk, its
		// published position equals the start, so the initial checkpoint
		// reflects the start.
		streams := make([]*keyStream, numThreads)
		progress := make([]workerProgress, numThreads)
		for i := 0; i < numThreads; i++ {
			streams[i] = newKeyStreamFromSeed(startKeySeed)
			progress[i].currentChunk = scan.nextChunk
		}
		frontierChunk = func() uint64 { return cpuFrontierChunk(scan, progress) }
		if err := writeCheckpoint(*checkpointPath, frontierChunk(), numThreads); err != nil {
			log.Printf("Failed to write initial checkpoint: %s", err)
		}
		go statsReporter(&counter, startTime, frontierChunk, *checkpointPath, baseTotal, numThreads)
		for i := 0; i < numThreads; i++ {
			workerWg.Add(1)
			go worker(i, &workerWg, targets, matchChan, &counter, streams[i], scan, &progress[i], stop)
		}
		// Runs until interrupted: SIGINT/SIGTERM closes stop, workers exit at the
		// next batch boundary, and the WaitGroup unblocks.
		workerWg.Wait()
	}

	// Close match channel to signal writer to finish, then wait for it to drain.
	close(matchChan)
	writerWg.Wait()

	// Final checkpoint capturing the exact frontier (graceful shutdown).
	if err := writeCheckpoint(*checkpointPath, frontierChunk(), numThreads); err != nil {
		log.Printf("Failed to write final checkpoint: %s", err)
	} else {
		fmt.Printf("Final checkpoint saved to %s\n", *checkpointPath)
	}
}

// selectBackend decides whether to use the hybrid GPU (Apple Metal) pipeline
// (CPU walk + on-device GLV+Hash160+Bloom) or the CPU hot path, honoring
// --gpu=auto|on|off. It returns the chosen hasher
// (nil for CPU). In auto mode it runs the bit-exact self-test and a short
// calibration and picks the faster backend, guaranteeing no regression below
// the CPU path. In on mode any failure is fatal; in off mode the GPU is skipped.
func selectBackend(mode string, numThreads, gpuProducers, gpuChunksPerDispatch int) (bool, *gpumetal.Hasher) {
	if mode == "off" {
		return false, nil
	}
	if !gpumetal.Available() {
		if mode == "on" {
			log.Fatalf("--gpu=on but this build has no Metal support (needs native darwin + cgo)")
		}
		return false, nil
	}

	hasher, err := gpumetal.New()
	if err != nil {
		if mode == "on" {
			log.Fatalf("--gpu=on but Metal initialization failed: %s", err)
		}
		log.Printf("GPU unavailable (%s); using CPU", err)
		return false, nil
	}

	// Correctness gate: refuse a GPU that is not bit-exact, exactly like the CPU
	// verifyHashPipeline — a silent hash error would miss every real match.
	if err := gpuSelfTest(hasher); err != nil {
		hasher.Close()
		if mode == "on" {
			log.Fatalf("--gpu=on but GPU self-test failed: %s", err)
		}
		log.Printf("GPU self-test failed (%s); using CPU", err)
		return false, nil
	}
	fmt.Printf("GPU self-test: PASS — Hash160 + on-device GLV expansion bit-exact vs btcutil on %s\n", hasher.Name())

	if mode == "on" {
		return true, hasher
	}

	// auto: measure both backends briefly and choose the faster one.
	fmt.Printf("Calibrating backends (~0.6s)...\n")
	gpuRate := calibrateGPUKeysPerSec(300*time.Millisecond, hasher, gpuProducers, gpuChunksPerDispatch)
	cpuRate := calibrateCPUKeysPerSec(300*time.Millisecond, numThreads)
	fmt.Printf("  GPU pipeline : %6.1f M keys/sec\n", gpuRate/1e6)
	fmt.Printf("  CPU pipeline : %6.1f M keys/sec\n", cpuRate/1e6)
	if gpuRate >= cpuRate {
		return true, hasher
	}
	hasher.Close()
	fmt.Printf("  -> CPU is faster on this machine; using CPU.\n")
	return false, nil
}
