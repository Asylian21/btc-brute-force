// Package main implements btc-brute-force, an offline Bitcoin address-collision
// research toolkit and command-line benchmark for P2PKH address generation,
// Hash160 matching, secp256k1 point arithmetic, SHA-256, RIPEMD-160, and Go
// performance engineering.
//
// The program is intentionally framed as a Bitcoin security education and
// cryptography research tool. It demonstrates why broad Bitcoin brute force is
// computationally infeasible while still providing measurable, reproducible
// benchmarks for the real P2PKH pipeline:
//
//	private scalar -> secp256k1 public key -> SHA-256 -> RIPEMD-160 -> Hash160 -> Base58 P2PKH address
//
// The optimized worker uses batched affine secp256k1 walks, GLV endomorphism,
// point negation, Montgomery batch inversion, raw Hash160 target lookups, a
// fused multi-buffer HASH160 hot path, allocation-free worker buffers, and a
// checkpointed scan frontier.
//
// On Apple Silicon it additionally auto-enables a hybrid Apple Metal GPU
// pipeline: the CPU runs the batched walk and feeds base public keys to the
// device, which expands the six GLV+negation variants, hashes them, and tests
// them against an on-device Bloom filter (zero false negatives) with atomic
// candidate compaction, all bit-exact over zero-copy unified memory. A startup
// self-test and calibration pick the faster backend, and a kept-but-experimental
// full on-GPU EC walk (gpu/metal/ec_walk.metal) lives behind the same self-test.
// Non-darwin and -tags=nometal builds compile the GPU out and use the CPU path.
//
// This package is not wallet software, a recovery service, or a practical
// cracking tool. It runs offline and exists for education, benchmarking, and
// reality-checking claims about Bitcoin private-key search.
package main
