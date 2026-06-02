# Bitcoin Address-Collision Research Toolkit

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![CI](https://github.com/Asylian21/btc-brute-force/actions/workflows/ci.yml/badge.svg)](https://github.com/Asylian21/btc-brute-force/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Asylian21/btc-brute-force?include_prereleases&label=release)](https://github.com/Asylian21/btc-brute-force/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**btc-brute-force** is a fast, offline Go research toolkit for studying Bitcoin P2PKH address generation, Hash160 matching, secp256k1 performance, and the mathematical reality of the 2^160 Bitcoin address-collision search space.

It is designed for cryptography education, Bitcoin security demonstrations, and reproducible Go performance benchmarks. It is not a wallet cracker, recovery product, or theft tool. You can run it, measure it, push the CPU hard, and still walk away with the same conclusion Bitcoin has relied on for years: the math is doing its job.

No cloud account, no API key, no node, no network dependency. Just local code, local CPU, and very large numbers.

## Repository Topics

`bitcoin` · `bitcoin-security` · `cryptography` · `secp256k1` · `hash160` · `p2pkh` · `brute-force` · `address-collision` · `go` · `golang` · `benchmark` · `performance-engineering` · `offline-tool`

## Table of Contents

- [Safety and Ethics](#safety-and-ethics)
- [Who This Is For](#who-this-is-for)
- [Quick Start](#quick-start-)
- [What Changed in This Version](#what-changed-in-this-version)
- [Benchmarks](#benchmarks-)
- [How It Works](#how-it-works)
- [FAQ](#faq-)
- [Comparison](#comparison)
- [Releases](#releases)
- [Contributing](#contributing)
- [Related Article](#related-article)

## Safety and Ethics

This toolkit is for education, performance research, and cryptographic intuition. Do not use it to attempt unauthorized access to funds or accounts. Brute forcing Bitcoin addresses is computationally infeasible, and trying to access assets you do not control is likely illegal.

The point is to make the impossible measurable. That is useful science, and a useful antidote to overconfident claims about "secret brute-force methods."

## Key Features

- **Offline Bitcoin address-collision lab** for legacy mainnet P2PKH addresses (`1...`) with no RPC, API, wallet import, or network access.
- **Optimized Go hot path** using batched secp256k1 affine walks, GLV endomorphism, point negation, Montgomery batch inversion, raw Hash160 lookup, and allocation-free worker buffers.
- **Fused multi-buffer HASH160 pipeline** with vectorized SHA-256 (`sha256mb`) feeding multi-buffer RIPEMD-160 (`ripemd160-asm`) for realistic cryptographic throughput measurements.
- **Apple Metal GPU acceleration** (Apple Silicon): auto-enabled, bit-exact GPU Hash160 offload with zero-copy unified-memory buffers and a CPU/GPU producer–consumer pipeline — ~120M keys/sec on an M3 (~2.7–2.9x the CPU path), with transparent CPU fallback and startup calibration so it never regresses.
- **Systematic resumable scan** from private key `1`, with checkpointed scan-frontier state that works across thread-count changes (and across CPU/GPU modes).
- **Honest security education** showing why Bitcoin brute force and broad address-collision search remain computationally infeasible even after serious optimization.
- **Reproducible benchmarks** for Go, secp256k1, SHA-256, RIPEMD-160, Hash160, Base58, and Bitcoin address-generation performance.

## Search Keywords

Bitcoin brute force research, Bitcoin address collision, Bitcoin address-collision benchmark, Bitcoin P2PKH generator, Bitcoin Hash160 lookup, secp256k1 benchmark Go, Go cryptography benchmark, offline Bitcoin address scanner, Bitcoin private key search space, RIPEMD160 SHA256 Hash160, Bitcoin security education, why Bitcoin brute force is impossible.

## Who This Is For

### Cryptography Students

See the full P2PKH pipeline in code: private scalar, secp256k1 public key, SHA256, RIPEMD160, Hash160 lookup, and Base58 address encoding.

### Security Educators

Turn "Bitcoin brute force is impossible" into a live demo with real numbers, checkpoints, and enough scale to make the lesson stick.

### Go Developers

Study a CPU-heavy Go workload with batched elliptic-curve addition, Montgomery batch inversion, a fused multi-buffer HASH160 hot path (vectorized SHA-256 + RIPEMD-160), allocation-free worker buffers, checkpointing, and atomic counters.

## Quick Start ⚡

### The "I Just Want To See It Run" Demo

If Go is installed, this is the whole first-run experience:

```bash
git clone https://github.com/Asylian21/btc-brute-force.git
cd btc-brute-force
make run-example
```

That command builds the binary and starts a tiny bundled demo against `example-addresses.txt`, a public list of 20 legacy P2PKH addresses. You will see target loading, throughput stats every 10 seconds, and a sample checked key/address pair.

Stop it with `Ctrl+C`. The demo writes `example-checkpoint.json`, so continuing is also one command:

```bash
make resume-example
```

The demo is intentionally tiny: 20 addresses, zero drama. It exists so users can verify the program before downloading any serious target list.

### Normal Usage

```bash
make build
./bin/btc-brute-force [--checkpoint=path] [--resume] [--gpu=auto|on|off] <threads> <output.txt> <addresses.txt>
```

The address file must contain one legacy mainnet P2PKH address per line, meaning addresses that start with `1`. Large local address lists, match outputs, and checkpoints are ignored by git.

```bash
./bin/btc-brute-force 8 matches.txt attack-addresses-p2pkh.txt
./bin/btc-brute-force --resume 8 matches.txt attack-addresses-p2pkh.txt
```

#### GPU acceleration (Apple Silicon)

On a Mac with Apple Silicon, `make build` produces a Metal-enabled binary and
the GPU Hash160 offload is **auto-enabled** — on startup the program runs a
bit-exact self-test against `btcutil.Hash160` and a short calibration, then
picks the faster backend (so it never runs slower than the CPU path). Control it
with `--gpu`:

```bash
./bin/btc-brute-force --gpu=auto 8 matches.txt addresses.txt   # default: GPU if faster
./bin/btc-brute-force --gpu=on   8 matches.txt addresses.txt   # force GPU (fatal if unavailable)
./bin/btc-brute-force --gpu=off  8 matches.txt addresses.txt   # CPU only
```

Requirements: macOS on Apple Silicon, built natively with cgo (the default for
`make build` / `make bench-gpu`). Other platforms — and the `make build-cpu`
(`-tags=nometal`) build — transparently use the CPU path. Tune the pipeline with
`BTC_GPU_PRODUCERS` and `BTC_GPU_CHUNKS` if needed. See [BENCHMARKS.md](BENCHMARKS.md#gpu-apple-metal-hash160-offload).

For a custom thread count in the demo, pass `THREADS`:

```bash
make run-example THREADS=4
```

### Pre-built Binaries

Download binaries from [Releases](https://github.com/Asylian21/btc-brute-force/releases) for:

- Linux (AMD64, ARM64)
- Windows (AMD64)
- macOS (Intel, Apple Silicon — the Apple Silicon build is compiled natively with cgo and ships the **Metal GPU** Hash160 path; Intel is CPU-only)

**Example (Linux):**

```bash
# Download and extract
wget https://github.com/Asylian21/btc-brute-force/releases/download/v0.1.0/btc-brute-force-v0.1.0-linux-amd64
chmod +x btc-brute-force-v0.1.0-linux-amd64

# Run
./btc-brute-force-v0.1.0-linux-amd64 8 output.txt attack-addresses-p2pkh.txt
```

### Docker

Run using Docker:

```bash
docker run --rm ghcr.io/asylian21/btc-brute-force:latest --help
```

Or build locally:

```bash
docker build -t btc-brute-force .
docker run --rm -v $(pwd):/data btc-brute-force 8 /data/output.txt /data/attack-addresses-p2pkh.txt
```

## What Changed in This Version

This version is a major performance and usability pass. The old loop was conceptually simple: generate a fresh random key, derive an address, Base58 compare, repeat until the calendar gives up.

The new loop is built like a proper research hot path:

1. **Batched secp256k1 walk**: a worker does one scalar multiplication per claimed chunk to land on its starting point, then advances through consecutive keys with affine point addition (`P + iG`) using a precomputed table of generator multiples.
2. **GLV endomorphism + point negation**: every affine point `(x, y)` yields SIX valid keys — the three endomorphism x-values `(x, beta*x, beta^2*x)` (scalars `k`, `lambda*k`, `lambda^2*k`), each in both point-negation parities (`-P = (x, -y)`, scalar `n-k`) — for just 2 field multiplies, since negation is a free `02/03` prefix flip (`y` is never serialized). That checks 6 keys per field inversion instead of 2; the scalars are reconstructed only on the rare match path. The `beta`/`lambda` constants and all six variants are verified end-to-end at startup, so a wrong constant or slot mismatch fails fast instead of silently missing matches.
3. **Montgomery batch inversion**: the expensive field inversion in affine addition is amortized across a 1,024-step batch (6,144 keys after the 6x endomorphism + negation expansion).
4. **Fast secp256k1 Fp field backend**: the per-key base-field arithmetic — the dominant CPU cost of the walk — runs on [`secp256k1-field`](https://github.com/Asylian21/secp256k1-field), a 5x52-limb implementation with arm64/amd64 assembler kernels, replacing dcrd's pure-Go 10x26 `FieldVal`. It is bit-identical to dcrd (differential-fuzzed) and roughly **doubles** the single-thread hot-loop throughput (see [BENCHMARKS.md](BENCHMARKS.md)).
5. **Hash160 target set**: target addresses are decoded once at startup and stored as raw 20-byte Hash160 keys; Base58 encoding runs only on the rare match path.
6. **Fused multi-buffer HASH160 with zero-copy output**: the whole batch's compressed pubkeys are hashed by one `hash160mb.FromPubkeys33` call — vectorized SHA-256 from [`sha256mb`](https://github.com/Asylian21/sha256mb) (arm64 `sha2x4` interleaves four messages through the ARMv8 hardware-SHA instructions, ~2.6x scalar) feeding multi-buffer RIPEMD-160 from [`ripemd160-asm`](https://github.com/Asylian21/ripemd160-asm). It is verified bit-for-bit against `crypto/sha256` + `golang.org/x/crypto/ripemd160` (the `btcutil.Hash160` algorithm) and writes its 20-byte digests straight into the result slice — no intermediate buffer or per-key scatter copy. Replacing the old per-key `minio/sha256-simd` calls lifted runtime throughput **+18.7%** at 8 threads (see [BENCHMARKS.md](BENCHMARKS.md)).
7. **Systematic, resumable scan**: the key space is swept in order from key `1` in fixed contiguous chunks handed out by a single global cursor, so no key is ever skipped — no matter how many threads run, or how that count changes between runs. A checkpoint storing a single frontier position is written every 10 seconds and on clean interrupt, so progress continues exactly where it stopped.
8. **macOS build fix**: the Makefile uses external link mode on Darwin to avoid the `missing LC_UUID load command` issue seen with older Go toolchains on macOS 15+.

The goal is not to make Bitcoin brute force practical. The goal is to make the benchmark honest: remove avoidable overhead, measure the real bottlenecks, and still show that the search space wins by an absurd margin.

## Resuming (Checkpoints) 💾

The key space is scanned **systematically from private key `1` upward**, with a
hard guarantee that **no key is ever skipped** — regardless of how many worker
threads you use, and even if you change that count between runs.

To make this robust, work is **not** split into one fixed range per thread.
Instead the space is divided into fixed contiguous **chunks**; a single global
cursor hands out the next chunk, and every worker simply claims the next
unclaimed chunk and walks it in order. Threads are interchangeable: with `N`
workers, `N` chunks are processed at once.

Because chunks are handed out in increasing order and each is walked
start-to-finish, the lowest chunk still in progress is a **frontier**: every key
below it is done. The checkpoint stores exactly that single frontier key, on the
same 10-second cadence as the stats line (plus once at startup and once on a
clean `Ctrl+C`):

```json
{
  "version": 2,
  "updated_at": "2026-05-31T17:16:20Z",
  "threads": 8,
  "chunk_steps": 16384,
  "key_batch_size": 1024,
  "next_private_key": "0000000000000000000000000000000000000000000000000000000000000001",
  "total_keys": 0
}
```

- **`next_private_key`** — the frontier: every key below it has been checked; the scan resumes here.
- **`total_keys`** — keys checked up to the frontier (`endoFactor` per linear key); derived from the frontier, so it only moves forward.
- **Default file:** `checkpoint.json` in the working directory (override with `--checkpoint=path`).
- **Fresh run (default):** the scan starts at key `1`.
- **Resume:** add `--resume` to continue from the saved frontier:

```bash
# Start a run (writes checkpoint.json every 10s)
btc-brute-force 8 matches.txt addresses.txt

# Later, continue exactly where it stopped — with ANY thread count
btc-brute-force --resume 4 matches.txt addresses.txt
```

### Changing the thread count between resumes

The scan is **thread-count agnostic**. The checkpoint stores a single frontier,
not per-thread state, so you can freely change the CPU/thread count between runs
(e.g. `4 → 8 → 12 → 4`). More threads simply process more chunks at once; fewer
threads process fewer. Coverage and the no-skip guarantee are unaffected — a
resume re-checks at most `threads × chunk_steps` keys (cheap and idempotent) and
never skips one.

Notes:

- Flags must come **before** the positional arguments (Go `flag` parsing stops at the first non-flag).
- The checkpoint is written atomically (temp file + rename) and is git-ignored (it's runtime state).
- Private key `0` is the secp256k1 point at infinity (invalid), so the scan begins at `1`, never `0`.
- The GLV endomorphism still emits 6 keys per step, but only the linear key advances the contiguous frontier; the other 5 are bonus checks of scattered keys and can never create a gap.
- Checkpoints written by the old per-segment format (`version 1`) are not compatible; delete the file to start a fresh systematic scan.

## Benchmarks 📊

Performance depends on CPU architecture, Go version, thermal state, worker count, and target-set size. The short version: the optimized code is fast enough to be interesting, and the Bitcoin address space is still astronomically larger.

**~45.1 million keys/sec is impressive. 2^160 remains undefeated.**

See [BENCHMARKS.md](BENCHMARKS.md) for raw output and methodology.

**Current local benchmark (Apple Silicon / darwin arm64 / Go 1.22.5):**

- **Real MacBook Air M3 runtime:** latest sustained 8-thread program output reached about **45.1 million keys/sec** — **+18.7%** over the ~38.0M pre-`sha256mb` baseline in a back-to-back A/B, after routing HASH160 through the vectorized multi-buffer SHA-256 + RIPEMD-160 pipeline. The same generation sustains around **26 million keys/sec at 4 threads** (that 4-thread figure predates the SHA-256 work; it was itself up from ~19.9M under the previous endoFactor=2 design, ~1.33x).
- `BenchmarkKeyStreamPerKey`: `118.5 ns/op`, `0 B/op`, `0 allocs/op` — the amortized cost **per checked key** across all six GLV+negation variants (down from `136.7 ns/op`, **−13.35%** by `benchstat`, after the SHA-256 vectorization).
- Approximate hot-path throughput: `1e9 / 118.5 = ~8.4M keys/sec` per benchmark worker.
- **Multi-buffer SHA-256 gain:** SHA-256 was ~23% of the per-key cost; `sha256mb`'s arm64 `sha2x4` kernel hashes it ~2.6x faster, which Amdahl's law turns into the measured ~−13% per-key and **+18.7%** at 8 threads.
- `BenchmarkGenerateKeyAndHash160`: `29,105 ns/op`, showing the older fresh-scalar path is roughly `245x` slower per key than the batched walk.

**Progress snapshot:** the hot path now checks six real compressed-public-key variants for every computed affine point, hashes the whole batch through a fused multi-buffer HASH160 (vectorized SHA-256 → RIPEMD-160) with zero-copy output, avoids hot-loop allocations, and records a single resumable scan frontier through checkpoints. The runtime benchmark is no longer dominated by per-key scalar multiplication or per-key SHA-256; it is mostly measuring the remaining RIPEMD-160 and field arithmetic, target lookup, and scheduler cost.

**Reality check:** even at **~45.1 million keys/sec**, searching 1% of the 2^160 address space would take roughly `1.03 × 10^31` years.

The older per-key scalar-multiplication benchmark is still useful for teaching the naive pipeline. The new `BenchmarkKeyStreamPerKey` is the microbenchmark that best represents the optimized worker hot path. The headline **~45.1 million keys/sec** figure is measured from the running program across 8 workers on a MacBook Air M3.

### Getting Good Numbers

1. **Threads** — set to your physical CPU core count (e.g. `8` on an 8-core machine). Hyperthreading usually adds little for this workload.
2. **Build** — `make build` (on macOS 15+, the Makefile uses `-linkmode=external` so binaries run under dyld; Go 1.24+ fixes this without external linking).
3. **Long runs** — optional `BTC_BRUTE_GC=400` reduces GC pauses during sustained execution.
4. **Input format** — provide clean P2PKH address lists; invalid or non-P2PKH lines are skipped during startup parsing.
5. **Measure sustained rates** — trust the 10-second stats lines and longer benchmarks more than startup output. CPUs, like researchers, need a warm-up period.

Run benchmarks yourself:

```bash
make bench
# or
go test -ldflags="-s -w -linkmode=external" -bench=. -benchmem -benchtime=5s . ./bench/...
```

## How It Works

The optimized worker follows this pipeline:

1. **Claim a chunk**: take the next contiguous chunk of the key space from the shared cursor and rebase to its first key with one scalar multiplication.
2. **Build batch points**: advance consecutive private keys with `P + iG` affine addition instead of fresh scalar multiplication per key.
3. **Expand via endomorphism + negation**: from each point `(x, y)`, derive six keys — `(x, beta*x, beta^2*x)` (scalars `k`, `lambda*k`, `lambda^2*k`), each in both parities (`(x, -y)`, scalar `n-k`) — for 2 field multiplies (negation is a free `02/03` prefix flip).
4. **Hash compressed public keys**: one fused multi-buffer HASH160 pass — vectorized SHA-256 (`sha256mb`, arm64 4-lane hardware-SHA) feeding multi-buffer RIPEMD-160 (`ripemd160-asm`, NEON) — that writes Hash160s directly into the result slice.
5. **Lookup Hash160**: compare the 20-byte hash against the target set in O(1).
6. **On match only**: reconstruct the private key for the matching variant (`k`, `n-k`, `lambda*k`, `n-lambda*k`, `lambda^2*k`, or `n-lambda^2*k`), encode the matching P2PKH address, print it, and append `<private_key_hex>:<address>` to the output file.

The whole loop runs completely **offline**. No RPC node, no API, no network magic. Just math, fans, and scale.

**Not a wallet. Not a puzzle solver. Not a miracle recovery tool.** This is a clean Go toolkit for education, reproducible benchmarks, and reality-checking brute-force limits.

See [COMPARISON.md](COMPARISON.md) for detailed positioning and comparison with similar projects.

## Comparison

This toolkit focuses on **education and benchmarking**, not cracking wallets or solving puzzles.

| Aspect           | This Toolkit         | Wallet Software | Puzzle Solvers         |
| ---------------- | -------------------- | --------------- | ---------------------- |
| **Goal**         | Education & Research | Manage Bitcoin  | Solve specific puzzles |
| **Offline**      | Yes                  | No              | Yes                    |
| **Focus**        | Benchmarks, Math     | Transactions    | Targeted search        |
| **Success Rate** | Effectively zero     | N/A             | Varies                 |

See [COMPARISON.md](COMPARISON.md) for a detailed comparison table.

## FAQ ❓

### Why doesn't brute force work?

The P2PKH address hash space is 2^160, or about `1.46 × 10^48` possible hashes. Even at **~45.1 million keys/second**, searching 1% of that space is still roughly `1.03 × 10^31` years of work.

That is not "needs a bigger server" hard. That is "your project manager should not put this in the sprint" hard.

### How to measure keys/sec correctly?

Use batch counters and sustained windows. Startup output is noisy; the 10-second stats line is much more meaningful.

For this version, use `BenchmarkKeyStreamPerKey` for the optimized worker hot path. The older `bench/` package still measures educational components such as Base58 and the naive key/hash pipeline.

### What's the probability of finding a match?

With roughly 50 million funded addresses and 2^160 possible Hash160 values, the probability per random guess is about `3.4 × 10^-41`. In human terms: effectively zero. Luck is not a scaling strategy.

### Can GPUs speed this up?

Yes — and this project does it on Apple Silicon. The Metal backend offloads the Hash160 (the ~80% hashing bottleneck) to the GPU with zero-copy unified-memory buffers, reaching ~120M keys/sec on an M3 (~2.7–2.9x the CPU path). See [GPU acceleration](#gpu-acceleration-apple-silicon) and [BENCHMARKS.md](BENCHMARKS.md#gpu-apple-metal-hash160-offload). GPUs add serious throughput but do **not** change the scale of the search space: even at billions of keys/sec, the answer is still measured in absurd cosmic time.

### What if quantum computers break this?

Quantum computers with sufficient qubits could break ECDSA using Shor's algorithm, but that's separate from brute forcing. Bitcoin would need quantum-resistant cryptography before that becomes a concern.

### Is this illegal?

The software itself is for research and education. Attempting to access or move funds from addresses you do not control is likely illegal in most jurisdictions. Know your local laws and keep the lab coat on.

## Releases

Pre-built binaries are available in [GitHub Releases](https://github.com/Asylian21/btc-brute-force/releases).

**Installation from release:**

1. Download the binary for your platform
2. Make it executable: `chmod +x btc-brute-force-v*`
3. Run: `./btc-brute-force-v* <threads> <output.txt> <addresses.txt>`

**Building from source:**

```bash
git clone https://github.com/Asylian21/btc-brute-force.git
cd btc-brute-force
make build
```

## GitHub Discoverability

For the best GitHub and search-engine preview, use this repository metadata:

- **Description:** `Offline Bitcoin address-collision research toolkit and Go benchmark for P2PKH, Hash160, secp256k1, SHA-256, RIPEMD-160, and brute-force infeasibility demos.`
- **Website:** `https://medium.com/@asylian21/brute-force-vs-reality-what-my-bitcoin-brute-force-really-shows-67872323d6bf`
- **Topics:** `bitcoin`, `bitcoin-security`, `cryptography`, `secp256k1`, `hash160`, `p2pkh`, `brute-force`, `address-collision`, `go`, `golang`, `benchmark`, `performance-engineering`, `offline-tool`
- **Social preview:** generate and upload `docs/social-preview.png`; see [`docs/SOCIAL_PREVIEW_INSTRUCTIONS.md`](docs/SOCIAL_PREVIEW_INSTRUCTIONS.md).

## License

MIT License

```
Copyright (c) 2024 David Zita

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing

Useful contributions are very welcome:

- Additional benchmark results from different hardware
- Performance optimizations with before/after numbers
- Educational documentation improvements
- Tests that protect the cryptographic hot path
- Clear explanations that help people understand why the attack still does not work
- Pull requests welcome; wallet-cracking feature requests will be politely shown the door

See [COMPARISON.md](COMPARISON.md) for project philosophy and contribution guidelines.

## Related Article

**[Brute Force vs Reality: What My Bitcoin Brute Force Really Shows](https://medium.com/@asylian21/brute-force-vs-reality-what-my-bitcoin-brute-force-really-shows-67872323d6bf)**

An in-depth Medium article explaining the mathematics, benchmarks, and reality-check behind this toolkit.

## Acknowledgments

- **btcsuite** – Bitcoin libraries for Go
- **decred/dcrd** – secp256k1 scalar arithmetic and point multiplication
- **[Asylian21/secp256k1-field](https://github.com/Asylian21/secp256k1-field)** – fast secp256k1 base-field (Fp) arithmetic with arm64/amd64 assembler
- **[Asylian21/sha256mb](https://github.com/Asylian21/sha256mb)** – multi-buffer SHA-256 (arm64 hardware-SHA) and fused HASH160 hot path
- **[Asylian21/ripemd160-asm](https://github.com/Asylian21/ripemd160-asm)** – multi-buffer SIMD RIPEMD160
- **minio/sha256-simd** – SIMD-accelerated SHA256 (now only the address checksum / decode path)
- **Bitcoin developers** – For creating cryptographically secure money

---

**Remember:** if brute forcing Bitcoin were practical, Bitcoin would already be worthless. The fact that Bitcoin has value is part of the experiment result.

Built with respect for the Bitcoin ecosystem and inspired by:

- Satoshi Nakamoto and the Bitcoin protocol
- The cypherpunk movement
- Open-source cryptography researchers
- The Bitcoin developer community

---

<p align="center">
  <strong>Made by Asylion21 (David Zita)</strong><br>
  <em>Building tools for Bitcoin's next century</em>
</p>

---

## Support This Project ₿

If this project helped you understand Bitcoin security, benchmark Go code, or explain why brute force is not a business model, you can support continued research here:

**Bitcoin donation address:**

```
bc1q9c5mmx9d3ajevjrvvw9yf52jclsre8x86qhnak
```

Every satoshi helps fund more experiments, better documentation, and fewer hand-wavy claims about cryptography.
