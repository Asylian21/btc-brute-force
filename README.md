# Bitcoin Address-Collision Research Toolkit

A fast, offline Go research tool for studying Bitcoin P2PKH address generation, benchmark reality, and the beautiful absurdity of the 2^160 search space.

This project is not a wallet cracker. It is a lab bench. You can run it, measure it, push the CPU hard, and still walk away with the same conclusion Bitcoin has relied on for years: the math is doing its job.

## Safety and Ethics

This toolkit is for education, performance research, and cryptographic intuition. Do not use it to attempt unauthorized access to funds or accounts. Brute forcing Bitcoin addresses is computationally infeasible, and trying to access assets you do not control is likely illegal.

The point is to make the impossible measurable. That is useful science. It is also a good antidote to internet mythology.

## Who This Is For

### Cryptography Students

See the full P2PKH pipeline in code: private scalar, secp256k1 public key, SHA256, RIPEMD160, Hash160 lookup, and Base58 address encoding.

### Security Educators

Turn "Bitcoin brute force is impossible" into a live demo with real numbers, checkpoints, and enough scale to make the lesson stick.

### Go Developers

Study a CPU-heavy Go workload with batched elliptic-curve addition, Montgomery batch inversion, SIMD SHA256, a specialized RIPEMD160 hot path, allocation-free worker buffers, checkpointing, and atomic counters.

## Quick Start

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

The demo is intentionally tiny. It exists so users can verify the program, not so anyone has to download a giant address database before seeing a single line of output.

### Normal Usage

```bash
make build
./bin/btc-brute-force [--checkpoint=path] [--resume] <threads> <output.txt> <addresses.txt>
```

The address file must contain one legacy mainnet P2PKH address per line, meaning addresses that start with `1`. Large local address lists, match outputs, and checkpoints are ignored by git.

```bash
./bin/btc-brute-force 8 matches.txt attack-addresses-p2pkh.txt
./bin/btc-brute-force --resume 8 matches.txt attack-addresses-p2pkh.txt
```

For a custom thread count in the demo, pass `THREADS`:

```bash
make run-example THREADS=4
```

### Pre-built Binaries

Download binaries from [Releases](https://github.com/Asylian21/btc-brute-force/releases) for:

- Linux (AMD64, ARM64)
- Windows (AMD64)
- macOS (Intel, Apple Silicon)

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

This version is a major performance and usability pass. The old loop was conceptually simple: generate a fresh random key, derive an address, Base58 compare, repeat until the universe gets bored.

The new loop is built like a proper research hot path:

1. **Batched secp256k1 walk**: each worker does one scalar multiplication for its starting point, then advances through consecutive keys with affine point addition (`P + iG`) using a precomputed table of generator multiples.
2. **Montgomery batch inversion**: the expensive field inversion in affine addition is amortized across a 2,048-key batch.
3. **Hash160 target set**: target addresses are decoded once at startup and stored as raw 20-byte Hash160 keys; Base58 encoding runs only if a generated hash matches.
4. **Specialized RIPEMD160**: Hash160 always feeds RIPEMD160 with a 32-byte SHA256 digest, so the hot path uses a single-block RIPEMD160 implementation verified against `golang.org/x/crypto/ripemd160`.
5. **Resume support**: long runs now write a checkpoint every 10 seconds and on clean interrupt, so progress can continue without losing segment positions.
6. **macOS build fix**: the Makefile uses external link mode on Darwin to avoid the `missing LC_UUID load command` issue seen with older Go toolchains on macOS 15+.

The goal is not to make Bitcoin brute force practical. The goal is to make the benchmark honest: remove avoidable overhead, measure the real bottlenecks, and still show that the search space wins by an absurd margin.

## Resuming (Checkpoints)

Each worker walks its own private-key sequence starting from a random base scalar
(`base, base+1, base+2, ...`). This is why the per-worker sample keys in the stats
output share a long common prefix that only changes at the end — consecutive keys
differ by 1, so the low bytes move first.

Because each worker advances an **independent** sequence (a "segment"), "where we
stopped" can't be captured by a single value. The program writes a JSON checkpoint
with the next private key for **every** segment, on the same 10-second cadence as
the stats line (plus once at startup and once on a clean `Ctrl+C`):

```json
{
  "version": 1,
  "updated_at": "2026-05-29T13:58:00Z",
  "threads": 8,
  "segments": 8,
  "key_batch_size": 2048,
  "total_keys": 1234567890,
  "workers": [
    { "id": 0, "next_private_key": "f0cf…82f9", "keys_processed": 1024000 },
    { "id": 1, "next_private_key": "a13b…0e77", "keys_processed": 1024000 }
  ]
}
```

- **Default file:** `checkpoint.json` in the working directory (override with `--checkpoint=path`).
- **Fresh run (default):** every worker starts from a new random key.
- **Resume:** add `--resume` to seed each worker from its saved `next_private_key`:

```bash
# Start a run (writes checkpoint.json every 10s)
btc-brute-force 8 matches.txt addresses.txt

# Later, continue exactly where it stopped
btc-brute-force --resume 8 matches.txt addresses.txt
```

### Changing the thread count between resumes

Segments are **decoupled from threads**, so you can change the CPU/thread count
between runs (e.g. `4 → 8 → 12 → 4`) without losing or corrupting anything:

| Situation                         | Behavior                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------ |
| `threads > saved segments`        | Resume all saved segments **and add** new random segments (set grows).         |
| `threads == saved segments`       | Resume everything (the common case).                                           |
| `threads < saved segments`        | Resume the first `threads`; the surplus segments are **preserved (frozen)** with their exact position and resume automatically when you next run with enough threads. |

So `total_keys` and the per-segment positions only ever move forward — the number
of tracked segments equals the **largest** thread count you've ever used.

Notes:

- Flags must come **before** the positional arguments (Go `flag` parsing stops at the first non-flag).
- The checkpoint is written atomically (temp file + rename) and is git-ignored (it's runtime state).
- A worker resumes by re-doing at most the last in-flight batch, so no keys are skipped.

## Benchmarks

Performance depends on CPU architecture, Go version, thermal state, worker count, and target-set size. The short version: the optimized code is fast enough to be interesting, and the Bitcoin address space is still astronomically larger.

See [BENCHMARKS.md](BENCHMARKS.md) for raw output and methodology.

**Current local benchmark (Apple Silicon / darwin arm64 / Go 1.22.5):**

- **Real MacBook Air M3 runtime:** sustained program throughput around **10 million keys/sec** with the optimized multi-worker hot path.
- `BenchmarkKeyStreamPerKey`: `532.6 ns/op`, `0 B/op`, `0 allocs/op`
- Approximate hot-path throughput: `1e9 / 532.6 = ~1.88M keys/sec` per benchmark worker
- `BenchmarkGenerateKeyAndHash160`: `28,833 ns/op`, showing the older fresh-scalar path is roughly `54x` slower than the batched walk
- `BenchmarkRIPEMD160Hash32`: `149.8 ns/op`, compared with `190.8 ns/op` for the streaming RIPEMD160 reference

**Reality check:** even at 10 million keys/sec, searching 1% of the 2^160 address space would take roughly `4.6 × 10^31` years.

The older per-key scalar-multiplication benchmark is still useful for teaching the naive pipeline. The new `BenchmarkKeyStreamPerKey` is the microbenchmark that best represents the optimized worker hot path. The headline **10M keys/sec** figure is measured from the running program across multiple workers on a MacBook Air M3.

### Getting Good Numbers

1. **Threads** — set to your physical CPU core count (e.g. `8` on an 8-core machine). Hyperthreading usually adds little for this workload.
2. **Build** — `make build` (on macOS 15+, the Makefile uses `-linkmode=external` so binaries run under dyld; Go 1.24+ fixes this without external linking).
3. **Long runs** — optional `BTC_BRUTE_GC=400` reduces GC pauses during sustained execution.
4. **Input format** — provide clean P2PKH address lists; invalid or non-P2PKH lines are skipped during startup parsing.
5. **Measure sustained rates** — trust the 10-second stats lines and longer benchmarks more than startup output.

Run benchmarks yourself:

```bash
make bench
# or
go test -ldflags="-s -w -linkmode=external" -bench=. -benchmem -benchtime=5s . ./bench/...
```

## How It Works

The optimized worker follows this pipeline:

1. **Seed worker segment**: generate one random secp256k1 scalar per worker.
2. **Build batch points**: advance consecutive private keys with `P + iG` affine addition instead of fresh scalar multiplication per key.
3. **Hash compressed public keys**: SHA256 via `minio/sha256-simd`, then specialized single-block RIPEMD160.
4. **Lookup Hash160**: compare the 20-byte hash against the target set in O(1).
5. **On match only**: reconstruct the private key, encode the matching P2PKH address, print it, and append `<private_key_hex>:<address>` to the output file.

The whole loop runs completely **offline**. No RPC node, no API, no network magic. Just math, fans, and existential scale.

**Not a wallet. Not a puzzle solver.** This is a clean Go toolkit for education, reproducible benchmarks, and reality-checking brute-force limits.

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

## FAQ

### Why doesn't brute force work?

The P2PKH address hash space is 2^160, or about `1.46 × 10^48` possible hashes. Even at 10 million keys/second, searching 1% of that space is still roughly `4.6 × 10^31` years of work.

That is not "needs a bigger server" hard. That is "the heat death of your project plan" hard.

### How to measure keys/sec correctly?

Use batch counters and sustained windows. Startup output is noisy; the 10-second stats line is much more meaningful.

For this version, use `BenchmarkKeyStreamPerKey` for the optimized worker hot path. The older `bench/` package still measures educational components such as Base58 and the naive key/hash pipeline.

### What's the probability of finding a match?

With roughly 50 million funded addresses and 2^160 possible Hash160 values, the probability per random guess is about `3.4 × 10^-41`. In human terms: effectively zero.

### Can GPUs speed this up?

Yes. GPUs can add serious throughput. They do not change the scale of the search space. Even at 1 billion keys/sec, the answer is still measured in absurd cosmic time.

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

See [COMPARISON.md](COMPARISON.md) for project philosophy and contribution guidelines.

## Related Article

**[Brute Force vs Reality: What My Bitcoin Brute Force Really Shows](https://medium.com/@asylian21/brute-force-vs-reality-what-my-bitcoin-brute-force-really-shows-67872323d6bf)**

An in-depth Medium article explaining the mathematics, benchmarks, and reality-check behind this toolkit.

## Acknowledgments

- **btcsuite** – Bitcoin libraries for Go
- **minio/sha256-simd** – SIMD-accelerated SHA256 implementation
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

## Support This Project

If this project helped you understand Bitcoin security, benchmark Go code, or win an argument with a brute-force enthusiast, you can support continued research here:

**Bitcoin donation address:**

```
bc1q9c5mmx9d3ajevjrvvw9yf52jclsre8x86qhnak
```

Every satoshi helps fund more experiments, better documentation, and fewer hand-wavy claims about cryptography.
