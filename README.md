# Bitcoin Address-Collision Research Toolkit

**aka 'Bitcoin Address-Collision Research'**

Educational Bitcoin address-collision research toolkit (Go). Benchmarks, math, why brute force is infeasible. This toolkit demonstrates bitcoin brute force, address collision mathematics, brainwallet security, and secp256k1 limits through hands-on code and reproducible benchmarks.

## ⚠️ Safety & Ethics

**This project is for education and research. Bitcoin address brute force is computationally infeasible. Do not use this software to attempt unauthorized access. The code illustrates mathematics and performance characteristics only.**

This toolkit exists to demonstrate **why** Bitcoin's cryptography is secure, not to provide a practical attack vector. Attempting to access funds from addresses you don't control is likely illegal in most jurisdictions.

## Who is this for?

### Cryptography Students

Understand hash160 operations and the vastness of the 2^160 vs 2^256 address space. Learn how Bitcoin addresses are derived from private keys through SHA256, RIPEMD160, and Base58 encoding.

### Security Educators

Demonstrate brute-force infeasibility in lectures and workshops. Use real benchmark data to show why cryptographic security works at scale.

### Go Developers

Benchmark hash pipeline and encoding performance. Study optimized Go code using SIMD acceleration, buffer pooling, and atomic operations.

## Quick Start

### Go Install

If you have Go installed:

```bash
go install github.com/Asylian21/btc-brute-force/cmd/btc-brute-force@latest
```

Then run:

```bash
btc-brute-force <threads> <output.txt> <addresses.txt>
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

## Benchmarks

Performance varies by CPU architecture and generation. See [BENCHMARKS.md](BENCHMARKS.md) for detailed results.

**Summary:**

- **Apple Silicon (M1/M2/M3)**: ~15,000-20,000 keys/sec per core
- **Modern AMD64 (Intel/AMD 2020+)**: ~20,000-50,000 keys/sec per core
- **Older CPUs**: ~5,000-15,000 keys/sec per core

**Example:** 8 cores × 20,000 keys/sec = ~160,000 keys/sec total

**Reality check:** Even at 1 million keys/sec, searching 1% of the 2^160 address space would take ~3.5 × 10^38 years.

Run benchmarks yourself:

```bash
make bench
# or
go test -bench=. -benchmem ./bench
```

## How it works

The toolkit follows a simple hash160 pipeline:

1. **Generate private key**: Cryptographically secure 256-bit random number
2. **Derive public key**: SECP256k1 elliptic curve multiplication
3. **Hash public key**: `RIPEMD160(SHA256(pubkey))` → 20-byte hash160
4. **Add version byte**: 0x00 for mainnet P2PKH
5. **Calculate checksum**: First 4 bytes of `SHA256(SHA256(version + hash160))`
6. **Base58 encode**: Human-readable address (starts with '1')

This entire pipeline runs completely **offline** - no network access required for the core loop.

**Not a wallet, not a 'puzzle solver';** clean Go toolkit for education, reproducible benchmarks, and reality-check of brute-force limits.

See [COMPARISON.md](COMPARISON.md) for detailed positioning and comparison with similar projects.

## Comparison

This toolkit focuses on **education and benchmarking**, not cracking wallets or solving puzzles.

| Aspect           | This Toolkit         | Wallet Software | Puzzle Solvers         |
| ---------------- | -------------------- | --------------- | ---------------------- |
| **Goal**         | Education & Research | Manage Bitcoin  | Solve specific puzzles |
| **Offline**      | ✅ Yes               | ❌ No           | ✅ Yes                 |
| **Focus**        | Benchmarks, Math     | Transactions    | Targeted search        |
| **Success Rate** | Effectively zero     | N/A             | Varies                 |

See [COMPARISON.md](COMPARISON.md) for a detailed comparison table.

## FAQ

### Why doesn't brute force work?

The address space is 2^160 ≈ 1.46 × 10^48 possible addresses. Even at 1 million keys/second, you'd need approximately 10^35 years to search 1% of the space. The probability per guess is ~3.4 × 10^-41 (effectively zero).

### How to measure keys/sec correctly?

Use atomic counters with batch updates (e.g., update every 10,000 iterations). Measure over sustained periods (10+ seconds) to avoid startup/GC noise. See `bench/bench_test.go` for reference implementation.

### What's the probability of finding a match?

With ~50 million funded addresses and 2^160 total addresses, probability per guess ≈ 3.4 × 10^-41. You're more likely to be struck by lightning while winning the lottery.

### Can GPUs speed this up?

Yes, GPUs could theoretically provide 100-1000x speedup. However, even at 1 billion keys/sec, you'd still need 10^31 years. The scale of the problem doesn't change.

### What if quantum computers break this?

Quantum computers with sufficient qubits could break ECDSA using Shor's algorithm, but that's separate from brute forcing. Bitcoin would need quantum-resistant cryptography before that becomes a concern.

### Is this illegal?

The software itself is legal for research and education. However, attempting to access or move funds from addresses you don't control is likely illegal in most jurisdictions. Know your local laws.

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

Contributions welcome for:

- Additional benchmark results from different hardware
- Performance optimizations (with documentation)
- Educational documentation improvements
- Code clarity and documentation

See [COMPARISON.md](COMPARISON.md) for project philosophy and contribution guidelines.

## Related Article

📖 **[Brute Force vs Reality: What My Bitcoin Brute Force Really Shows](https://medium.com/@asylian21/brute-force-vs-reality-what-my-bitcoin-brute-force-really-shows-67872323d6bf)**

An in-depth Medium article explaining the mathematics, benchmarks, and reality-check behind this toolkit.

## 🙏 Acknowledgments

- **btcsuite** – Bitcoin libraries for Go
- **minio/sha256-simd** – SIMD-accelerated SHA256 implementation
- **Bitcoin developers** – For creating cryptographically secure money

---

**Remember:** If brute forcing Bitcoin were practical, Bitcoin would be worthless. The fact that Bitcoin has value is proof that this doesn't work at scale.

Built with respect for the Bitcoin ecosystem and inspired by:

- Satoshi Nakamoto and the Bitcoin protocol
- The cypherpunk movement
- Open-source cryptography researchers
- The Bitcoin developer community

---

<p align="center">
  <strong>Made with ❤️ by Asylion21 (David Zita)</strong><br>
  <em>Building tools for Bitcoin's next century</em>
</p>

---

## ₿ Support This Project

If you find this work valuable, consider supporting development:

**Bitcoin Address (Taproot):**

```
bc1phd6c0znnl0jjnf734svg6z67cr4jet4je889uvk6yqawdcj4djhsj746n3
```

Every satoshi helps fund continued research and development of Bitcoin security tools.
