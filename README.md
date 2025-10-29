# Bitcoin Brute Force / Address Collision Research Toolkit

This project is a high-performance Bitcoin address collision research toolkit. People on the internet often call this "Bitcoin brute forcing." **Reality check:** Bitcoin's cryptography is designed so that "brute forcing a wallet" is effectively impossible in practice. This code exists for education, benchmarking, and understanding why Bitcoin is secure – not for stealing funds.

**⚠️ Legal / Ethical Notice:**

This software is for **educational and research use only**. Do not attempt to access, move, or claim funds from any address you do not control. You are solely responsible for what you run. The authors take no responsibility for misuse of this software.

---

## 🚀 Quick Start - Get Running in 3 Steps

Choose your platform and follow the steps. The program will start immediately with a small test address list included.

### 🍎 macOS

**Step 1:** Open Terminal (press `Cmd + Space`, type "Terminal", press Enter)

**Step 2:** Navigate to the project folder and build:

```bash
cd /path/to/bitcoin-bruteforce
go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

**Step 3:** Run the program (using 8 threads):

```bash
./bitcoin-wallet-bruteforce-offline 8 output.txt attack-addresses-p2pkh.txt
```

**That's it!** The program is now running. You'll see statistics every 10 seconds. Press `Ctrl+C` to stop.

---

### 🪟 Windows

**Step 1:** Open PowerShell or Command Prompt (press `Win + R`, type "powershell", press Enter)

**Step 2:** Navigate to the project folder and build:

```powershell
cd C:\path\to\bitcoin-bruteforce
go build -o bitcoin-wallet-bruteforce-offline.exe bitcoin-wallet-bruteforce-offline.go
```

**Step 3:** Run the program (using 8 threads):

```powershell
.\bitcoin-wallet-bruteforce-offline.exe 8 output.txt attack-addresses-p2pkh.txt
```

**That's it!** The program is now running. You'll see statistics every 10 seconds. Press `Ctrl+C` to stop.

---

### 🐧 Linux

**Step 1:** Open Terminal (`Ctrl + Alt + T`)

**Step 2:** Navigate to the project folder and build:

```bash
cd /path/to/bitcoin-bruteforce
go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

**Step 3:** Run the program (using 8 threads):

```bash
./bitcoin-wallet-bruteforce-offline 8 output.txt attack-addresses-p2pkh.txt
```

**That's it!** The program is now running. You'll see statistics every 10 seconds. Press `Ctrl+C` to stop.

---

### 📊 What You'll See

Once running, you'll see output like this:

```
╔════════════════════════════════════════════════════════════╗
║  Bitcoin Wallet Bruteforce - Optimized Edition            ║
╚════════════════════════════════════════════════════════════╝

CPU Cores: 8 | Worker Threads: 8
SHA256: Hardware Accelerated (SIMD)
Public Key: Compressed (33 bytes)
Address Type: Legacy P2PKH (starts with '1')

Loading addresses from attack-addresses-p2pkh.txt...
✓ Loaded 27 addresses to check against

Starting brute force...
════════════════════════════════════════════════════════════

[Stats] Total: 880000 | Overall: 87877 keys/sec | Current: 87877 keys/sec | Runtime: 10s
```

**Note:** The included `attack-addresses-p2pkh.txt` has 27 test addresses. To add more addresses, see the "Getting the Funded Address List" section below.

---

## TL;DR (human version)

Here's what this toolkit does in simple terms:

1. **Generate random private keys offline** – The program creates random 256-bit numbers (Bitcoin private keys)
2. **Derive corresponding Bitcoin addresses** – From each private key, it calculates the matching Bitcoin address
3. **Check for matches** – It compares the generated address against a list of addresses known to hold bitcoin
4. **Repeat at high speed** – This happens millions of times per second

If by some absurd cosmic luck you generate the exact same address as someone else's funded wallet, you "won the lottery."

**The probability is so close to zero that for practical purposes it IS zero.**

Why do people find this fascinating? It feels like "what if I guess someone's key and become rich" – a tempting fantasy. This toolkit shows you how that fantasy actually looks in math and code, and why it's fundamentally unrealistic.

---

## How Bitcoin Keys and Addresses Actually Work

To understand why brute forcing Bitcoin is effectively impossible, you need to understand the mathematics:

### Private Keys and Public Keys

- A **Bitcoin private key** is essentially a 256-bit number
- That means there are **2^256 possible private keys** ≈ **1.16 × 10^77** (a 78-digit number)
- From a private key, you compute a **public key** using elliptic curve cryptography (secp256k1)
- This is a one-way mathematical operation – you can't reverse it to find the private key from the public key

### Bitcoin Addresses

From the public key, you compute a Bitcoin address. For **Legacy P2PKH addresses** (the ones starting with `1`):

1. Take the public key
2. Hash it with SHA256
3. Hash that result with RIPEMD160 → this gives you a **160-bit value**
4. Encode it with Base58Check → you get a human-readable address like `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`

### The Key Space vs. Address Space

Here's the crucial part:

- **Private key space:** 2^256 ≈ 1.16 × 10^77 possible keys
- **P2PKH address space:** 2^160 ≈ 1.46 × 10^48 possible addresses

Since there are far more private keys than addresses, **many different private keys must mathematically collapse to the same final address**. Collisions are guaranteed to exist in theory.

**BUT:**

Finding a collision with one specific funded address is still so insanely unlikely that you can treat it as impossible. Both 2^256 and 2^160 are numbers way beyond anything physically searchable by all computers on Earth, even with GPUs or specialized hardware.

To put it in perspective:

- Atoms in the observable universe: ≈ 10^80
- Private key space: ≈ 10^77 (nearly as many as atoms in the universe)
- Your chance of hitting a specific funded address: ≈ 1 in 10^48

---

## Why This Focuses on Addresses (and Not on Seeds)

You might wonder: "Why not brute force seed phrases instead?"

Brute forcing **BIP39 seed phrases** (the 12 or 24 words) is a different problem, typically only feasible when:

- Someone used a weak custom passphrase
- The seed has reduced entropy (partially known words)

With a properly generated random 12-word or 24-word seed, brute forcing is just as impossible as brute forcing private keys directly.

**This toolkit takes a different approach:**

- **Offline key generation** – Generate random private keys using cryptographically secure random number generation
- **Instant address derivation** – Compute the corresponding address immediately
- **Local database lookup** – Compare against a pre-loaded list of funded addresses (no network access required for the core loop)

This is the most **cost-effective theoretical attack** because:

- No API rate limits or network delays
- Can run completely air-gapped
- Maximum computational efficiency

**This is still basically impossible to succeed**, but it's the only version of brute force that even makes theoretical sense from a resource perspective.

---

## How the Toolkit Works

The toolkit follows a simple four-step pipeline:

### 1. Generate a Candidate Private Key

The tool generates a random 256-bit number (or iterates through keys, depending on mode) using a cryptographically secure random number generator.

### 2. Derive its Legacy Bitcoin P2PKH Address

From the private key:

- Compute the public key using secp256k1 elliptic curve multiplication
- Hash the public key: `RIPEMD160(SHA256(pubkey))` → 20 bytes
- Encode as Base58Check → address like `1A1zP1...`

### 3. Check Against a List of Funded Addresses

Compare the generated address against a pre-built set of addresses known to have a non-zero balance. This uses an in-memory hash map for O(1) constant-time lookup.

### 4. Repeat at Very High Speed

This loop runs completely offline. The only "online" step is refreshing the funded-address list occasionally.

**Performance Note:**

Performance depends on your hardware (CPU architecture, number of cores). On a modern consumer CPU, the toolkit can test anywhere from **20,000 to 50,000 keys per second per core**. With 8 cores running, that's approximately **160,000 to 400,000 keys per second**.

That sounds like a lot until you remember you need to search through 2^160 possibilities (1.46 × 10^48). At 400,000 keys/sec, you would need approximately **10^38 years** to have a reasonable chance of finding a match.

---

## Getting the Funded Address List

The scanner needs a local list of Bitcoin addresses that currently (or recently) hold a non-zero balance.

**Where to get address data:**

Public snapshots of Bitcoin addresses and their balances exist. One well-known community source is **[addresses.loyce.club](http://addresses.loyce.club/)**, which provides regularly updated dumps of the Bitcoin UTXO set.

**Important:**

- You must download such a list yourself
- This repository **does not ship any "target" addresses**
- You are responsible for how you use any data you obtain

### What Addresses to Use

This tool currently generates **Legacy P2PKH addresses** (those starting with `1`). You need to filter your dataset to include only those addresses, because:

- The tool doesn't generate SegWit addresses (`bc1q...`)
- The tool doesn't generate Taproot addresses (`bc1p...`)
- The tool doesn't generate P2SH addresses (starting with `3`)

---

### Quick Start (copy/paste friendly)

For beginners, here's a simple step-by-step guide:

**Step 1: Download an address snapshot**

Visit a source like [addresses.loyce.club](http://addresses.loyce.club/) and download the latest Bitcoin address snapshot. These files are typically large (several GB compressed).

**Step 2: Filter for P2PKH addresses**

Use the provided `filter-p2pkh.py` script to extract only Legacy P2PKH addresses:

```bash
python3 filter-p2pkh.py raw-addresses.txt -o attack-addresses-p2pkh.txt
```

This will create a clean text file with one P2PKH address per line.

**Step 3: Build the Go program**

```bash
go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

**Step 4: Run the scanner**

```bash
./bitcoin-wallet-bruteforce-offline 8 output.txt attack-addresses-p2pkh.txt
```

Arguments:

- `8` – Number of worker threads (use your CPU core count)
- `output.txt` – File where matches will be saved
- `attack-addresses-p2pkh.txt` – Your filtered address list

The program will run indefinitely, displaying statistics every 10 seconds. Press `Ctrl+C` to stop.

---

### Advanced / Manual Data Prep

For advanced users who want more control:

**Input File Format:**

Most Bitcoin address dumps come in formats like:

```
<address> <balance_satoshis> <other_metadata>
```

You only need the first column (the address itself). The Python filter script handles this automatically.

**Why Only P2PKH?**

This toolkit focuses on Legacy P2PKH addresses because:

- They use a 160-bit hash (Hash160), making them the "easiest" theoretical target
- The address derivation is straightforward: `Base58(version + Hash160(pubkey) + checksum)`
- This is where collisions would be most likely (though still effectively impossible)

**Optimization Tips:**

For maximum lookup performance:

- **Hash Set in RAM:** The Go program loads all addresses into a `map[string]bool` for O(1) lookup
- **Bloom Filters:** For extremely large datasets (100M+ addresses), consider implementing a Bloom filter for a first-pass check
- **Memory Efficiency:** Each address consumes approximately 50-100 bytes in the hash map. 10M addresses ≈ 500MB-1GB RAM

**Custom Filtering:**

If you want to write your own filter, the criteria are:

- Address starts with `1`
- Length is typically 26-35 characters
- Only Base58 characters (excludes `0`, `O`, `I`, `l`)

---

## Is This Actually Dangerous to Bitcoin?

**No.** Brute forcing random private keys is **not a practical threat** to Bitcoin at global scale.

Here's why:

### The Numbers Don't Lie

The key space (2^256) is unimaginably huge. Even though many private keys map to the same 160-bit P2PKH address space (2^160), finding a collision with a **specific funded address** is beyond the reach of current physics and computing.

Let's do the math:

- **Total Bitcoin addresses with funds:** ~50 million (as of 2024)
- **Address space:** 2^160 ≈ 1.46 × 10^48
- **Your probability of hitting ANY funded address per guess:** ~50,000,000 / (1.46 × 10^48) ≈ 3.4 × 10^-41

That's 0.000000000000000000000000000000000000000034%

### Energy Requirements

Even if you had a computer that could test 1 trillion keys per second (which doesn't exist), and ran it for the age of the universe (13.8 billion years), you would test approximately:

10^12 keys/sec × 3.15 × 10^7 sec/year × 1.38 × 10^10 years ≈ 4.3 × 10^29 keys

That's still only 0.00000000000000003% of the 2^160 address space.

### The Purpose of This Project

**This project exists to show WHY Bitcoin is safe**, not to pretend it's easy.

If you think "I will just run this overnight and maybe hit a rich address," **you are fundamentally misunderstanding the scale of these numbers**. You are more likely to:

- Win the lottery jackpot 5 times in a row
- Be struck by lightning twice in the same day
- Find a specific grain of sand on all Earth's beaches

This toolkit is educational. It demonstrates the astronomical improbability in concrete, runnable code.

---

## License and Responsibility

This project is released under the **MIT License**.

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

### Your Responsibilities

- **Compliance:** You are responsible for complying with your local laws and regulations
- **Ethics:** Do not attempt to access or move funds from addresses you do not control
- **Liability:** The authors take **no responsibility** for any misuse of this software
- **Education:** This is a research and educational tool – use it to learn, not to harm

---

## Performance and System Requirements

### Hardware Requirements

**Minimum:**

- CPU: Any modern processor with at least 2 cores
- RAM: 2GB (depends on address database size)
- Storage: 10GB for address databases

**Recommended:**

- CPU: Modern multi-core processor (8+ cores)
- RAM: 8GB+ (for large address databases with 10M+ addresses)
- Storage: SSD for faster address database loading

### Software Requirements

- **Go:** Version 1.22 or higher
- **Python:** Version 3.6 or higher (for the filter script)

### Expected Performance

Performance varies by CPU architecture and generation:

| CPU Type          | Keys/sec per core | 8-core total      |
| ----------------- | ----------------- | ----------------- |
| Modern (2020+)    | 30,000 - 50,000   | 240,000 - 400,000 |
| Older (2015-2019) | 15,000 - 30,000   | 120,000 - 240,000 |
| ARM/Mobile        | 5,000 - 15,000    | 40,000 - 120,000  |

**Performance factors:**

- SIMD acceleration (AVX2, AVX-512 on Intel/AMD)
- CPU cache size and speed
- Memory bandwidth
- Number of threads vs. CPU cores

### Build Instructions

**Standard build:**

```bash
go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

**Static binary (works across different systems):**

```bash
go build -ldflags '-extldflags "-static"' -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

**Optimized build:**

```bash
go build -ldflags="-s -w" -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

The `-s -w` flags strip debug information, reducing binary size by ~30%.

### Installation

**Clone the repository:**

```bash
git clone https://github.com/yourusername/bitcoin-bruteforce.git
cd bitcoin-bruteforce
```

**Install Go dependencies:**

```bash
go mod download
go mod verify
```

**Build:**

```bash
go build -o bitcoin-wallet-bruteforce-offline bitcoin-wallet-bruteforce-offline.go
```

---

## Technical Implementation

This toolkit is designed for maximum performance within the constraints of standard consumer hardware.

### Key Optimizations

**SIMD-Accelerated SHA256**

- Uses `minio/sha256-simd` library for hardware-accelerated hashing
- 2-3x faster than Go's standard `crypto/sha256`
- Automatically detects CPU capabilities (AVX2, AVX, SSE, ARM NEON)

**Compressed Public Keys**

- Uses 33-byte compressed public keys instead of 65-byte uncompressed
- Reduces hashing workload and memory usage
- Standard format for modern Bitcoin wallets

**Multi-threaded Worker Pool**

- Scales across all available CPU cores
- Each worker operates independently with its own RNG state
- Lock-free architecture with atomic counters for statistics

**Buffer Pooling**

- Reuses byte buffers across goroutines with `sync.Pool`
- Reduces garbage collection pressure by ~90%
- Minimal memory allocations in the hot path

**Efficient Data Structures**

- Hash map (`map[string]bool`) for O(1) address lookups
- Buffered channels for non-blocking match writing
- Atomic operations batched every 10,000 iterations to reduce contention

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         Main Thread                          │
└────────────┬────────────────────────────────────────────┬────┘
             │                                            │
             ├──> [Stats Reporter] ──> Console (10s)     │
             │                                            │
             ├──> [Match Writer] ──> output.txt          │
             │         ▲                                  │
             │         │ matchChan                        │
             │         │                                  │
             ├──> [Worker 1] ──┐                         │
             ├──> [Worker 2] ──┤                         │
             ├──> [Worker 3] ──┼──> Shared Match Chan   │
             └──> [Worker N] ──┘                         │
                                                          │
                   Load address DB ──────────────────────┘
```

### Source Code Documentation

The Go source code (`bitcoin-wallet-bruteforce-offline.go`) is extensively documented with:

- Detailed function-level comments
- Algorithm explanations
- Performance analysis
- Mathematical background

For deep technical details, read the source code directly – it's written to be educational.

---

## Contributing

Contributions are welcome for:

- Performance optimizations
- Additional address format support (SegWit, Taproot)
- Better statistics and monitoring
- Cross-platform compatibility improvements

Please ensure all contributions maintain the educational focus and include appropriate warnings about the impracticality of actual brute forcing.

---

## FAQ

**Q: Will this actually find me Bitcoin?**

A: Statistically, no. The probability is so close to zero that you should treat it as impossible. You're more likely to be struck by lightning while winning the lottery.

**Q: How long would it take to find a match?**

A: At 400,000 keys/second, you would need approximately 10^38 years (quadrillions times the age of the universe) to have a reasonable chance.

**Q: Is this illegal?**

A: The software itself is legal for research and education. However, attempting to access or move funds from addresses you don't control is likely illegal in most jurisdictions. Know your local laws.

**Q: Why did you create this?**

A: To demonstrate mathematically and practically why Bitcoin's cryptography is secure. Education through hands-on experimentation is powerful.

**Q: Can I use GPUs to speed this up?**

A: Yes, GPUs could theoretically speed up key generation by 100-1000x. However, even at 1 billion keys/second, you would still need 10^31 years. The scale of the problem doesn't change.

**Q: What if quantum computers break this?**

A: That's a separate concern. Quantum computers with sufficient qubits (millions) could theoretically break ECDSA using Shor's algorithm. Bitcoin would need to migrate to quantum-resistant cryptography before that happens. This has nothing to do with brute forcing.

---

## Acknowledgments

- **btcsuite** – Bitcoin libraries for Go
- **minio/sha256-simd** – SIMD-accelerated SHA256 implementation
- **Loyce Club** – Community-maintained Bitcoin address databases
- **Bitcoin developers** – For creating cryptographically secure money

---

## Final Thoughts

This project exists at the intersection of cryptography, probability theory, and practical computing. It's a hands-on demonstration of why Bitcoin's security model works.

When you run this tool and see it processing hundreds of thousands of keys per second – and realize that's still **nowhere near enough** – you gain an intuitive understanding of just how vast 2^160 really is.

Use this knowledge responsibly. Learn, experiment, and appreciate the mathematics that makes Bitcoin secure.

**Remember:** If brute forcing Bitcoin were practical, Bitcoin would be worthless. The fact that Bitcoin has value is proof that this doesn't work at scale.

---

## ₿ Support This Project

If you find this work valuable, consider supporting development:

**Bitcoin Address (Taproot):**

```
bc1phd6c0znnl0jjnf734svg6z67cr4jet4je889uvk6yqawdcj4djhsj746n3
```

Every satoshi helps fund continued research and development of Bitcoin security tools.

---

**Author:** David Zita  
**License:** MIT  
**Repository:** https://github.com/yourusername/bitcoin-bruteforce
