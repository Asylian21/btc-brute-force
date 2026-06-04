# Performance Benchmarks

This document explains how to benchmark the Bitcoin address-collision research toolkit and how to interpret the results. The important number for the optimized program is `BenchmarkKeyStreamPerKey`, because it measures the production worker hot path: batched secp256k1 point addition plus Hash160 lookup preparation.

## How to Run Benchmarks

```bash
# Preferred: uses the same Darwin linker workaround as normal builds.
make bench

# Manual equivalent on macOS 15+ with Go < 1.24.
go test -ldflags="-s -w -linkmode=external" -bench=. -benchmem -benchtime=5s . ./bench/...

# Linux and other platforms usually do not need the linkmode flag.
go test -bench=. -benchmem -benchtime=5s . ./bench/...
```

The root package contains benchmarks for the current optimized implementation. The `bench/` package contains educational component benchmarks for the older direct key/hash/Base58 pipeline.

## Current Results

Measured locally with Go 1.22.5 on darwin/arm64:

### Runtime Throughput

On a MacBook Air M3, the latest optimized 8-thread program run reached about **45.1 million keys/sec** — up from ~38.0M before the multi-buffer SHA-256 work, a measured **+18.7%** in a back-to-back A/B (see [Multi-Buffer SHA-256](#multi-buffer-sha-256-sha256mb-and-the-hash160-hot-path) below). The same implementation sustains roughly **26 million keys/sec with 4 worker threads** (that 4-thread figure predates the SHA-256 vectorization and is a conservative lower bound; it was itself up from ~19.9M under the previous endoFactor=2 design — a ~1.33x runtime gain on identical hardware). This is the headline practical throughput number because it includes the actual worker pool, target Hash160 lookup, stats accounting, checkpoint-aware scan-frontier tracking, and runtime scheduling. Each computed affine point now yields SIX real, distinct keys — the three GLV endomorphism x-values (x, beta*x, beta^2*x), each in both point-negation parities — for just 2 extra field multiplies (negation is a free 02/03 prefix flip since y is never serialized). All six are genuine keys checked against the target set, so they are counted honestly.

Progress captured by the current run:

- Runtime 8-thread headline reached about **45.1 million checked keys/sec** on local Apple Silicon (**+18.7%** over the pre-`sha256mb` baseline in a controlled A/B).
- HASH160 now runs through a single batched multi-buffer pass — vectorized SHA-256 ([`sha256mb`](https://github.com/Asylian21/sha256mb), arm64 `sha2x4`) feeding multi-buffer RIPEMD-160 ([`ripemd160-asm`](https://github.com/Asylian21/ripemd160-asm), `neon`) — replacing the old per-key `minio/sha256-simd` calls.
- The worker hot path is allocation-free (`0 B/op`, `0 allocs/op`) and operates on raw Hash160 values instead of Base58 strings.
- The GLV+negation layout checks six variants per affine walk step while reconstructing private scalars only on the rare match path.
- Checkpoints preserve a single scan frontier, so long measurements can resume from exactly where they stopped (with any thread count).

### Microbenchmarks

| Benchmark | ns/op | Approx keys/sec | Memory/op | Allocs/op | What it measures |
| --- | ---: | ---: | ---: | ---: | --- |
| `BenchmarkKeyStreamPerKey` | 118.5 | ~8,439,000 keys/sec | 0 B | 0 | Optimized hot path (batched affine walk + GLV endomorphism + negation + multi-buffer HASH160), per checked key |
| `BenchmarkGenerateKeyAndHash160` | 29,105 | ~34,358 keys/sec | 488 B | 8 | Fresh random key + scalar multiplication + Hash160 |

The `BenchmarkKeyStreamPerKey` figure (118.5 ns/op) is the controlled `GOMAXPROCS=1 -count=6` median; it dropped from 136.7 ns/op (−13.35%, `benchstat` n=10) when the per-key SHA-256 was replaced with the `sha256mb` multi-buffer pipeline. The benchmark body is single-goroutine, so `make bench` (`-8`, below) reports a near-identical ~120.7 ns/op.

`BenchmarkKeyStreamPerKey` counts every checked key, including all six GLV+negation variants produced from each computed affine point (each linear walk step yields six keys), so its ns/op is the amortized cost per key actually compared against the target set.

The educational component benchmarks in `bench/` (the older direct key/hash/Base58 pipeline) measure separately: `BenchmarkHashPipeline` ~29,655 ns/op, `BenchmarkKeyGeneration` ~29,439 ns/op, `BenchmarkHash160` ~290.2 ns/op, `BenchmarkBase58Encode` ~63.28 ns/op.

Raw command used:

```text
make bench
```

Raw output:

```text
BenchmarkKeyStreamPerKey-8         	51146752	       120.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkGenerateKeyAndHash160-8   	  201792	     29105 ns/op	     488 B/op	       8 allocs/op
BenchmarkHashPipeline-8            	  192752	     30666 ns/op	     907 B/op	      43 allocs/op
BenchmarkKeyGeneration-8           	  204842	     29509 ns/op	     192 B/op	       4 allocs/op
BenchmarkHash160-8                 	20302436	       298.2 ns/op	     296 B/op	       4 allocs/op
BenchmarkBase58Encode-8            	93246190	        64.47 ns/op	     144 B/op	       3 allocs/op
```

## GPU (Apple Metal) Pipeline: on-device GLV + Hash160 + Bloom

On Apple Silicon the program auto-enables a GPU pipeline. The CPU profile shows
hashing (SHA-256 + RIPEMD-160) is **~79%** of the per-key cost and the secp256k1
walk ~20%, so the heavy, embarrassingly parallel work is moved to the device
while the CPU keeps the part it is genuinely best at.

**Hybrid split (production).** CPU producers run the elite Montgomery-batched
affine walk and serialize **one base pubkey per linear step** straight into a
shared (unified-memory) Metal buffer — zero copy. The GPU then, per base point:

- derives all **six GLV+negation variants** on-device (`x`, `beta*x`, `beta^2*x`,
  each in both point-negation parities) for two field multiplies,
- runs the six-way **Hash160** (unrolled SHA-256 + RIPEMD-160),
- probes each digest against an on-device **Bloom filter** built from the target
  set, and
- **atomically compacts** only the (vanishingly rare) candidate ids into a small
  output buffer.

The CPU reads back the candidate count (typically zero) per dispatch instead of
every 20-byte digest, re-hashes each candidate with `btcutil.Hash160`, and
confirms it by an exact target lookup — so the Bloom filter (FPR ~1e-6, **zero
false negatives**) is a pure accelerator that can never miss or fabricate a
match. A gap-free `frontierTracker` preserves resumable checkpoints under the
pipeline's out-of-order completion. The single shared field inversion stays
amortized over a 1,024-step CPU batch (the walk's cheapest form) while the device
absorbs the 6x hashing it saturates on.

### Runtime throughput (end-to-end)

On a MacBook Air M3, 8 producers feeding the GPU sustain about **220–240 million
checked keys/sec** end-to-end (EC walk + on-device GLV + Hash160 + Bloom probe +
compaction + confirm + checkpointing) versus ~45–48M for the 8-thread CPU path —
a measured **~4.5–5x** runtime gain on identical hardware, with zero loss of
correctness (the GPU GLV expansion and Hash160 are bit-exact, verified at startup
against `btcutil`).

The startup auto-calibration (each backend measured ~0.3s, the full pipeline
minus the target scan) picks the GPU:

```text
GPU self-test: PASS — Hash160 + on-device GLV expansion bit-exact vs btcutil on Apple M3
Calibrating backends (~0.6s)...
  GPU pipeline :  218.4 M keys/sec
  CPU pipeline :   48.0 M keys/sec
Active backend: GPU — Apple M3 (Apple Metal) | 8 producer(s) x 6 chunks/dispatch = 589824 keys/dispatch
```

`--gpu=auto` (default) runs this calibration and chooses the faster backend, so
the GPU path **can never regress below the CPU path**. `--gpu=on` forces it
(fatal if the device or bit-exact self-test fails); `--gpu=off` stays on CPU.
Throughput is thermal-sensitive; the short calibration window under-reports the
sustained `[Stats]` rate, so it is a backend *selector*, not the headline number.

### Why hybrid, not a full on-GPU walk?

An experimental **full on-GPU EC walk** (`gpu/metal/ec_walk.metal`) is also
implemented and kept: the host fills only one start point per GPU thread, the
device fine-walks `ECWalkBatch` affine points per thread with its own per-thread
Montgomery inversion, then does the same GLV + Hash160 + Bloom. It is bit-exact
(validated by `TestGPUECWalk` and `gpuECWalkSelfTest` against `btcutil`) and
frees the CPU almost entirely.

On the M3 reference machine it nonetheless tops out around **166–174M keys/sec —
slower than the hybrid.** The reason is inversion amortization: the field
inversion (~80 multiplies' worth of work) is shared across a **1,024**-step batch
on the CPU but only across a per-thread **`ECWalkBatch` (≤128)** batch on the GPU,
where pushing the batch higher blows the per-thread register/stack budget and
collapses occupancy. The device walk therefore pays proportionally more inversion
cost than the CPU walk it would replace. The CPU is simply the better place to run
the amortized inversion; the GPU is the better place to run the 6x hash — which is
exactly what the hybrid does.

The full on-GPU walk is kept as an experiment (and may win on larger GPUs —
M-Max/Ultra — where occupancy is less constrained), but the **hybrid is the
production path** chosen by `--gpu=auto`.

### Standalone Hash160 kernel throughput vs batch size

The raw Hash160 kernel (the device building block, before GLV fusion) saturates
only at large batches, which is why a dispatch spans several 98,304-key chunks.
Multi-buffer CPU HASH160 (single thread) is shown for scale:

| Batch (keys) | GPU Metal Hash160 | CPU `hash160mb` (1 thread) |
| ---: | ---: | ---: |
| 16,384 | 27.3 M/s | 10.6 M/s |
| 65,536 | 45.2 M/s | 10.7 M/s |
| 262,144 | 135.3 M/s | 10.7 M/s |
| 1,048,576 | **159.9 M/s** | 10.6 M/s |

In production each GPU thread does 6 Hash160 per base point (one per GLV+negation
variant), so the per-base hash work is ~6x a single hash; fusing it with the
on-device GLV expansion is what lifts the end-to-end rate above this standalone
single-hash table. The bit-exact correctness test hashes 1,000,000 messages (plus
genuine secp256k1 pubkeys) and compares every 20-byte digest to `btcutil.Hash160`.

### Reproduce

```text
# Production GPU vs CPU calibration A/B (Apple Silicon, darwin only)
go test -ldflags="-linkmode=external" -run TestGPUCalibrationSanity -v .

# Full GPU correctness surface (field vs math/big, Hash160 vs btcutil, GLV,
# EC add, on-GPU walk, hybrid end-to-end gate)
make test-gpu

# Bit-exact Hash160 (1M messages + real pubkeys)
go test -ldflags="-linkmode=external" -run TestHash160 ./gpu/metal/

# Diagnostics: production tuning sweep + experimental on-GPU walk ceiling
go test -ldflags="-linkmode=external" -v \
  -run 'TestGPUProductionSweep|TestGPUWalkDispatchThroughput' .

# CPU baseline for comparison (Metal compiled out)
make build-cpu && ./bin/btc-brute-force-cpu 8 out.txt addresses.txt
```

End-to-end depends on RAM, core count, and thermals; tune with
`BTC_GPU_PRODUCERS` and `BTC_GPU_CHUNKS` (defaults: NumCPU producers, 6
chunks/dispatch ≈ 590k keys/dispatch).

## What Changed

The previous benchmark story was dominated by per-key secp256k1 scalar multiplication. That is useful for teaching the naive Bitcoin address pipeline, but it is not how the current worker is structured.

The current implementation claims a contiguous chunk of the key space per worker and walks consecutive keys from the chunk's first key:

1. Compute the chunk's starting point `P = base*G` (one scalar multiplication per chunk).
2. Use precomputed multiples of the generator `G` to derive `P + iG` with affine point addition.
3. From each affine point `(x, y)`, derive SIX valid keys: the three GLV endomorphism x-values `(x, beta*x, beta^2*x)` — scalars `k`, `lambda*k`, `lambda^2*k` — each in both point-negation parities (`-P = (x, -y)`, scalar `n-k`). This costs only 2 field multiplies (`beta*x`, `beta^2*x`); negation is a free `02/03` prefix flip because `y` is never serialized.
4. Batch the field inversions with Montgomery's trick so one inversion covers a whole 1,024-step batch (6,144 keys after the 6x endomorphism+negation expansion).
5. Hash all compressed public keys in the batch with a single fused multi-buffer HASH160 pass — vectorized SHA-256 (`sha256mb`, arm64 4-lane hardware-SHA) feeding multi-buffer RIPEMD-160 (`ripemd160-asm`, NEON) — writing the 20-byte digests straight into the result slice (no scatter copy).
6. Compare raw 20-byte Hash160 values against the target set.
7. Encode Base58 only on the rare match path.

This is why `BenchmarkKeyStreamPerKey` is roughly 245x faster per key than `BenchmarkGenerateKeyAndHash160` in the local run above:

```text
29105 ns/op / 118.5 ns/op = ~245x
```

## Interpreting Keys/sec

Convert `ns/op` to keys/sec with:

```text
keys/sec = 1,000,000,000 / ns_per_op
```

Example:

```text
1,000,000,000 / 118.5 = ~8,439,000 keys/sec
```

Actual program throughput depends on CPU core mix, thermal throttling, worker count, Go scheduler behavior, the target set size, and background system load. For a long run, the 10-second `[Stats]` output is more representative than a short benchmark; on the MacBook Air M3 runtime run, that sustained output is about **26M keys/sec at 4 threads** and about **45.1M keys/sec at 8 threads**.

## Why It Still Does Not Matter for Theft

The P2PKH hash space is 2^160, about `1.46 x 10^48` possible hashes.

Searching 1% of that space means about `1.46 x 10^46` guesses. At **45,100,000 keys/sec**:

```text
1.46e46 / 45,100,000 seconds = 3.2e38 seconds
3.2e38 / 31,557,600 seconds/year = ~1.03e31 years
```

That is many orders of magnitude beyond any practical computation. The optimization work makes the benchmark more honest; it does not make brute forcing Bitcoin practical.

## Optimization Notes

Current production hot-path optimizations:

1. **Batched affine EC walk**: one scalar multiplication per claimed chunk, then group addition for whole batches.
2. **GLV endomorphism + point negation**: each affine point `(x, y)` yields six valid keys — the three endomorphism x-values `(x, beta*x, beta^2*x)` with scalars `k`, `lambda*k`, `lambda^2*k`, each negated to `-P = (x, -y)` with scalar `n-k`. This costs 2 extra field multiplies (negation is a free `02/03` prefix flip), producing 6x the keys per field inversion and amortizing the slope/`y3`/normalization work over 6 candidates; see the section below.
3. **Montgomery batch inversion**: amortizes the expensive field inversion across a whole batch.
4. **Fast secp256k1 Fp field backend**: the per-key base-field arithmetic (multiply, square, add, negate, normalize, inversion) runs on [`github.com/Asylian21/secp256k1-field`](https://github.com/Asylian21/secp256k1-field), a 5x52-limb implementation with arm64/amd64 assembler kernels, instead of dcrd's pure-Go 10x26 `FieldVal`. Field math was the dominant CPU cost of the walk; see the section below.
5. **Hash160 target database**: input addresses are decoded once; workers compare fixed 20-byte arrays.
6. **Multi-buffer SHA-256**: compressed public keys are hashed in batches by [`github.com/Asylian21/sha256mb`](https://github.com/Asylian21/sha256mb), whose arm64 `sha2x4` kernel interleaves four messages through the ARMv8 hardware-SHA instructions (~2.6x scalar; see the section below). It replaces the per-key `minio/sha256-simd` calls on the hot path.
7. **Fused multi-buffer HASH160**: a single `hash160mb.FromPubkeys33` call hashes the whole batch — multi-buffer SHA-256 feeding multi-buffer RIPEMD-160 — instead of two per-key passes.
8. **Zero-copy Hash160**: the RIPEMD-160 pass writes its 20-byte digests straight into the caller's `[][20]byte` result slice (`hash160mb.Size == 20`), so the batch needs no intermediate output buffer and no per-key scatter copy.
9. **Allocation-free worker batch**: per-worker scratch buffers keep the hot loop at `0 B/op`.
10. **Batch counter updates**: atomics are updated per batch, not per key.

## GLV Endomorphism and Zero-Copy Hash160

secp256k1 admits an efficiently computable endomorphism: for any point `P = (x, y)`,
the point `(beta*x mod p, y)` is also on the curve and equals `lambda*P`, where
`beta` is a nontrivial cube root of unity in the base field `Fp` and `lambda` is
the matching cube root of unity in the scalar field `Fn`. Applied twice,
`(beta^2*x, y) = lambda^2*P` gives a third valid x-value. Each of those three
points can also be negated: `-P = (x, -y)` is on the curve with private scalar
`n-k`, and because `y` is never serialized — only its parity picks the `02/03`
compressed prefix — negation is a free prefix flip costing zero field operations.

So one computed affine point yields SIX valid keys (`k`, `n-k`, `lambda*k`,
`n-lambda*k`, `lambda^2*k`, `n-lambda^2*k`) for just 2 field multiplies
(`beta*x`, `beta^2*x`); the private scalars are reconstructed only on the rare
match path. The expensive EC addition and the shared Montgomery inversion now
amortize over 6 keys instead of 2. The same batch also avoids copying Hash160
results twice: RIPEMD160 writes directly into the caller's slice and SHA256
digests are stored with a single array assignment.

`BenchmarkKeyStreamPerKey` on a MacBook Air M3 (darwin/arm64, Go 1.22.5, ns per
*checked* key, `0 allocs/op` throughout). These rows isolate the GLV key-expansion
milestone and predate the multi-buffer SHA-256 work, which later took the 6-key
endpoint from ~136.7 to ~118.5 ns/key (see
[Multi-Buffer SHA-256](#multi-buffer-sha-256-sha256mb-and-the-hash160-hot-path)):

| Hot path | ns/key | keys/sec | Allocs | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Identity-only affine walk | ~222.1 | ~4.50M | 0 | 1.00x |
| + GLV endomorphism (2 keys/step, keyBatchSize 2048) | ~171.5 | ~5.83M | 0 | 1.30x |
| + beta^2 + negation (6 keys/step, keyBatchSize 1024) | ~136.7 | ~7.32M | 0 | **1.62x** |

Hashing (SHA256 + RIPEMD160) still runs per key, so the 6-key expansion does not
triple throughput — its win is spreading the EC addition and the single batched
inversion across 6 keys, dropping the per-checked-key cost from ~171.5 to ~136.7 ns
(a ~1.26x step over the 2-key design, ~1.62x cumulatively over the identity-only
walk). At the runtime level that is ~19.9M → ~26M keys/sec at 4 threads (~1.33x).
keyBatchSize was retuned from 2048 to 1024 because, with hashing now dominating the
per-key cost, single-thread cost is flat across 512..2048 while the smaller working
set wins on sustained multi-worker throughput. The hot loop stays at `0 allocs/op`
(the 6 variants are emitted by straight-line code, no closure). Reproduce:

```bash
GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=6 .
```

## secp256k1 Field (Fp) Backend

The base-field arithmetic over `p = 2^256 - 2^32 - 977` (the EC point-addition
math) was the single largest CPU cost of the key walk. The hot loop now uses
`field.Val` from `github.com/Asylian21/secp256k1-field` — a 5x52-bit limb layout
(25 wide `64x64->128` products per multiply vs dcrd's 100 narrow `32x32->64`
ones) with hand-written arm64 (MUL/UMULH) and amd64 (BMI2 MULX) kernels and a
pure-Go fallback. dcrd is retained for scalar math (`ModNScalar`,
`ScalarBaseMultNonConst`); only the per-key field math moved, bridged once per
worker via the canonical 32-byte encoding. The swap is bit-identical to dcrd
(verified by differential fuzzing) and keeps the hot loop at `0 allocs/op`.

Back-to-back `BenchmarkKeyStreamPerKey` on a MacBook Air M3 (darwin/arm64,
Go 1.22.5, `GOMAXPROCS=1`, `-benchtime=2s -count=5`, median ns/key), toggling
only the field backend (the dcrd row was measured by reverting just the field
type):

| Field backend | ns/key | keys/sec | Allocs | Speedup |
| --- | ---: | ---: | ---: | ---: |
| dcrd `FieldVal` (10x26, pure Go) | ~424 | ~2.36M | 0 | 1.00x |
| `field.Val` generic (5x52, pure Go) | ~281 | ~3.56M | 0 | **1.51x** |
| `field.Val` arm64 asm (5x52, MUL/UMULH) | ~215 | ~4.65M | 0 | **1.98x** |

The assembler backend nearly **doubles** single-thread hot-loop throughput. The
gain exceeds a naive "multiply only" estimate because the 5x52 layout also
speeds up add/negate/normalize and the Montgomery inversion (~2.8x faster than
dcrd's). Component micro-benchmarks (in the field library) measure the arm64
kernels at Mul 3.28x, Square 2.86x, and Inverse 2.81x versus dcrd.

(These ns/key figures were captured in the earlier endoFactor=2 configuration, so
their absolute values are higher than the current ~118.5 ns/checked key. They are
kept because they isolate the field-backend contribution, which is independent of
the GLV key-expansion factor; the relative speedups carry over unchanged.)

Reproduce the backend comparison:

```bash
# assembler (default on arm64/amd64+BMI2)
GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=5 .

# portable backend
GOSECP256K1FIELD_FORCE=generic GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=5 .
```

## Multi-Buffer SHA-256 (sha256mb) and the HASH160 Hot Path

After the field backend and the GLV expansion, hashing became the dominant
remaining cost. A `BenchmarkKeyStreamPerKey` CPU profile of the pre-`sha256mb`
build (minio per-key SHA-256 + multi-buffer RIPEMD-160) splits the per-key cost
roughly as:

| Component | Share of per-key cost |
| --- | ---: |
| RIPEMD-160 (multi-buffer NEON) | ~55% |
| SHA-256 (per-key `minio/sha256-simd`) | ~23% |
| EC point addition + field math | ~20% |
| Everything else (loop, slot writes) | ~2% |

The old code called `sha256simd.Sum256` once per compressed public key inside
`hashSextet`. The ARMv8 SHA-256 instructions are *latency-bound*: a single-message
hash cannot keep the crypto pipeline busy, so per-key hashing leaves throughput on
the table. The fix is the new sibling module
[`github.com/Asylian21/sha256mb`](https://github.com/Asylian21/sha256mb): its
arm64 `sha2x4` kernel interleaves **four independent 33-byte messages** through
`SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1`, hiding the per-instruction latency.
The hot path now serializes the batch's pubkeys (`writeSextet`) and makes one
`hash160mb.FromPubkeys33` call that runs multi-buffer SHA-256 straight into
multi-buffer RIPEMD-160.

### Component: SHA-256 alone

`sha256mb`'s own `BenchmarkHash33` on the same M3 (`GOMAXPROCS=1`, Go 1.22.5,
`n = 6144` — the bruteforcer's batch size, `-count=8` median, 0 allocs/op),
scalar `crypto/sha256` vs the `sha2x4` kernel:

| Backend | ns/op | hashes/sec | Speedup |
| --- | ---: | ---: | ---: |
| `scalar` (`crypto/sha256`) | 285100 | ~21,550,000 | 1.00x |
| `sha2x4` (arm64 HW-SHA, 4-lane) | 106700 | ~57,580,000 | **2.67x** |

### End-to-end: the bruteforcer

Replacing per-key SHA-256 with the `sha2x4` multi-buffer pipeline, measured
back-to-back to neutralize thermal drift:

| Measurement | Baseline (minio per-key) | Optimized (`sha2x4` staged) | Delta |
| --- | ---: | ---: | ---: |
| A3 — `BenchmarkKeyStreamPerKey`, `GOMAXPROCS=1` | 136.7 ns/key | 118.5 ns/key | **−13.35%** (`benchstat`, p=0.000, n=10) |
| A4 — runtime throughput, 8 threads | ~38.0M keys/sec | ~45.1M keys/sec | **+18.7%** |

The single-thread number is exactly what Amdahl's law predicts: SHA-256 was ~23%
of the per-key cost, so making it ~2.6x faster shrinks that slice to ~9% and
predicts ~−14% overall; the measured −13.35% is within a fraction of a point, the
small gap being the extra memory traffic of staging digests between the SHA and
RIPEMD passes. The 8-thread gain is larger because the batched kernel retires far
fewer instructions per key, easing the shared-resource pressure that builds up
when all cores hash at once.

This also explains why the original ">=20% per-key" target was optimistic: with
SHA-256 only ~23% of the cost, no SHA-only optimization can clear 20% single-core
on its own. The remaining headroom now lives in RIPEMD-160 (already NEON, ~55%)
and the EC/field work (~20%).

### Staged vs fused HASH160

`hash160mb` ships two bit-identical arm64 paths:

- **staged** (default): a full multi-buffer SHA-256 pass into a pooled digest
  buffer, then a full multi-buffer RIPEMD-160 pass.
- **fused**: one kernel that keeps each 4-lane group's SHA-256 digests in
  registers and feeds them straight into NEON RIPEMD-160 — no intermediate
  buffer — verified bit-for-bit against the staged path and `btcutil.Hash160`.

On M3 the two tie single-threaded (~585.6 vs ~586.2 µs at `n = 6144`) and the
staged path is ~3% faster at 8 threads, because each kernel runs in its own
deeply pipelined loop instead of starving the SHA pipeline of independent work.
The staged path is therefore the arm64 default; the fused kernel is kept, fully
tested, and selectable with `GOHASH160MB_FORCE=fused`.

### Reproduce

```bash
# Component SHA-256 (in the sha256mb module): scalar vs sha2x4
cd ../sha256mb
GOMAXPROCS=1 GOSHA256MB_FORCE=scalar \
  go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=10 ./ | tee /tmp/scalar.txt
GOMAXPROCS=1 GOSHA256MB_FORCE=sha2x4 \
  go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=10 ./ | tee /tmp/sha2x4.txt
benchstat /tmp/scalar.txt /tmp/sha2x4.txt

# End-to-end per-key (A3), this module
GOMAXPROCS=1 go test -ldflags="-s -w -linkmode=external" \
  -run '^$' -bench '^BenchmarkKeyStreamPerKey$' -benchmem -benchtime=2s -count=6 .
```

amd64 SIMD SHA-256 (AVX-512 / SHA-NI) is a documented follow-up — it cannot be
measured or validated on the M3 reference machine, so `sha256mb` currently runs
the scalar backend on amd64. See the `sha256mb`
[PERFORMANCE.md](https://github.com/Asylian21/sha256mb/blob/main/PERFORMANCE.md)
for the full methodology.

## Memory Usage

- Per worker: batch buffers for Hash160 output and elliptic-curve scratch values.
- Target database: one Go map entry per valid P2PKH address, keyed by `[20]byte`.
- Checkpoints: a small JSON file containing the single scan frontier (next private key).

Large address lists, checkpoint files, and match outputs are intentionally git-ignored because they are runtime inputs or outputs, not source artifacts.

## Contributing Benchmarks

To add benchmark results:

1. Run `make bench` on an idle system.
2. Record CPU model, architecture, Go version, OS, power mode, and worker-relevant context.
3. Include raw benchmark output.
4. Compare `BenchmarkKeyStreamPerKey` for the optimized hot path and `BenchmarkGenerateKeyAndHash160` for the direct scalar-multiplication baseline.
