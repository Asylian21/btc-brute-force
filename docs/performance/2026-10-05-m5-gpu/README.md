# Measured Metal GPU optimization — 2026-10-05

The selected implementation keeps the hybrid CPU EC walk and on-device GLV,
HASH160 and Bloom filtering. It changes the shader's SHA schedule and state
handling, removes hot dispatch allocations and improves startup calibration.
Slower shader layouts and CPU-side GLV expansion were restored after measurement.

Ten paired 2-second samples demonstrate **+5.08% complete hybrid throughput**
(666.0 → 699.9 million variant hashes/s, p<0.001) and **+4.06% isolated dispatch
throughput** (672.7 → 700.0 million hashes/s, p=0.001). Hot dispatch Go allocations
fall from two to zero. Longer samples give lower absolute rates and do not
establish a significant sustained throughput gain.

## Final combined acceptance

| Measurement | Pairs / requested window | Original GPU | Selected GPU | Result |
| --- | --- | ---: | ---: | --- |
| Complete hybrid benchmark | 10 / 2s | 666.0 M hashes/s | 699.9 M hashes/s | **+5.08%, p<0.001** |
| Isolated populated-filter dispatch | 10 / 2s | 672.7 M hashes/s | 700.0 M hashes/s | **+4.06%, p=0.001** |
| Hybrid during continued load | 6 / 10s | 498.2 M hashes/s | 514.3 M hashes/s | **No significant difference, p=0.310** |
| Hybrid Go allocations | 10 / 2s | 3 allocs/op | 1 alloc/op | −66.67%, p<0.001 |
| Dispatch Go allocations | 10 / 2s | 48 B/op, 2 allocs/op | 0 B/op, 0 allocs/op | −100%, p<0.001 |

The longer series followed continuous CPU/GPU testing and measurement. Both
versions slowed during that series. The selected median is numerically higher,
but sustained acceptance is **inconclusive** at benchstat's default threshold;
700 M hashes/s is not a demonstrated sustained rate. No chip temperature or
frequency measurements were recorded; `pmset` reported no thermal warnings.

Each timed run completed successfully and verified its exact dispatch, checked
hash and frontier counts. All expected rows/configurations are present. Samples
are sequential and alternate AB/BA; no other tests or builds ran alongside the
final measurements. These synthetic benchmarks exclude console/checkpoint I/O
and have the populated-filter scope described below.

Evidence: [final benchstat](final-benchstat.txt),
[sustained benchstat](sustained-benchstat.txt),
[original final samples](final-before.bench), [selected final samples](final-after.bench),
[original longer samples](sustained-before.bench),
[selected longer samples](sustained-after.bench).

Component results below are separate experiments with their own paired
baselines; their medians should not be compared across experiments or added
together.

## Machine and comparison method

Apple M5 Pro, 18 CPU cores (6 Super + 12 Performance), 20 GPU cores, 48 GiB,
macOS 27.0.1 arm64. Fixed Go 1.27.1 test binaries use PGO disabled and external
Mach-O linking. The baseline and selected binaries use the same CPU dependencies
already optimized in the [preceding CPU pass](../2026-10-05-m5/README.md).

Each comparison runs sequentially with alternating AB/BA ordering, producing
ABBA blocks, and clears CPU backend-force environment overrides. The paired
runner rejects failed processes, missing rows and changed benchmark names. The
fixture is held at 18 producers, 4 chunks per dispatch, threadgroup 384 and
65,536 deterministic synthetic target digests. Desktop background activity was
recorded in `environment.json`; this is a real workstation measurement with
the noise shown by the paired samples.

## What one measured operation does

One production chunk contains 16 batches × 1,024 base points = **16,384 base
points**. At four chunks, one dispatch consumes **65,536 base points** and
computes all six GLV/negation variants, totaling **393,216 hashes**. Throughput
always counts variants, not base points. The complete benchmark must finish
exactly `b.N` dispatches and verify `b.N × chunks × 16,384 × 6` checked hashes
and the complete contiguous frontier.

The target fixture builds the actual production Bloom format: **256 KiB,
49.72% populated bits, k=22**, from 65,536 synthetic digests. A zero Bloom table
would reject every digest at its first probe and underrepresent populated-filter
work. No external target/address list is read by these benchmarks.

- `BenchmarkHybridGPUScan` includes chunk claims, rebasing, the complete CPU
  affine walk filling shared Metal memory, overlapping per-producer queue
  dispatches, GPU GLV/HASH160/Bloom, candidate count readback, rare independent
  CPU reconstruction/hash/exact lookup, key counter updates and frontier
  completion. Each producer waits for its own dispatch while other producers
  fill or dispatch, matching production overlap.
- `BenchmarkGPUDispatch` fills each producer's input once before timing and
  repeatedly dispatches the populated-filter workload on independent queues.
  It includes completion and candidate count readback, but excludes CPU EC
  refill, frontier work and CPU exact confirmation. Its rate is an isolated
  dispatch ceiling.
- Metal initialization and shader compilation, target/Bloom construction,
  buffer/stream allocation, queue warmup, producer launch/setup and post-run
  assertions are excluded. Console liveness sampling, match output and
  checkpoint/disk I/O are also excluded. `allocs/op` measures timed **Go**
  allocations; it does not count Metal's internal command allocations or the
  excluded persistent buffers.

## Completed component comparisons

Rates are million variant hashes per second. `~` means benchstat did not
demonstrate a difference at its default significance threshold.

| Change | Pairs | Hybrid before → after | Hybrid result | Dispatch before → after | Dispatch result |
| --- | ---: | ---: | --- | ---: | --- |
| SHA schedule/state handling | 10 | 671.0 → 687.8 | ~, p=0.089 | 673.9 → 703.1 | **+4.33%, p<0.001** |
| Hot bridge dispatch | 6 | 683.0 → 694.9 | ~, p=0.394 | 689.7 → 699.1 | ~, p=0.485 |

The SHA dispatch time fell from 583.5 to 559.3 µs per operation (**−4.15%**).
The bridge comparison reduced hybrid Go allocation medians from 145.0 to
93.5 B/op and 3 to 1 allocs/op, and isolated dispatch from 48 to 0 B/op and
2 to 0 allocs/op (p=0.002 for each allocation comparison). These reductions are
retained without claiming a demonstrated bridge throughput improvement.

Evidence: [SHA benchstat](sha-benchstat.txt), [bridge benchstat](host-benchstat.txt).

## Selected implementation

- The SHA-256 shader rotates logical round-state arguments and uses constant
  sliding schedule slots, removing dynamic indexing and repeated assignments
  of unchanged state words. Its HASH160 output remains bit-exact.
- The GLV stream caches its Hasher-owned pipeline. A typed C dispatch wrapper
  binds four buffers and four scalars from the C stack, avoiding Go argument
  slice allocations and repeated shared pipeline-cache locking. The complete
  Objective-C dispatch and autorelease pool stay inside one synchronous C call,
  allowing removal of `runtime.LockOSThread` bookkeeping. Other kernel paths
  retain their generic dispatch wrapper.
- Calibration shares a populated synthetic Bloom and prepares persistent
  producer buffers, key streams and queues once. Allocation, queue warmup,
  shader setup and cleanup are excluded from sample rates. Samples start at a
  readiness barrier and include draining every in-flight dispatch in both
  elapsed time and exact checked counts. Any allocation/warmup/dispatch error,
  overflow, idle producer or count/frontier mismatch rejects the entire sample
  with a logged zero rate; partial cohorts cannot publish a plausible rate.
- Autotuning searches threadgroups at the starting chunk count, then chunks at
  the chosen threadgroup. It confirms incumbent and candidate in alternating
  order, uses medians of three samples and requires at least **3%** improvement
  before changing the starting configuration. The display states that sample
  windows take about 2–3 seconds plus setup and queue drain. Short observations
  guide startup choice and cannot guarantee later sustained performance.
- Calibration is not called inside either timed GPU benchmark. Its improved
  measurement method cannot account for a throughput change in those loops.
  The CPU calibrator still measures EC/HASH160 without target-map lookup; the
  startup CPU/GPU comparison is therefore a heuristic with different membership
  workloads, rather than a complete scanner equivalence test.
- GLV default and stream wrappers explicitly reject candidate-buffer overflow.
  A saturated filter cannot silently discard compacted ids and advance the scan.
  Test/benchmark initialization skips only the explicit absence of a Metal
  device; shader compilation and queue failures fail validation.

## Rejected experiments

Every row uses its own retained control binary with the same populated fixture.
The alternative changes were removed from the final implementation.

| Candidate | Pairs | Hybrid before → after | Hybrid change | Dispatch before → after | Dispatch change |
| --- | ---: | ---: | --- | ---: | --- |
| One X image live, six hashes per thread | 10 | 691.0 → 571.3 | −17.32%, p<0.001 | 702.3 → 576.8 | −17.87%, p<0.001 |
| Three image threads, two parities each | 6 | 665.8 → 594.4 | −10.73%, p=0.002 | 694.1 → 600.8 | −13.44%, p=0.002 |
| Independent β² multiply | 6 | 696.6 → 615.4 | −11.66%, p=0.004 | 702.5 → 617.3 | −12.12%, p=0.002 |
| RIPEMD left/right round interleaving | 6 | 683.9 → 687.6 | ~, p=0.699 | 692.4 → 690.7 | ~, p=0.699 |
| CPU GLV precomputation | 6 | 700.8 → 678.3 | **−3.21%, p=0.026** | 706.0 → 871.8 | +23.49%, p=0.002 |

CPU GLV is the useful counterexample: avoiding device field multiplication made
the prefilled dispatch faster, but additional host arithmetic and buffer work
made the complete hybrid path slower. Its hybrid allocation medians also rose
from 89.5 to 140 B/op and 1 to 3 allocs/op. It was a benchmark-only experiment,
and was not retained as the production pipeline.

Evidence: [one-image benchstat](glv-benchstat.txt),
[three-image benchstat](threeimage-benchstat.txt),
[β² benchstat](beta2-benchstat.txt), [RIPEMD benchstat](ripemd-benchstat.txt),
[CPU GLV benchstat](cpuglv-benchstat.txt).

## Physical-device validation completed

The completed logs contain **54 top-level passing tests, 0 failures and 0
skips**: 44 in [root-final-tests.txt](root-final-tests.txt) and 10 in
[metal-final-tests.txt](metal-final-tests.txt). Subtests are excluded from these
counts. Both logs end in `PASS`; their Metal operations executed on the physical
M5 Pro.

- Shader hashing compares **1,000,000** deterministic 33-byte messages against
  independent `btcutil.Hash160`, plus **1,024** genuine compressed public keys.
- Field arithmetic compares **1,100,000** inputs with the `math/big` oracle:
  200,000 each for add/sub/multiply/square/normalize, plus 100,000 inversions.
  EC affine addition validates **20,000** random point additions.
- The GPU GLV test checks 72,000 variants with 4,236 planted target variants.
  The populated benchmark fixture independently checks all six variants of
  64 base points (**384 hashes**), finds all **30** planted targets and compares
  every GPU candidate exactly with the CPU Bloom oracle.
- Production end-to-end orchestration finds both planted targets, including a
  GLV/negation variant, through CPU fill, GPU dispatch, candidate decode, exact
  confirmation and match delivery, and verifies the frontier advances.
- Candidate overflow is forced through both the default and stream GLV
  wrappers. The persistent calibration test also saturates its actual shared
  bitmap and verifies a zero rate, error and unchanged frontier after rejection.
  Valid successive chunk configurations return positive rates and advance
  exactly by completed work. Invalid configurations/samples are rejected;
  median permutations and the complete autotune search/confirmation path pass.
- Both throughput diagnostics previously skipped under `-short` now execute:
  the hybrid production sweep and experimental full GPU walk dispatch sweep.
  Their short diagnostic windows are not substitutes for the paired
  sustained comparison above. The experimental GPU EC walk is also validated
  against all **98,304** variants of 16,384 walked points.

Additional completed checks:

- Go 1.22.5 `-short ./...`: **52 top-level passes**, with only the two long
  throughput diagnostics skipped. Both diagnostics passed in the full native
  run above. [Log](go122-tests.jsonl).
- Native race checks: **7 top-level passes**, including concurrent production,
  calibration/autotune, shared-buffer fixture, overflow and generic dispatch.
  [Log](race-tests.jsonl).
- `GOEXPERIMENT=cgocheck2`: **5 top-level passes** exercising the new C dispatch
  arguments and buffer lifetimes. [Log](cgocheck2-tests.jsonl).
- `go vet ./...`, `make build-native` and the `make bench-gpu-scan` fixed-count
  smoke test pass. Linux amd64/arm64 and Windows
  amd64 cross-builds pass; this establishes compilation only on those targets.

## Reproduce with synthetic data

From the repository root on native darwin/arm64 with cgo and a Metal device:

```sh
BTC_BENCH_GPU_PRODUCERS=18 BTC_BENCH_GPU_CHUNKS=4 \
BTC_BENCH_GPU_TG=384 BTC_BENCH_GPU_TARGETS=65536 \
make bench-gpu-scan THREADS=18 BENCHTIME=2s BENCHCOUNT=10

# A smaller target fixture; this changes Bloom size and occupancy.
BTC_BENCH_GPU_PRODUCERS=12 BTC_BENCH_GPU_CHUNKS=3 \
BTC_BENCH_GPU_TG=256 BTC_BENCH_GPU_TARGETS=20 \
make bench-gpu-scan THREADS=18 BENCHTIME=2s BENCHCOUNT=5

# Compare previously built fixed binaries in alternating pairs.
BTC_BENCH_GPU_PRODUCERS=18 BTC_BENCH_GPU_CHUNKS=4 \
BTC_BENCH_GPU_TG=384 BTC_BENCH_GPU_TARGETS=65536 \
python3 scripts/compare-benchmarks.py BEFORE.test AFTER.test \
  --bench '^Benchmark(HybridGPUScan|GPUDispatch)$' --cpu 18 \
  --time 2s --count 10 --out gpu-results
benchstat gpu-results/before.txt gpu-results/after.txt
```

`BTC_BENCH_GPU_*` controls these test fixtures; production `BTC_GPU_*` variables
control the scanner. The `make` target selects Go 1.27.1 and explicitly disables
PGO. No match/checkpoint files or external target lists are used by the benchmark.

Paired samples, component benchstat reports and completed test logs are preserved
under `.local-perf/20261005-gpu/`; review copies belong beside this report. The final runtime source/binary manifest is [source-manifest.json](source-manifest.json).
A verified source archive and the original GPU snapshot are preserved in that
local directory, alongside the preceding CPU pass's archive. No commit, push or
external publication is part of this report.
