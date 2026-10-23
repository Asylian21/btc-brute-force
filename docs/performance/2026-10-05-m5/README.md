# Measured dependency optimization — 2026-10-05

The selected changes improve individual library operations; the complete CPU
pipeline does **not** show a statistically significant throughput change.
Slower and inconclusive assembly candidates were discarded. The existing
staged HASH160 path remains the large-batch default.

## Selected results

Apple M5 Pro (6 Super + 12 Performance cores), 48 GiB, darwin/arm64, Go 1.27.1,
PGO disabled. Each comparison uses ten sequential A/B pairs with order
alternating AB/BA, fixed test binaries and cleared backend-force overrides.

| Operation | Before | Selected | Change | p |
| --- | ---: | ---: | ---: | ---: |
| Field square | 5.974 ns | 5.691 ns | -4.75% time | <0.001 |
| Field multiply | 7.608 ns | 7.611 ns | no demonstrated difference | 0.897 |
| Field inverse | 2.482 us | 2.485 us | no demonstrated difference | 1.000 |
| HASH160, one message | 163.2 ns | 146.0 ns | -10.51% time / +11.72% throughput | <0.001 |
| HASH160, two messages | 301.2 ns | 302.7 ns | no demonstrated difference | 0.066 |
| HASH160, three messages | 452.3 ns | 453.9 ns | +0.35% time | 0.007 |
| RIPEMD NEON-SHA3, four messages | 164.5 ns | 162.0 ns | -1.52% time | <0.001 |
| RIPEMD NEON-SHA3, eight messages | 196.5 ns | 194.6 ns | -0.99% time | <0.001 |
| RIPEMD NEON-SHA3, 2,048 messages | 48.96 us | 48.96 us | no demonstrated difference | 0.754 |

All these component loops report zero allocations. Field samples run for
300 ms; HASH160/RIPEMD samples for 200 ms. The tiny three-message HASH160 cost
is retained and disclosed; the earlier 7–8% regressions in two/three-message
shortcuts were removed by limiting the shortcut to one message.

## Whole CPU path

| Measurement | Before | Selected | p |
| --- | ---: | ---: | ---: |
| EC + HASH160, one hash | 55.52 ns | 55.67 ns | 0.810 |
| GPU base-point CPU producer, one point | 78.25 ns | 77.96 ns | 0.143 |
| EC + HASH160, 18 workers | 262.0 M hashes/s | 266.5 M hashes/s | 0.481 |
| Synthetic scan, 20 targets, one worker | 15.19 M hashes/s | 15.16 M hashes/s | 0.796 |
| Synthetic scan, 65,536 targets, one worker | 15.22 M hashes/s | 15.40 M hashes/s | 0.089 |
| Synthetic scan, 20 targets, 18 workers | 236.7 M hashes/s | 232.3 M hashes/s | 0.481 |
| Synthetic scan, 65,536 targets, 18 workers | 228.1 M hashes/s | 223.7 M hashes/s | 0.247 |

None of these differences establishes a whole-pipeline improvement or
regression. EC/hash samples run for 750 ms, synthetic scans for 400 ms.
The single-worker EC/hash loops allocate nothing. Parallel results include
worker initialization inside timing; their rounded zero allocs/op do not mean
initialization is free.

`BenchmarkCPUScan` uses deterministic synthetic digests. One operation walks
16 production batches, totaling 98,304 hashes, and checks the exact map after
each batch. Chunk rebasing, cursor/counter/progress atomics and inner stop
checks run inside timing; map creation runs outside it. Counters must equal
`b.N * 98,304`, and synthetic matches must stay zero. This models chunk scanning;
it does not invoke `worker()` directly and omits its outer stop check, console
sampling, match handling and checkpoint/disk I/O. No address list is loaded.
These figures are CPU measurements, not GPU throughput or full scanner claims.

## Implementation selected by measurement

- Field: immediate masks and hoisted reduction constants in ARM64 **square**.
  Original multiplication and repeated-square inversion kernels were restored.
- RIPEMD: direct calls to the four/eight-message assembly kernels replace
  function-value dispatch. Register-local wide finalization removes ten state
  spills and reloads and reduces the frame from 512 to 288 bytes. That frame
  reduction demonstrates no significant large-batch speed gain.
- HASH160: a one-message SHA-256/fixed-32-byte RIPEMD shortcut avoids the scratch
  pool and batch wrappers, while preserving source/output overlap and zero
  allocations. Larger counts retain the original pooled pipeline.
- Validation: guarded-page assembly tests, pinned vector digests that actually
  run SIMD bodies and tails, variable stride/alignment fuzzing, overlapping
  buffers, magnitude/alias limits, and overflow-safe convenience API checks.
- Measurement: `make bench-scan` and a sequential paired comparison script that
  rejects missing/mismatched benchmark rows and missing binaries.

## Rejected experiments

The raw benchstat reports retain both wins and failures:

- Combined field multiply/square constant hoisting made multiply 1.24% slower
  (p=0.017), so only square was retained. Two repeated-square variants failed
  to demonstrate an inverse improvement.
- Broad and minimal SHA4 scheduling/padding changes showed no significant
  improvement. All SHA/fused assembly and generator changes were restored.
- Fused SHA3 HASH160 fell from 17.89 to 17.59 M hashes/s (-1.71%, p<0.001).
- A shortcut for all counts below four made counts two/three 8.39%/7.50% slower.
  The final shortcut applies only to a single message.

The initial CPU profile attributed about 37% to RIPEMD, 27% to SHA4, 19% to
field multiplication and 3% to square. Single-operation gains are therefore
small relative to the already optimized 6,144-message production batch.

## Validation

- Final root suite: 45 top-level tests passed on Go 1.27.1, Go 1.22.5 and with
  fused HASH160 forced. Physical M5 Pro Metal differential/pipeline checks ran.
  `-short` skipped `TestGPUProductionSweep` and `TestGPUWalkDispatchThroughput`;
  no new GPU throughput claim is made.
- Binary integration: 2 passed, no skips. Root CPU race: 30 passed, Metal
  excluded with `nometal`. Native build and vet pass.
- Field: native/forced generic/forced assembly/purego/race/vet and minimum-Go
  suites pass. Exact limb boundaries for magnitudes 1..8, aliases, generic
  limb equality and dcrd equality are covered. FuzzSquare: 4,992,361 executions.
- RIPEMD: 44 named tests, all three backends/race/vet/staticcheck, 100% coverage
  in both libraries; 1,968 guarded calls compare 39,360 digests. Final Hash32
  fuzz: 380,062 executions; unchanged Sum and convenience HASH160 campaigns
  also passed. See `ripemd-validation.md` for campaign timing and details.
- SHA/HASH160: native and race matrices each pass 678 tests, including 616
  guarded-page configurations. Forced scalar/SHA4/staged/fused/NEON/SHA3,
  minimum-Go, vet, staticcheck and generator idempotence pass. Coverage is
  97.7% SHA and 87.7% HASH160; two fuzz campaigns total 3,401,008 executions.
- Cross-builds pass for the documented Linux/Windows targets. They prove
  compilation, not runtime correctness or performance there.
- Benchmark harness smoke checks reject empty regex matches and mismatched names, and preserve
  existing output when an input binary is missing; a valid fixed-count run
  succeeds. `make bench-scan BENCHTIME=1x BENCHCOUNT=1` passes.

## Reproduce and preserve

```sh
make test-subs
make bench-local BENCHTIME=750ms BENCHCOUNT=10
make bench-scan BENCHTIME=400ms BENCHCOUNT=10
python3 scripts/compare-benchmarks.py BEFORE.test AFTER.test \
  --bench '^BenchmarkKeyStreamPerKey$' --cpu 1 --time 750ms --count 10 --out results
benchstat results/before.txt results/after.txt
```

Raw paired samples (`*.bench`), selected/rejected benchstat reports and machine
metadata are stored beside this report for review in the parent repository. Larger JSON test logs,
CPU profile, original module snapshots, fixed binaries and source-change archive
remain under `.local-perf/20261005-m5/`.

The three `subs/` repositories and `go.work` are ignored by the parent Git repo;
parent commits alone cannot capture their changes. `source-changes.tar.gz` and
`final-source-manifest.json` preserve the final changed/new sources and hashes.
The initial worktrees were clean. No commit, push or dependency version change
was performed.
