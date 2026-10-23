# RIPEMD-160 validation, 2026-10-05

Host: Apple M5 Pro, darwin/arm64. Performance binaries use Go 1.27.1 and
`-pgo=off`; timed comparisons were run by the root agent without concurrent
validation. No commit or push was performed.

## Final-source checks

- 44 named tests across the root library and `hash160`.
- Native, forced scalar, forced NEON, forced NEON-SHA3, and race suites pass.
  Logs: `ripemd-tests-native.txt`, `ripemd-tests-scalar.txt`,
  `ripemd-tests-neon.txt`, `ripemd-tests-neon-sha3.txt`, `ripemd-tests-race.txt`.
- Coverage: 100.0% in both libraries; `ripemd-coverage.txt` and
  `ripemd-coverage.out`.
- The added oracle test runs 1,968 guarded calls: every n from 0 to 40 at all
  16 byte alignments on all three backends, comparing 39,360 output digests.
- Final Hash32 fuzz: 30 seconds, two workers, 380,062 executions, PASS;
  `ripemd-fuzz-hash32-final.txt`.
- Sum fuzz: 30 seconds, two workers, 167,004 executions, PASS.
- Hash160 fuzz: 30 seconds, two workers, 1,650,087 executions, PASS.
  The three relevant final-path campaigns total 2,197,153 executions. An
  earlier Hash32 candidate also passed 256,370 executions.
- go vet and gofmt pass; `ripemd-vet.txt` and `ripemd-gofmt.txt` are empty.
- Pinned staticcheck 2024.1.1 passes using Go 1.22.5 with external linking;
  `ripemd-staticcheck-external.txt` is empty. Internal linking on this macOS
  host initially failed with dyld's missing LC_UUID. The reusable executable
  is `tools/ripemd/staticcheck`, external-linked and ad-hoc signed after install.
- Generation is idempotent: all five generated outputs have identical hashes
  in `ripemd-generated-before.sha256` and `ripemd-generated-after.sha256`.
- Minimum-Go 1.22.5 native tests pass with external linking;
  `ripemd-tests-go122.txt`.
- Linux cross-build checks pass for amd64, arm64, 386, and ppc64le using
  Go 1.22.5; `ripemd-cross-build.txt`. These use `go test -exec=true` and prove
  compilation only, not runtime correctness or performance on those targets.
- `git diff --check` passes.

## Measured outcome

`ripemd-direct-benchstat.txt` contains ten paired samples for NEON-SHA3:

| Batch | Before | After | Change | Significance |
| --- | ---: | ---: | ---: | --- |
| 4 | 164.5 ns | 162.0 ns | -1.52% | p < 0.001 |
| 8 | 196.5 ns | 194.6 ns | -0.99% | p < 0.001 |
| 2048 | 48.96 us | 48.96 us | unchanged | p = 0.754 |

Large-batch throughput remains 41.83M hashes/s, with zero allocations. The
wide-kernel frame shrinks from 512 to 288 bytes and removes ten register spills
and ten reloads per eight-message iteration; this memory-traffic reduction did
not demonstrate a statistically significant large-batch throughput gain.

## Reproduction

Run from `subs/ripemd160-asm`:

```sh
GOTOOLCHAIN=go1.27.1 go test -pgo=off -count=1 ./...
GORIPEMD160MB_FORCE=scalar GOTOOLCHAIN=go1.27.1 go test -pgo=off -count=1 ./...
GORIPEMD160MB_FORCE=neon GOTOOLCHAIN=go1.27.1 go test -pgo=off -count=1 ./...
GORIPEMD160MB_FORCE=neon-sha3 GOTOOLCHAIN=go1.27.1 go test -pgo=off -count=1 ./...
GOTOOLCHAIN=go1.27.1 go test -pgo=off -race -count=1 ./...
GOTOOLCHAIN=go1.27.1 go vet ./...
GOMAXPROCS=2 GOTOOLCHAIN=go1.27.1 go test -pgo=off -run '^$' -fuzz '^FuzzHash32$' -fuzztime=30s -parallel=2 .
GOTOOLCHAIN=go1.22.5 CGO_ENABLED=1 go run -ldflags=-linkmode=external honnef.co/go/tools/cmd/staticcheck@2024.1.1 ./...
CGO_ENABLED=1 GOTOOLCHAIN=go1.22.5 go test -ldflags=-linkmode=external -count=1 ./...
```
