//go:build darwin && arm64 && cgo && !nometal

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	gpumetal "github.com/Asylian21/btc-brute-force/gpu/metal"
	"github.com/btcsuite/btcutil"
)

type gpuBenchmarkConfig struct {
	producers, chunks, threadgroup, targets int
}

func gpuBenchmarkEnv(tb testing.TB, name string, fallback, min, max int) int {
	tb.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		tb.Fatalf("%s=%q: expected an integer in [%d,%d]", name, raw, min, max)
	}
	return n
}

func gpuBenchmarkSettings(tb testing.TB) gpuBenchmarkConfig {
	return gpuBenchmarkConfig{
		producers:   gpuBenchmarkEnv(tb, "BTC_BENCH_GPU_PRODUCERS", runtime.GOMAXPROCS(0), 1, 128),
		chunks:      gpuBenchmarkEnv(tb, "BTC_BENCH_GPU_CHUNKS", gpuDefaultChunksPerDispatch, 1, 256),
		threadgroup: gpuBenchmarkEnv(tb, "BTC_BENCH_GPU_TG", gpuDefaultThreadgroup, 0, 1024),
		targets:     gpuBenchmarkEnv(tb, "BTC_BENCH_GPU_TARGETS", 65536, 1, 1<<20),
	}
}

func (c gpuBenchmarkConfig) name() string {
	return fmt.Sprintf("p=%d/chunks=%d/tg=%d/targets=%d", c.producers, c.chunks, c.threadgroup, c.targets)
}

// These synthetic digests are independent of the EC input. They populate the
// same production Bloom builder used for a real target set, including its power
// of two rounding and probe-count choice; no address file is read.
func gpuBenchmarkTargets(n int) hash160Set {
	targets := make(hash160Set, n)
	for i := 0; i < n; i++ {
		var input [16]byte
		copy(input[:8], "gpu-perf")
		binary.LittleEndian.PutUint64(input[8:], uint64(i))
		digest := sha256.Sum256(input[:])
		var target [20]byte
		copy(target[:], digest[:])
		targets[target] = struct{}{}
	}
	return targets
}

func gpuBenchmarkBuffer(tb testing.TB, h *gpumetal.Hasher, size int) *gpumetal.Buffer {
	tb.Helper()
	buf, err := h.NewBuffer(size)
	if err != nil {
		tb.Fatalf("Metal buffer (%d bytes): %v", size, err)
	}
	tb.Cleanup(buf.Free)
	return buf
}

type gpuBenchmarkProducer struct {
	in, mcount, mdata *gpumetal.Buffer
	stream            *gpumetal.Stream
	ks                *keyStream
	input, count, ids []byte
	completed         uint64
	candidates        uint64
	hits              uint64
	err               error
}

func gpuBenchmarkNewProducer(tb testing.TB, h *gpumetal.Hasher, baseCount int) *gpuBenchmarkProducer {
	tb.Helper()
	p := &gpuBenchmarkProducer{
		in:     gpuBenchmarkBuffer(tb, h, baseCount*pubStride),
		mcount: gpuBenchmarkBuffer(tb, h, 16),
		mdata:  gpuBenchmarkBuffer(tb, h, baseCount*4),
		ks:     newKeyStreamForGPU(),
	}
	stream, err := h.NewStream()
	if err != nil {
		tb.Fatalf("Metal stream: %v", err)
	}
	tb.Cleanup(stream.Free)
	p.stream = stream
	p.input, p.count, p.ids = p.in.Bytes(), p.mcount.Bytes(), p.mdata.Bytes()
	return p
}

func (p *gpuBenchmarkProducer) fill(start uint64, chunks int) {
	for k := 0; k < chunks; k++ {
		p.ks.setBase(chunkBaseSeed(start + uint64(k)))
		for batch := 0; batch < chunkBatches; batch++ {
			offset := (k*chunkBatches + batch) * gpuSubBatchBaseBytes
			p.ks.pubBuf = p.input[offset : offset+gpuSubBatchBaseBytes]
			p.ks.fillBasePubkeysSteps(keyBatchSize)
		}
	}
}

func (p *gpuBenchmarkProducer) dispatch(bloom *gpumetal.Buffer, bf *bloomFilter, baseCount int) error {
	binary.LittleEndian.PutUint32(p.count[:4], 0)
	return p.stream.GLVFilterStream(p.in, bloom, p.mcount, p.mdata, baseCount, pubStride, bf.mask, bf.k)
}

// confirm mirrors the production candidate decode and independent CPU exact
// lookup. Overflow or invalid ids fail the measurement rather than hiding work.
func (p *gpuBenchmarkProducer) confirm(start uint64, baseCount int, targets hash160Set) error {
	n := int(binary.LittleEndian.Uint32(p.count[:4]))
	if n > baseCount {
		return fmt.Errorf("candidate count %d exceeds buffer capacity %d", n, baseCount)
	}
	p.candidates += uint64(n)
	for i := 0; i < n; i++ {
		id := int(binary.LittleEndian.Uint32(p.ids[i*4 : i*4+4]))
		if id >= baseCount*endoFactor {
			return fmt.Errorf("candidate id %d exceeds key count %d", id, baseCount*endoFactor)
		}
		variant, gid := id/baseCount, id%baseCount
		priv := privateKeyForVariantFromBase(chunkBaseSeed(start+uint64(gid/chunkSteps)), uint64(gid%chunkSteps), variant)
		var digest [20]byte
		copy(digest[:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
		if _, found := targets[digest]; found {
			p.hits++
		}
	}
	return nil
}

// BenchmarkHybridGPUScan measures the production CPU fill -> GPU GLV+HASH160+
// populated Bloom -> readback -> rare CPU confirmation pipeline. Each persistent
// producer owns one stream and blocks on its own dispatch while other producers
// fill or dispatch, matching gpuProducer's CPU/GPU overlap. Frontier claim and
// completion plus checked-key counter updates are timed. Console samples,
// checkpoint/match I/O, setup, warmup, and post-run assertions are excluded.
//
// Exactly b.N dispatches complete: one op = chunks*16384*6 hashes with current
// production constants. ReportAllocs covers timed Go allocations, including
// frontier updates and rare confirmations; Metal buffers are allocated before
// timing. Change producer/chunk/threadgroup/target counts via BTC_BENCH_GPU_*.
func BenchmarkHybridGPUScan(b *testing.B) {
	cfg := gpuBenchmarkSettings(b)
	b.Run(cfg.name(), func(b *testing.B) { benchmarkGPUScan(b, cfg, true) })
}

// BenchmarkGPUDispatch isolates concurrent GLV+HASH160+populated Bloom dispatch
// and completion/readback overhead. Buffers are filled once before timing and
// reused without CPU EC work, frontier updates, or CPU exact confirmation. Its
// throughput is a device ceiling, not complete search throughput. One operation
// and the environment controls are identical to BenchmarkHybridGPUScan.
func BenchmarkGPUDispatch(b *testing.B) {
	cfg := gpuBenchmarkSettings(b)
	b.Run(cfg.name(), func(b *testing.B) { benchmarkGPUScan(b, cfg, false) })
}

func benchmarkGPUScan(b *testing.B, cfg gpuBenchmarkConfig, hybrid bool) {
	hasher, err := gpumetal.New()
	if err != nil {
		if err.Error() == "metal: no Metal device available" {
			b.Skipf("Metal unavailable: %v", err)
		}
		b.Fatalf("Metal initialization failed: %v", err)
	}
	b.Cleanup(hasher.Close)
	hasher.SetThreadgroup(cfg.threadgroup)
	targets := gpuBenchmarkTargets(cfg.targets)
	bf := newBloomFromTargets(targets, gpuBloomFPR)
	bloom := gpuBenchmarkBuffer(b, hasher, bf.byteLen())
	bf.writeTo(bloom.Bytes())
	baseCount := cfg.chunks * chunkSteps
	keyCount := uint64(baseCount * endoFactor)
	workers := make([]*gpuBenchmarkProducer, cfg.producers)
	for i := range workers {
		workers[i] = gpuBenchmarkNewProducer(b, hasher, baseCount)
	}

	// Warm every persistent queue and compile the kernel before measuring. All
	// workers use disjoint input ranges, as in production. GPU runtime allocation
	// and the initial CPU fill/seed preparation are excluded from the timer.
	for i, p := range workers {
		start := uint64(i * cfg.chunks)
		p.fill(start, cfg.chunks)
		if err := p.dispatch(bloom, bf, baseCount); err != nil {
			b.Fatalf("warmup dispatch: %v", err)
		}
		if err := p.confirm(start, baseCount, targets); err != nil {
			b.Fatalf("warmup confirm: %v", err)
		}
		if p.hits != 0 {
			b.Fatal("synthetic target unexpectedly matches warmup input")
		}
		p.candidates = 0
	}

	tracker := newFrontierTracker(0)
	var tickets, checked atomic.Uint64
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(len(workers))
	done.Add(len(workers))
	for pid, p := range workers {
		go func(pid int, p *gpuBenchmarkProducer) {
			defer done.Done()
			ready.Done()
			<-start
			for tickets.Add(1) <= uint64(b.N) {
				chunk := uint64(pid * cfg.chunks) // prefilled dispatch-only range
				if hybrid {
					chunk = tracker.claim(uint64(cfg.chunks))
					p.fill(chunk, cfg.chunks)
				}
				if p.err = p.dispatch(bloom, bf, baseCount); p.err != nil {
					return
				}
				checked.Add(keyCount)
				if hybrid {
					if p.err = p.confirm(chunk, baseCount, targets); p.err != nil {
						return
					}
					tracker.complete(chunk, uint64(cfg.chunks))
				} else {
					// Read completion data just as a host consumer would. No CPU
					// hashing is included in the isolated GPU ceiling measurement.
					n := uint64(binary.LittleEndian.Uint32(p.count[:4]))
					if n > uint64(baseCount) {
						p.err = fmt.Errorf("candidate count %d exceeds capacity %d", n, baseCount)
						return
					}
					p.candidates += n
				}
				p.completed++
			}
		}(pid, p)
	}
	ready.Wait()
	b.ReportAllocs()
	b.ResetTimer()
	close(start)
	done.Wait()
	b.StopTimer()

	var dispatches, candidates, hits uint64
	for i, p := range workers {
		if p.err != nil {
			b.Fatalf("producer %d: %v", i, p.err)
		}
		dispatches += p.completed
		candidates += p.candidates
		hits += p.hits
	}
	want := uint64(b.N) * keyCount
	if dispatches != uint64(b.N) || checked.Load() != want || hits != 0 {
		b.Fatalf("dispatches=%d want=%d checked=%d want=%d synthetic hits=%d", dispatches, b.N, checked.Load(), want, hits)
	}
	if hybrid && tracker.frontierChunk() != uint64(b.N)*uint64(cfg.chunks) {
		b.Fatalf("frontier=%d want=%d", tracker.frontierChunk(), uint64(b.N)*uint64(cfg.chunks))
	}
	var setBits uint64
	for _, word := range bf.bits {
		setBits += uint64(bits.OnesCount32(word))
	}
	b.ReportMetric(float64(want)/b.Elapsed().Seconds(), "hashes/s")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(want), "ns/hash")
	b.ReportMetric(float64(keyCount), "hashes/dispatch")
	b.ReportMetric(float64(candidates)/float64(b.N), "candidates/dispatch")
	b.ReportMetric(float64(bf.byteLen()), "bloom_bytes")
	b.ReportMetric(float64(bf.k), "bloom_probes")
	b.ReportMetric(100*float64(setBits)/float64(uint64(bf.mask)+1), "bloom_occupancy_pct")
}

// TestGPUPerformanceFixture validates the populated benchmark Bloom and all six
// candidate-id mappings outside timed runs. The expected hashes use btcec scalar
// multiplication and btcutil.Hash160, independently of GPU arithmetic/hashing.
// Every GPU candidate must agree exactly with the CPU Bloom oracle, including
// false positives; planted targets prove that hit handling is exercised.
func TestGPUPerformanceFixture(t *testing.T) {
	hasher, err := gpumetal.New()
	if err != nil {
		if err.Error() == "metal: no Metal device available" {
			t.Skipf("Metal unavailable: %v", err)
		}
		t.Fatalf("Metal initialization failed: %v", err)
	}
	t.Cleanup(hasher.Close)
	const count = 64
	seed := chunkBaseSeed(11)
	targets := gpuBenchmarkTargets(65536)
	var digests [count * endoFactor][20]byte
	for step := 0; step < count; step++ {
		for variant := 0; variant < endoFactor; variant++ {
			priv := privateKeyForVariantFromBase(seed, uint64(step), variant)
			copy(digests[variant*count+step][:], btcutil.Hash160(priv.PubKey().SerializeCompressed()))
			if step%13 == 0 {
				targets[digests[variant*count+step]] = struct{}{}
			}
		}
	}
	bf := newBloomFromTargets(targets, gpuBloomFPR)
	bloom := gpuBenchmarkBuffer(t, hasher, bf.byteLen())
	bf.writeTo(bloom.Bytes())
	p := gpuBenchmarkNewProducer(t, hasher, count)
	p.ks.setBase(seed)
	p.ks.pubBuf = p.input
	p.ks.fillBasePubkeysSteps(count)
	if err := p.dispatch(bloom, bf, count); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	n := int(binary.LittleEndian.Uint32(p.count[:4]))
	if n > count {
		t.Fatalf("candidate count %d exceeds capacity %d", n, count)
	}
	got := make(map[uint32]bool, n)
	for i := 0; i < n; i++ {
		id := binary.LittleEndian.Uint32(p.ids[i*4 : i*4+4])
		if id >= uint32(len(digests)) || got[id] {
			t.Fatalf("invalid or duplicate candidate id %d", id)
		}
		got[id] = true
	}
	confirmed := 0
	for id, digest := range digests {
		if want := bf.test(digest); got[uint32(id)] != want {
			t.Errorf("candidate id %d: GPU=%v CPU Bloom=%v", id, got[uint32(id)], want)
		}
		if _, found := targets[digest]; found {
			if !got[uint32(id)] {
				t.Errorf("planted target id %d missing", id)
			}
			confirmed++
		}
	}
	if confirmed != ((count-1)/13+1)*endoFactor {
		t.Fatalf("confirmed=%d want=%d", confirmed, ((count-1)/13+1)*endoFactor)
	}
	t.Logf("%d base points, %d independent hashes, %d GPU candidates, %d planted targets; Bloom %d bytes, k=%d", count, len(digests), n, confirmed, bf.byteLen(), bf.k)
}
