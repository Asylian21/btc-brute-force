package main

import (
	"sync/atomic"
	"testing"
)

// BenchmarkBasePubkeyStream measures the CPU producer used by the hybrid GPU
// pipeline. ns/op counts one base point; each becomes six hashes on the GPU.
func BenchmarkBasePubkeyStream(b *testing.B) {
	ks := newKeyStreamSeeded([32]byte{1, 2, 3})
	b.ReportAllocs()
	b.ResetTimer()
	produced := 0
	for produced < b.N {
		ks.fillBasePubkeysSteps(keyBatchSize)
		produced += keyBatchSize
	}
	// A whole batch can overshoot b.N; divide by points actually generated.
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(produced), "ns/op")
}

// BenchmarkKeyStreamParallel measures sustained throughput with concurrent
// CPU workers, including each worker's real EC walk and HASH160 pipeline.
// ns/op counts a whole batch; hashes/s counts every resulting hash.
func BenchmarkKeyStreamParallel(b *testing.B) {
	const total = endoFactor * keyBatchSize
	var nextSeed atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		seed := [32]byte{1, 2, 3}
		seed[31] = byte(nextSeed.Add(1))
		ks := newKeyStreamSeeded(seed)
		hashes := make([][20]byte, total)
		for pb.Next() {
			ks.nextBatch(hashes)
		}
	})
	b.ReportMetric(float64(b.N)*float64(total)/b.Elapsed().Seconds(), "hashes/s")
}
