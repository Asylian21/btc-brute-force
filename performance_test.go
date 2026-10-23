package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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

// BenchmarkCPUScan includes chunk rebasing, cursor/counter atomics and exact
// target-map lookups in addition to the EC/HASH160 pipeline. Targets are
// deterministic synthetic digests; this never loads an address file or writes
// matches/checkpoints. One operation walks an entire production-sized chunk.
// Console sampling, match handling and checkpoint I/O are excluded.
func BenchmarkCPUScan(b *testing.B) {
	for _, count := range []int{20, 65536} {
		b.Run(fmt.Sprintf("targets=%d", count), func(b *testing.B) {
			targets := make(hash160Set, count)
			for i := 0; i < count; i++ {
				var input [8]byte
				binary.LittleEndian.PutUint64(input[:], uint64(i))
				digest := sha256.Sum256(input[:])
				var target [20]byte
				copy(target[:], digest[:])
				targets[target] = struct{}{}
			}
			var cursor, checked, hits atomic.Uint64
			stop := make(chan struct{})
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				ks := newKeyStreamSeeded([32]byte{1, 2, 3})
				hashes := make([][20]byte, endoFactor*keyBatchSize)
				var progress atomic.Uint64
				var localHits uint64
				for pb.Next() {
					chunk := cursor.Add(1) - 1
					progress.Store(chunk)
					ks.setBase(addOffsetToSeed([32]byte{1, 2, 3}, chunk*chunkSteps))
					for batch := 0; batch < chunkBatches; batch++ {
						select {
						case <-stop:
							return
						default:
						}
						ks.nextBatch(hashes)
						checked.Add(uint64(len(hashes)))
						for _, hash := range hashes {
							if _, found := targets[hash]; found {
								localHits++
							}
						}
					}
				}
				hits.Add(localHits)
			})
			b.StopTimer()
			want := uint64(b.N) * chunkSteps * endoFactor
			if checked.Load() != want || hits.Load() != 0 {
				b.Fatalf("checked=%d want=%d hits=%d", checked.Load(), want, hits.Load())
			}
			b.ReportMetric(float64(want)/b.Elapsed().Seconds(), "hashes/s")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(want), "ns/hash")
		})
	}
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
