//go:build darwin && cgo && !nometal

package metal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	hash160mb "github.com/Asylian21/sha256mb/hash160mb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
)

// stride mirrors the production keyStream.pubBuf slot width (cache-line aligned).
const testStride = 64

// fillRandomMessages writes count pseudo-random 33-byte messages into buf at the
// given stride (byte 0 set to a realistic 0x02/0x03 compressed-pubkey prefix).
// Hash160 only hashes bytes, so message validity is irrelevant to correctness;
// this lets the bit-exact test cover a million messages without paying for a
// scalar multiplication per key.
func fillRandomMessages(buf []byte, count, stride int) {
	rng := rand.New(rand.NewSource(0x1e3779b97f4a7c15))
	for i := 0; i < count; i++ {
		msg := buf[i*stride : i*stride+33]
		rng.Read(msg)
		msg[0] = 0x02 | byte(i&1)
	}
}

func newHasherOrSkip(t testing.TB) *Hasher {
	t.Helper()
	h, err := New()
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	return h
}

// TestHash160BitExact proves the GPU kernel is bit-for-bit identical to the
// reference btcutil.Hash160 over one million messages. A single mismatch fails
// the run (a wrong GPU hash would silently miss every real match).
func TestHash160BitExact(t *testing.T) {
	const n = 1_000_000
	h := newHasherOrSkip(t)
	defer h.Close()
	t.Logf("Metal device: %s", h.Name())

	in, err := h.NewBuffer(n * testStride)
	if err != nil {
		t.Fatalf("NewBuffer(in): %v", err)
	}
	defer in.Free()
	out, err := h.NewBuffer(n * 20)
	if err != nil {
		t.Fatalf("NewBuffer(out): %v", err)
	}
	defer out.Free()

	src := in.Bytes()
	fillRandomMessages(src, n, testStride)

	if err := h.Hash160(in, out, n, testStride); err != nil {
		t.Fatalf("Hash160: %v", err)
	}

	res := out.Bytes()
	mismatches := 0
	for i := 0; i < n; i++ {
		want := btcutil.Hash160(src[i*testStride : i*testStride+33])
		got := res[i*20 : i*20+20]
		if !bytes.Equal(got, want) {
			if mismatches < 5 {
				t.Errorf("message %d: GPU %x != reference %x", i, got, want)
			}
			mismatches++
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d/%d messages mismatched", mismatches, n)
	}
}

// TestHash160RealPubkeys runs genuine secp256k1 compressed public keys through
// the kernel (prefix 0x02/0x03 + valid X), as a faithfulness check on top of the
// random-message coverage.
func TestHash160RealPubkeys(t *testing.T) {
	const n = 1024
	h := newHasherOrSkip(t)
	defer h.Close()

	in, err := h.NewBuffer(n * testStride)
	if err != nil {
		t.Fatalf("NewBuffer(in): %v", err)
	}
	defer in.Free()
	out, err := h.NewBuffer(n * 20)
	if err != nil {
		t.Fatalf("NewBuffer(out): %v", err)
	}
	defer out.Free()

	src := in.Bytes()
	for i := 0; i < n; i++ {
		var priv [32]byte
		binary.BigEndian.PutUint64(priv[24:], uint64(i+1))
		_, pub := btcec.PrivKeyFromBytes(priv[:])
		copy(src[i*testStride:i*testStride+33], pub.SerializeCompressed())
	}

	if err := h.Hash160(in, out, n, testStride); err != nil {
		t.Fatalf("Hash160: %v", err)
	}

	res := out.Bytes()
	for i := 0; i < n; i++ {
		want := btcutil.Hash160(src[i*testStride : i*testStride+33])
		got := res[i*20 : i*20+20]
		if !bytes.Equal(got, want) {
			t.Fatalf("pubkey %d: GPU %x != reference %x", i+1, got, want)
		}
	}
}

// BenchmarkGPUHash160 reports the GPU Hash160 throughput across batch sizes (a
// 6144-key production batch is far too small to saturate the GPU; this sweeps up
// to 1M to find the saturation point). Run with:
//
//	go test -run '^$' -bench BenchmarkGPUHash160 ./gpu/metal/
func BenchmarkGPUHash160(b *testing.B) {
	for _, n := range []int{16384, 65536, 262144, 1048576} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			h := newHasherOrSkip(b)
			defer h.Close()
			in, err := h.NewBuffer(n * testStride)
			if err != nil {
				b.Fatalf("NewBuffer(in): %v", err)
			}
			defer in.Free()
			out, err := h.NewBuffer(n * 20)
			if err != nil {
				b.Fatalf("NewBuffer(out): %v", err)
			}
			defer out.Free()
			fillRandomMessages(in.Bytes(), n, testStride)

			// Warm up: first dispatch allocates/encodes lazily.
			for i := 0; i < 3; i++ {
				_ = h.Hash160(in, out, n, testStride)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := h.Hash160(in, out, n, testStride); err != nil {
					b.Fatalf("Hash160: %v", err)
				}
			}
			b.StopTimer()
			keysPerSec := float64(n) * float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(keysPerSec/1e6, "Mkeys/s")
		})
	}
}

// BenchmarkCPUHash160 is the CPU baseline (same fused multi-buffer HASH160 the
// worker uses today), for a direct GPU-vs-CPU comparison on identical data.
func BenchmarkCPUHash160(b *testing.B) {
	for _, n := range []int{16384, 65536, 262144, 1048576} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			pub := make([]byte, n*testStride)
			fillRandomMessages(pub, n, testStride)
			out := make([]byte, n*20)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hash160mb.FromPubkeys33(out, pub, n, testStride)
			}
			b.StopTimer()
			keysPerSec := float64(n) * float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(keysPerSec/1e6, "Mkeys/s")
		})
	}
}
