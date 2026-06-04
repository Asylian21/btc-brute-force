//go:build darwin && cgo && !nometal

package metal

import "testing"

// This file provides a small differential test harness: it compiles the
// production Metal library together with extra test-only kernels, then runs any
// of them over input bytes and returns the output bytes. Later phases use it to
// validate secp256k1 field operations and the EC walk against Go references by
// running probe kernels on the GPU and comparing byte-for-byte.

// newTestHasher builds a Hasher whose library is the production source plus
// extraSrc (test-only kernels). It skips the test if no Metal device is present.
func newTestHasher(t testing.TB, extraSrc string) *Hasher {
	t.Helper()
	h, err := newWithSource(metalLibrarySource() + "\n" + extraSrc)
	if err != nil {
		t.Skipf("Metal unavailable: %v", err)
	}
	return h
}

// runProbe dispatches kernel `name` over `grid` threads with input bytes `in`
// bound at buffer(0), a fresh output buffer of outLen bytes bound at buffer(1),
// and scalars bound via setBytes at the following indices. It returns a copy of
// the output bytes. It is the building block for differential GPU-vs-Go tests.
func runProbe(t testing.TB, h *Hasher, name string, in []byte, outLen int, scalars []uint32, grid int) []byte {
	t.Helper()
	inBuf, err := h.NewBuffer(len(in))
	if err != nil {
		t.Fatalf("NewBuffer(in): %v", err)
	}
	defer inBuf.Free()
	copy(inBuf.Bytes(), in)

	outBuf, err := h.NewBuffer(outLen)
	if err != nil {
		t.Fatalf("NewBuffer(out): %v", err)
	}
	defer outBuf.Free()

	if err := h.dispatch(name, []*Buffer{inBuf, outBuf}, scalars, grid); err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}

	out := make([]byte, outLen)
	copy(out, outBuf.Bytes())
	return out
}

// probeAddKernel is a trivial test kernel that proves the generic dispatch path:
// buffer binding (in/out), scalar binding order (addend at nbufs+0, count at
// nbufs+1), and grid sizing. out[gid] = in[gid] + addend.
const probeAddKernel = `
kernel void probe_add_kernel(device const uint* in   [[buffer(0)]],
                             device uint*       out  [[buffer(1)]],
                             constant uint&     addend [[buffer(2)]],
                             constant uint&     count  [[buffer(3)]],
                             uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    out[gid] = in[gid] + addend;
}
`

// TestComputeHarness validates the generic dispatch + differential harness with
// a trivial add kernel, so the secp256k1 field/EC probes built on it can be
// trusted to be exercising the GPU correctly.
func TestComputeHarness(t *testing.T) {
	h := newTestHasher(t, probeAddKernel)
	defer h.Close()

	const n = 4096
	const addend = 0x01020304
	in := make([]byte, n*4)
	for i := 0; i < n; i++ {
		v := uint32(i * 2654435761) // scramble
		in[i*4+0] = byte(v)
		in[i*4+1] = byte(v >> 8)
		in[i*4+2] = byte(v >> 16)
		in[i*4+3] = byte(v >> 24)
	}

	out := runProbe(t, h, "probe_add_kernel", in, n*4, []uint32{addend, n}, n)

	for i := 0; i < n; i++ {
		want := (uint32(in[i*4]) | uint32(in[i*4+1])<<8 | uint32(in[i*4+2])<<16 | uint32(in[i*4+3])<<24) + addend
		got := uint32(out[i*4]) | uint32(out[i*4+1])<<8 | uint32(out[i*4+2])<<16 | uint32(out[i*4+3])<<24
		if got != want {
			t.Fatalf("probe_add[%d] = %#08x, want %#08x", i, got, want)
		}
	}
}
