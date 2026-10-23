//go:build darwin && cgo && !nometal

package metal

import (
	"encoding/binary"
	"strings"
	"testing"
)

// A dense Bloom filter can admit six variants per base, while the documented
// output contract has only one candidate slot per base. Both APIs must reject
// that incomplete output and preserve the kernel's write bound.
func TestGLVFilterCandidateOverflow(t *testing.T) {
	h := newHasherOrSkip(t)
	defer h.Close()
	const count = 7 // Also exercises a grid smaller than one SIMD group.
	const guard = uint32(0xdecafbad)
	in, err := h.NewBuffer(count * testStride)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Free()
	fillRandomMessages(in.Bytes(), count, testStride)
	bloom, err := h.NewBuffer(4)
	if err != nil {
		t.Fatal(err)
	}
	defer bloom.Free()
	mcount, err := h.NewBuffer(4)
	if err != nil {
		t.Fatal(err)
	}
	defer mcount.Free()
	mdata, err := h.NewBuffer((count + 1) * 4)
	if err != nil {
		t.Fatal(err)
	}
	defer mdata.Free()
	stream, err := h.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Free()

	for _, tc := range []struct {
		name string
		run  func(*Buffer, *Buffer, *Buffer, *Buffer, int, int, uint32, uint32) error
	}{
		{"default", h.GLVFilter},
		{"stream", stream.GLVFilterStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, dense := range []bool{true, false} {
				bits := uint32(0)
				if dense {
					bits = ^uint32(0)
				}
				binary.LittleEndian.PutUint32(bloom.Bytes(), bits)
				binary.LittleEndian.PutUint32(mcount.Bytes(), 0)
				binary.LittleEndian.PutUint32(mdata.Bytes()[count*4:], guard)
				err := tc.run(in, bloom, mcount, mdata, count, testStride, 31, 1)
				got := binary.LittleEndian.Uint32(mcount.Bytes())
				if dense {
					if err == nil || !strings.Contains(err.Error(), "candidate buffer overflow") {
						t.Fatalf("dense Bloom: expected overflow error, got %v", err)
					}
					if got != count*6 {
						t.Fatalf("dense Bloom count: got %d want %d", got, count*6)
					}
				} else if err != nil || got != 0 {
					t.Fatalf("empty Bloom: err=%v candidates=%d", err, got)
				}
				if got := binary.LittleEndian.Uint32(mdata.Bytes()[count*4:]); got != guard {
					t.Fatalf("kernel wrote beyond candidate capacity: guard=%08x", got)
				}
			}
		})
	}
}

func TestGLVFilterEmptyAndNilInputs(t *testing.T) {
	var h *Hasher
	var stream *Stream
	if err := h.GLVFilter(nil, nil, nil, nil, 0, 0, 0, 0); err != nil {
		t.Fatalf("empty default dispatch: %v", err)
	}
	if err := stream.GLVFilterStream(nil, nil, nil, nil, 0, 0, 0, 0); err != nil {
		t.Fatalf("empty stream dispatch: %v", err)
	}
	for _, missing := range []int{0, 1, 2} {
		bufs := [3]*Buffer{{data: make([]byte, testStride)}, {data: make([]byte, 4)}, {data: make([]byte, 4)}}
		bufs[missing] = nil
		if err := glvFilterArgs(bufs[0], bufs[1], bufs[2], 1, testStride); err == nil {
			t.Fatalf("missing buffer %d accepted", missing)
		}
	}
}
