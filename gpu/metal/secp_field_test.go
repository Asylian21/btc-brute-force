//go:build darwin && cgo && !nometal

package metal

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"
)

// secpP is the secp256k1 field prime p = 2^256 - 2^32 - 977.
var secpP, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// fieldTestKernels are test-only kernels that expose the secp_field.metal fe_*
// operations element-wise so the host can run them on >= 1e5 inputs and diff the
// results against a math/big reference. Binary ops read a||b (16 limbs) per
// element; unary ops read a (8 limbs). All write 8 little-endian limbs.
const fieldTestKernels = `
kernel void fp_add_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 16u;
    uint a[8], b[8], r[8];
    for (int i = 0; i < 8; i++) { a[i] = e[i]; b[i] = e[8 + i]; }
    fe_add(a, b, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
kernel void fp_sub_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 16u;
    uint a[8], b[8], r[8];
    for (int i = 0; i < 8; i++) { a[i] = e[i]; b[i] = e[8 + i]; }
    fe_sub(a, b, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
kernel void fp_mul_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 16u;
    uint a[8], b[8], r[8];
    for (int i = 0; i < 8; i++) { a[i] = e[i]; b[i] = e[8 + i]; }
    fe_mul(a, b, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
kernel void fp_sqr_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 8u;
    uint a[8], r[8];
    for (int i = 0; i < 8; i++) a[i] = e[i];
    fe_sqr(a, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
kernel void fp_inv_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 8u;
    uint a[8], r[8];
    for (int i = 0; i < 8; i++) a[i] = e[i];
    fe_inv(a, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
kernel void fp_normalize_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                              constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 8u;
    uint a[8], r[8];
    for (int i = 0; i < 8; i++) a[i] = e[i];
    fe_normalize(a, r);
    device uint* o = out + gid * 8u;
    for (int i = 0; i < 8; i++) o[i] = r[i];
}
`

func bigToLimbsLE(x *big.Int) [8]uint32 {
	var out [8]uint32
	t := new(big.Int).Set(x)
	mask := big.NewInt(0xFFFFFFFF)
	w := new(big.Int)
	for i := 0; i < 8; i++ {
		w.And(t, mask)
		out[i] = uint32(w.Uint64())
		t.Rsh(t, 32)
	}
	return out
}

func limbsLEToBig(b []byte) *big.Int {
	r := new(big.Int)
	for i := 7; i >= 0; i-- {
		r.Lsh(r, 32)
		r.Or(r, new(big.Int).SetUint64(uint64(binary.LittleEndian.Uint32(b[i*4:]))))
	}
	return r
}

func putLimbsLE(dst []byte, x *big.Int) {
	l := bigToLimbsLE(x)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(dst[i*4:], l[i])
	}
}

// randField returns a uniformly random reduced field element (< p).
func randField(rng *rand.Rand) *big.Int {
	var b [32]byte
	rng.Read(b[:])
	return new(big.Int).Mod(new(big.Int).SetBytes(b[:]), secpP)
}

// randRaw256 returns a random 256-bit value, often >= p (for normalize tests).
func randRaw256(rng *rand.Rand) *big.Int {
	var b [32]byte
	rng.Read(b[:])
	return new(big.Int).SetBytes(b[:])
}

// TestGPUFieldBinaryOps diffs fe_add/fe_sub/fe_mul against math/big over many
// random reduced inputs.
func TestGPUFieldBinaryOps(t *testing.T) {
	h := newTestHasher(t, fieldTestKernels)
	defer h.Close()

	const n = 200000
	rng := rand.New(rand.NewSource(0x5EC9F1E1D))

	type opCase struct {
		name   string
		kernel string
		ref    func(a, b *big.Int) *big.Int
	}
	cases := []opCase{
		{"add", "fp_add_test", func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), secpP) }},
		{"sub", "fp_sub_test", func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), secpP) }},
		{"mul", "fp_mul_test", func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), secpP) }},
	}

	as := make([]*big.Int, n)
	bs := make([]*big.Int, n)
	in := make([]byte, n*16*4)
	for i := 0; i < n; i++ {
		as[i] = randField(rng)
		bs[i] = randField(rng)
		putLimbsLE(in[i*64:i*64+32], as[i])
		putLimbsLE(in[i*64+32:i*64+64], bs[i])
	}

	for _, c := range cases {
		out := runProbe(t, h, c.kernel, in, n*32, []uint32{uint32(n)}, n)
		for i := 0; i < n; i++ {
			got := limbsLEToBig(out[i*32 : i*32+32])
			want := c.ref(as[i], bs[i])
			if got.Cmp(want) != 0 {
				t.Fatalf("fe_%s mismatch at %d:\n a=%064x\n b=%064x\n got =%064x\n want=%064x",
					c.name, i, as[i], bs[i], got, want)
			}
		}
		t.Logf("fe_%s: %d random inputs OK", c.name, n)
	}
}

// TestGPUFieldSqr diffs fe_sqr against math/big.
func TestGPUFieldSqr(t *testing.T) {
	h := newTestHasher(t, fieldTestKernels)
	defer h.Close()

	const n = 200000
	rng := rand.New(rand.NewSource(0x59112))
	as := make([]*big.Int, n)
	in := make([]byte, n*32)
	for i := 0; i < n; i++ {
		as[i] = randField(rng)
		putLimbsLE(in[i*32:i*32+32], as[i])
	}
	out := runProbe(t, h, "fp_sqr_test", in, n*32, []uint32{uint32(n)}, n)
	for i := 0; i < n; i++ {
		got := limbsLEToBig(out[i*32 : i*32+32])
		want := new(big.Int).Mod(new(big.Int).Mul(as[i], as[i]), secpP)
		if got.Cmp(want) != 0 {
			t.Fatalf("fe_sqr mismatch at %d:\n a=%064x\n got =%064x\n want=%064x", i, as[i], got, want)
		}
	}
	t.Logf("fe_sqr: %d random inputs OK", n)
}

// TestGPUFieldNormalize diffs fe_normalize over RAW (often >= p) inputs.
func TestGPUFieldNormalize(t *testing.T) {
	h := newTestHasher(t, fieldTestKernels)
	defer h.Close()

	const n = 200000
	rng := rand.New(rand.NewSource(0x404A11))
	// The window [p, 2^256) has width only 2^32+977, so a uniform 256-bit value
	// is essentially never >= p. Explicitly construct in-range values >= p (and p
	// itself, which must normalize to 0) so the conditional subtract is exercised.
	overflow := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), secpP) // 2^256 - p = c
	as := make([]*big.Int, n)
	in := make([]byte, n*32)
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			as[i] = randField(rng) // < p
		case 1:
			// p + small  in (p, 2^256)
			small := new(big.Int).Mod(randRaw256(rng), overflow)
			as[i] = new(big.Int).Add(secpP, small)
		case 2:
			as[i] = new(big.Int).Set(secpP) // == p -> 0
		default:
			as[i] = randRaw256(rng) // uniform 256-bit (almost always < p)
		}
		putLimbsLE(in[i*32:i*32+32], as[i])
	}
	out := runProbe(t, h, "fp_normalize_test", in, n*32, []uint32{uint32(n)}, n)
	ge := 0
	for i := 0; i < n; i++ {
		got := limbsLEToBig(out[i*32 : i*32+32])
		want := new(big.Int).Mod(as[i], secpP)
		if got.Cmp(want) != 0 {
			t.Fatalf("fe_normalize mismatch at %d:\n a=%064x\n got =%064x\n want=%064x", i, as[i], got, want)
		}
		if as[i].Cmp(secpP) >= 0 {
			ge++
		}
	}
	t.Logf("fe_normalize: %d inputs OK (%d were >= p)", n, ge)
}

// TestGPUFieldInverse diffs fe_inv against math/big ModInverse. A correct
// inverse is the most demanding check: any multiply/reduce bug breaks it.
func TestGPUFieldInverse(t *testing.T) {
	h := newTestHasher(t, fieldTestKernels)
	defer h.Close()

	const n = 100000
	rng := rand.New(rand.NewSource(0x10E125))
	as := make([]*big.Int, n)
	in := make([]byte, n*32)
	for i := 0; i < n; i++ {
		a := randField(rng)
		if a.Sign() == 0 {
			a = big.NewInt(1)
		}
		as[i] = a
		putLimbsLE(in[i*32:i*32+32], a)
	}
	out := runProbe(t, h, "fp_inv_test", in, n*32, []uint32{uint32(n)}, n)
	for i := 0; i < n; i++ {
		got := limbsLEToBig(out[i*32 : i*32+32])
		want := new(big.Int).ModInverse(as[i], secpP)
		if got.Cmp(want) != 0 {
			t.Fatalf("fe_inv mismatch at %d:\n a=%064x\n got =%064x\n want=%064x", i, as[i], got, want)
		}
		// Sanity: a * a^{-1} == 1 (mod p).
		chk := new(big.Int).Mod(new(big.Int).Mul(as[i], got), secpP)
		if chk.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("fe_inv not an inverse at %d: a*inv = %s", i, chk)
		}
	}
	t.Logf("fe_inv: %d random inputs OK", n)
}
