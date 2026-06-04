//go:build darwin && cgo && !nometal

package metal

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// secpN is the secp256k1 group order (scalar field modulus).
var secpN, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// ecTestKernels expose ec_walk.metal point arithmetic element-wise so the host
// can diff GPU results against a btcec reference.
const ecTestKernels = `
kernel void ec_add_test(device const uint* in [[buffer(0)]], device uint* out [[buffer(1)]],
                        constant uint& count [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    if (gid >= count) return;
    device const uint* e = in + gid * 32u; // 4 field elements: xp, yp, xq, yq
    uint xp[8], yp[8], xq[8], yq[8], x3[8], y3[8];
    for (int i = 0; i < 8; i++) { xp[i] = e[i]; yp[i] = e[8+i]; xq[i] = e[16+i]; yq[i] = e[24+i]; }
    ec_affine_add(xp, yp, xq, yq, x3, y3);
    device uint* o = out + gid * 16u;
    for (int i = 0; i < 8; i++) { o[i] = x3[i]; o[8+i] = y3[i]; }
}
`

// scalarMulG returns the affine coordinates (as big.Int) of k*G for k in [1, n),
// via btcec as the independent reference.
func scalarMulG(k *big.Int) (x, y *big.Int) {
	var kb [32]byte
	k.FillBytes(kb[:])
	_, pub := btcec.PrivKeyFromBytes(kb[:])
	u := pub.SerializeUncompressed() // 0x04 || X(32) || Y(32)
	return new(big.Int).SetBytes(u[1:33]), new(big.Int).SetBytes(u[33:65])
}

// randScalar returns a uniform nonzero scalar in [1, n).
func randScalar(rng *rand.Rand) *big.Int {
	for {
		var b [32]byte
		rng.Read(b[:])
		k := new(big.Int).Mod(new(big.Int).SetBytes(b[:]), secpN)
		if k.Sign() != 0 {
			return k
		}
	}
}

// TestGPUECAdd diffs the GPU affine point addition (ec_affine_add) against btcec:
// for random scalars a, b it checks aG + bG == (a+b)G. It is the foundational
// correctness gate for the on-GPU EC walk — every walked point is a chain of
// these additions, so a single slope/inverse/reduce bug would corrupt the keys.
func TestGPUECAdd(t *testing.T) {
	h := newTestHasher(t, ecTestKernels)
	defer h.Close()

	const n = 20000
	rng := rand.New(rand.NewSource(0xEC0FFEE))
	in := make([]byte, n*128) // 4 field elements * 32 bytes each
	type pt struct{ x, y *big.Int }
	want := make([]pt, n)
	for i := 0; i < n; i++ {
		a := randScalar(rng)
		b := randScalar(rng)
		// Require distinct x (P != Q and P != -Q): a != b and a+b != n.
		for a.Cmp(b) == 0 || new(big.Int).Add(a, b).Cmp(secpN) == 0 {
			b = randScalar(rng)
		}
		xp, yp := scalarMulG(a)
		xq, yq := scalarMulG(b)
		sum := new(big.Int).Mod(new(big.Int).Add(a, b), secpN)
		rx, ry := scalarMulG(sum)
		want[i] = pt{rx, ry}
		base := i * 128
		putLimbsLE(in[base:base+32], xp)
		putLimbsLE(in[base+32:base+64], yp)
		putLimbsLE(in[base+64:base+96], xq)
		putLimbsLE(in[base+96:base+128], yq)
	}
	out := runProbe(t, h, "ec_add_test", in, n*64, []uint32{uint32(n)}, n)
	for i := 0; i < n; i++ {
		gx := limbsLEToBig(out[i*64 : i*64+32])
		gy := limbsLEToBig(out[i*64+32 : i*64+64])
		if gx.Cmp(want[i].x) != 0 || gy.Cmp(want[i].y) != 0 {
			t.Fatalf("ec_affine_add mismatch at %d:\n got =(%064x, %064x)\n want=(%064x, %064x)",
				i, gx, gy, want[i].x, want[i].y)
		}
	}
	t.Logf("ec_affine_add: %d random point additions OK", n)
}
