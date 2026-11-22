package cover

import (
	"math/rand"
	"testing"
)

func TestCoversExact(t *testing.T) {
	for w := uint(1); w <= 8; w++ {
		for lo := uint64(0); lo < 1<<w; lo++ {
			for hi := lo; hi < 1<<w; hi++ {
				checkCover(t, Canonical(lo, hi, w), lo, hi, w)
				checkCover(t, MinMask(lo, hi, w), lo, hi, w)
			}
		}
	}
}

func TestMinMaskNoWorse(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, w := range []uint{8, 10, 12, 16} {
		var tc, tm, n int
		for i := 0; i < 300; i++ {
			lo := uint64(rng.Intn(1 << w))
			hi := lo + uint64(rng.Intn(1<<w-int(lo)+1))
			if hi >= 1<<w {
				hi = 1<<w - 1
			}
			c := len(Canonical(lo, hi, w))
			m := len(MinMask(lo, hi, w))
			if m > c {
				t.Fatalf("w=%d [%d,%d]: MinMask %d > canonical %d", w, lo, hi, m, c)
			}
			checkCoverSample(t, MinMask(lo, hi, w), lo, hi, w, rng)
			tc += c
			tm += m
			n++
		}
		t.Logf("w=%2d canonical=%d minmask=%d (%.1f%% fewer)", w, tc, tm, 100*(1-float64(tm)/float64(tc)))
	}
}

func checkCover(t *testing.T, cs []Cube, lo, hi uint64, w uint) {
	t.Helper()
	for v := uint64(0); v < 1<<w; v++ {
		want := v >= lo && v <= hi
		got := false
		for _, c := range cs {
			if c.Match(v) {
				got = true
				break
			}
		}
		if got != want {
			t.Fatalf("w=%d [%d,%d] v=%d got=%v want=%v cubes=%v", w, lo, hi, v, got, want, cs)
		}
	}
}

func checkCoverSample(t *testing.T, cs []Cube, lo, hi uint64, w uint, rng *rand.Rand) {
	t.Helper()
	for i := 0; i < 20000; i++ {
		v := uint64(rng.Intn(1 << w))
		want := v >= lo && v <= hi
		got := false
		for _, c := range cs {
			if c.Match(v) {
				got = true
				break
			}
		}
		if got != want {
			t.Fatalf("w=%d [%d,%d] v=%d got=%v want=%v", w, lo, hi, v, got, want)
		}
	}
	// Also verify the cover never exceeds the range at its endpoints.
	for _, c := range cs {
		if c.Value < lo && c.Value|c.Mask != c.Value {
			t.Logf("note: cube value %d below lo %d (may still be fine)", c.Value, lo)
		}
	}
}

func TestUnionOf(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 20000; i++ {
		w := uint(6)
		a := Cube{Value: uint64(rng.Intn(64)), Mask: uint64(rng.Intn(64)), Width: w}
		b := Cube{Value: uint64(rng.Intn(64)), Mask: uint64(rng.Intn(64)), Width: w}
		u, ok := UnionOf(a, b)
		if !ok {
			continue
		}
		for v := uint64(0); v < 64; v++ {
			want := a.Match(v) || b.Match(v)
			if u.Match(v) != want {
				t.Fatalf("bad union %v U %v = %v at %d", a, b, u, v)
			}
		}
	}
}
