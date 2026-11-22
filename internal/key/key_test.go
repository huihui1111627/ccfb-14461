package key

import (
	"math/rand"
	"testing"
)

func testLayout() Layout {
	widths := map[string]uint{
		"a": 32, "b": 16, "c": 12, "d": 8, "e": 6, "f": 1,
	}
	return NewLayout([]string{"a", "b", "c", "d", "e", "f"}, widths)
}

func TestFieldRoundTrip(t *testing.T) {
	l := testLayout()
	for field, width := range l.Widths {
		var v uint64
		for i := uint(0); i < width; i++ {
			v |= uint64(1) << i
		}
		// Test every single-bit value plus all-ones and zero.
		cases := []uint64{0, v, v >> 1, 1}
		for _, c := range cases {
			var k Key
			l.PutField(&k, field, c)
			got := l.GetField(k, field)
			if got != c&(v) {
				t.Errorf("%s width %d: put %#x got %#x", field, width, c, got)
			}
		}
	}
}

func TestFieldsDoNotOverlap(t *testing.T) {
	l := testLayout()
	var k Key
	for field := range l.Widths {
		l.PutField(&k, field, ^uint64(0))
	}
	// After writing all ones into every field, the whole used key must be ones.
	for b := uint(0); b < l.Width; b++ {
		if k[b/64]&(1<<(b%64)) == 0 {
			t.Fatalf("bit %d not set after filling every field", b)
		}
	}
}

func TestMatchAndIntersects(t *testing.T) {
	l := testLayout()
	v1, m1 := l.FieldCube("b", 0x1234, 0xff00)
	v2, m2 := l.FieldCube("b", 0x1200, 0xff00)
	if !Intersects(v1, m1, v2, m2) {
		t.Error("12xx and 1234 should intersect")
	}
	v3, m3 := l.FieldCube("b", 0x3400, 0xff00)
	if Intersects(v1, m1, v3, m3) {
		t.Error("34xx and 1234 should not intersect")
	}
	var k Key
	l.PutField(&k, "b", 0x1234)
	if !Match(k, v1, m1) {
		t.Error("1234 should match 1234/ff00")
	}
}

func TestUnionOf(t *testing.T) {
	l := testLayout()
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 2000; i++ {
		// Build two random wildcard patterns over one field.
		val := rng.Uint64() & 0xff
		mask := rng.Uint64() & 0xff
		val &= mask
		val2 := rng.Uint64() & 0xff
		mask2 := rng.Uint64() & 0xff
		val2 &= mask2
		v1, m1 := l.FieldCube("d", val, mask)
		v2, m2 := l.FieldCube("d", val2, mask2)
		u, um, ok := UnionOf(v1, m1, v2, m2)
		if !ok {
			continue
		}
		for x := uint64(0); x < 256; x++ {
			var k Key
			l.PutField(&k, "d", x)
			want := Match(k, v1, m1) || Match(k, v2, m2)
			if Match(k, u, um) != want {
				t.Fatalf("bad union %#x/%#x U %#x/%#x at %#x", val, mask, val2, mask2, x)
			}
		}
	}
}
