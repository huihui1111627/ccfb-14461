package encode

import (
	"math/rand"
	"testing"
)

// TestLabelRoundTrip checks the defining property of the interval map: for
// every value, the label is the index of the interval containing it, and a
// range maps to a contiguous label range that contains exactly the values of
// the range.
func TestLabelRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		width := uint(8)
		var ranges [][2]uint64
		for i := 0; i < 1+rng.Intn(12); i++ {
			lo := uint64(rng.Intn(256))
			hi := lo + uint64(rng.Intn(256-int(lo)))
			ranges = append(ranges, [2]uint64{lo, hi})
		}
		m := BuildIntervalMap("f", width, ranges)
		// Labels must be non-decreasing in value and every value must map.
		prev := m.Label(0)
		for v := uint64(1); v < 256; v++ {
			l := m.Label(v)
			if l < prev {
				t.Fatalf("label decreased at %d: %d < %d", v, l, prev)
			}
			prev = l
		}
		// A range's label span must contain exactly its values' labels.
		for _, r := range ranges {
			lo, hi := m.LabelRange(r[0], r[1])
			for v := uint64(0); v < 256; v++ {
				in := v >= r[0] && v <= r[1]
				l := m.Label(v)
				inLabel := l >= lo && l <= hi
				if in != inLabel {
					t.Fatalf("range %v: value %d in=%v label=%d span=[%d,%d]", r, v, in, l, lo, hi)
				}
			}
		}
	}
}

func TestHasCut(t *testing.T) {
	m := BuildIntervalMap("f", 8, [][2]uint64{{10, 20}, {30, 40}})
	for _, v := range []uint64{0, 10, 21, 30, 41} {
		if !m.HasCut(v) {
			t.Errorf("expected cut at %d", v)
		}
	}
	for _, v := range []uint64{1, 11, 25, 31} {
		if m.HasCut(v) {
			t.Errorf("unexpected cut at %d", v)
		}
	}
}

// TestLabelBitsNeverWiderThanRaw keeps the label encoding from ever costing
// more key bits than the raw field.
func TestLabelBitsNeverWiderThanRaw(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for trial := 0; trial < 500; trial++ {
		width := uint(4 + rng.Intn(13))
		max := uint64(1)<<width - 1
		var ranges [][2]uint64
		for i := 0; i < 1+rng.Intn(40); i++ {
			lo := rng.Uint64() & max
			hi := lo + (rng.Uint64() & (max - lo))
			ranges = append(ranges, [2]uint64{lo, hi})
		}
		m := BuildIntervalMap("f", width, ranges)
		if m.LabelPackWidth() > width {
			t.Fatalf("width %d: labels need %d bits", width, m.LabelPackWidth())
		}
	}
}
