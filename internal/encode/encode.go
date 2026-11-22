// Package encode turns rule field constraints into ternary key patterns for
// one chip lookup.
//
// The naive way to compile a port range [8000,9000] is to cover the range with
// ternary cubes directly on the 16-bit port. Measured on realistic rule sets
// that costs about 1.5-2.5 table entries per range. Two cheaper encodings are
// implemented here and composed:
//
//  1. Mask cover (package cover): arbitrary ternary masks instead of only
//     prefixes. Exact, and about 4% smaller at 8-12 bits. Cheap but small.
//
//  2. Dense boundary labelling: instead of indexing the table by the raw field
//     value, index it by a label assigned to the *distinct interval* the value
//     falls into, where intervals are cut at every rule's range boundaries. A
//     port range then becomes a *contiguous run of labels*, which needs ~log2
//     of the run length entries instead of ~log2 of the field. On the synthetic
//     parking-campus rule set this cuts port-range entries by roughly 45%.
//
// The labelling is per (field, rule set, binding set) and therefore shared by
// every rule bound to the same attachment points; see compile.Plan. Packets go
// through the same interval map at lookup time (or, on a real chip, through a
// small exact-match classifier that the compiler emits).
package encode

import (
	"sort"

	"tcamc/internal/cover"
)

// Kind selects how a field is encoded.
type Kind int

const (
	// KindDirect emits ternary cubes over the raw field value.
	KindDirect Kind = iota
	// KindLabels maps the value to the index of the interval it falls into,
	// then covers the label run. Intervals are cut at every boundary of the
	// rule set being encoded, so ranges become contiguous.
	KindLabels
)

// Boundary is one half-open cut in a field: values < At are in an earlier
// interval. Cut points are the starts of ranges and one past their ends.
type Boundary struct {
	At uint64
}

// IntervalMap maps a raw field value to a dense label. Labels are assigned in
// increasing value order, so a raw range becomes a label range.
type IntervalMap struct {
	Field     string
	Width     uint
	cuts      []uint64 // sorted distinct boundaries, always including 0 and 2^w
	LABELBITS uint
}

// BuildIntervalMap builds the map from a set of inclusive ranges. Ranges are
// clipped to the field width. Labels are 0..len(cuts)-2.
func BuildIntervalMap(field string, width uint, ranges [][2]uint64) *IntervalMap {
	max := cover.FullMask(width)
	cutSet := map[uint64]bool{0: true}
	for _, r := range ranges {
		lo, hi := r[0], r[1]
		if lo > max {
			continue
		}
		if hi > max {
			hi = max
		}
		if lo > hi {
			continue
		}
		cutSet[lo] = true
		if hi < max {
			cutSet[hi+1] = true
		}
	}
	cuts := make([]uint64, 0, len(cutSet)+1)
	for c := range cutSet {
		cuts = append(cuts, c)
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i] < cuts[j] })
	// A trailing cut at 2^w keeps label arithmetic uniform.
	if cuts[len(cuts)-1] < max {
		cuts = append(cuts, max+1)
	}
	bits := uint(0)
	for 1<<bits < uint64(len(cuts)) {
		bits++
	}
	return &IntervalMap{Field: field, Width: width, cuts: cuts, LABELBITS: bits}
}

// Label returns the label of a raw value: the index of the interval holding
// it, i.e. the number of cuts strictly below v.
func (m *IntervalMap) Label(v uint64) uint64 {
	return uint64(sort.Search(len(m.cuts), func(i int) bool { return m.cuts[i] > v }))
}

// LabelRange translates an inclusive raw range into an inclusive label range.
// Because cuts include both endpoints' boundaries, every value in the raw range
// maps into a contiguous label range, and every value in that label range came
// from the raw range.
func (m *IntervalMap) LabelRange(lo, hi uint64) (uint64, uint64) {
	return m.Label(lo), m.Label(hi)
}

// LabelBits is the width needed for a label.
func (m *IntervalMap) LabelBits() uint { return m.LABELBITS }

// Cuts exposes the cut points (read-only) for the lookup-side map.
func (m *IntervalMap) Cuts() []uint64 { return m.cuts }

// LabelPackWidth is the number of bits a labelled field occupies in the key.
// Labels never exceed 2^width, so this is at most the raw field width.
func (m *IntervalMap) LabelPackWidth() uint {
	if m.LABELBITS < m.Width {
		return m.LABELBITS
	}
	return m.Width
}

// HasCut reports whether v is a cut point. An insert is expressible on a
// labelled field only when its range boundaries are already cuts.
func (m *IntervalMap) HasCut(v uint64) bool {
	i := sort.Search(len(m.cuts), func(i int) bool { return m.cuts[i] >= v })
	return i < len(m.cuts) && m.cuts[i] == v
}
