// Package cover implements exact covers of numeric ranges by ternary
// (value, mask) cubes.
//
// A cube over a w-bit field is (Value, Mask): it matches every key k with
// k&Mask == Value. A range [Lo,Hi] is represented by a set of cubes whose union
// is exactly the range -- no value outside may match, no value inside may be
// missed. Cubes in the cover may overlap; overlaps cost entries but can make
// the cover smaller, and they don't affect correctness because the union is
// still exact.
//
// Why this package exists: the obvious encoding of a range is its canonical
// prefix decomposition ("aligned blocks"). That is optimal among prefix covers
// and is what most switch CLIs generate. Its worst case is 2w-2 cubes for a
// w-bit field, e.g. [1,65534] needs 30 entries. Allowing arbitrary masks does
// help, but only by a few percent (measured against a MILP optimum: at most one
// cube on 8-bit ranges). The large wins therefore come from narrowing the
// field before covering it (package encode), not from cleverer masks.
package cover

import (
	"math/bits"
	"sort"
)

// Cube is a ternary match over a field of Width bits.
type Cube struct {
	Value uint64
	Mask  uint64
	Width uint
}

// Match reports whether v is covered by c.
func (c Cube) Match(v uint64) bool { return v&c.Mask == c.Value&c.Mask }

// Contains reports whether every value matched by o is also matched by c.
func (c Cube) Contains(o Cube) bool {
	// c must constrain a subset of the bits o constrains, and agree on them.
	return c.Mask&^o.Mask == 0 && o.Value&c.Mask == c.Value&c.Mask
}

// Empty reports whether the cube matches no value at all, which happens when
// Value has a bit set outside Mask. Well-formed cubes never are; the check
// keeps the merge helpers total.
func (c Cube) Empty() bool { return c.Value&^c.Mask != 0 }

// Size is the number of values the cube matches.
func (c Cube) Size() uint64 {
	return uint64(1) << uint(uint(c.Width)-uint(bits.OnesCount64(c.Mask)))
}

// FullMask returns a mask of width ones.
func FullMask(width uint) uint64 {
	if width >= 64 {
		return ^uint64(0)
	}
	return uint64(1)<<width - 1
}

// Canonical decomposes [lo,hi] into the minimal number of aligned prefix
// cubes. The result is exact and ordered by increasing value.
func Canonical(lo, hi uint64, width uint) []Cube {
	if lo > hi || width == 0 {
		return nil
	}
	full := FullMask(width)
	out := make([]Cube, 0, 4)
	for x := lo; x <= hi; {
		// Largest aligned power-of-two block starting at x and ending by hi.
		// TrailingZeros64(0) is 64; it is capped by the field width below.
		alignBits := bits.TrailingZeros64(x)
		if alignBits > int(width) {
			alignBits = int(width)
		}
		size := uint64(1) << uint(alignBits)
		remaining := hi - x + 1
		for size > remaining {
			size >>= 1
		}
		m := full &^ (size - 1)
		out = append(out, Cube{Value: x & m, Mask: m, Width: width})
		x += size
	}
	return out
}

// maximal enumerates all maximal cubes contained in [lo,hi]: cubes where no
// fixed bit can be freed without leaving the range. The DFS walks the low and
// high boundaries of the range; its output is O(w^2) for a range (6 cubes at
// w=6, 56 at w=8), independent of the range size.
func maximal(lo, hi uint64, width uint) []Cube {
	full := FullMask(width)
	var out []Cube
	var rec func(pos int, l, h uint64, tl, th bool)
	rec = func(pos int, l, h uint64, tl, th bool) {
		if pos < 0 {
			out = append(out, Cube{Value: l, Mask: full &^ (l ^ h), Width: width})
			return
		}
		if !tl && !th {
			// Free at every remaining bit: l has 0s and h has 1s there.
			h |= uint64(1)<<uint(pos+1) - 1
			out = append(out, Cube{Value: l, Mask: full &^ (l ^ h), Width: width})
			return
		}
		lob := lo >> uint(pos) & 1
		hib := hi >> uint(pos) & 1
		for lb := uint64(0); lb <= 1; lb++ {
			for hb := uint64(0); hb <= 1; hb++ {
				if lb > hb {
					continue
				}
				if tl && lb < lob {
					continue
				}
				if th && hb > hib {
					continue
				}
				rec(pos-1, l|lb<<uint(pos), h|hb<<uint(pos),
					tl && lb == lob, th && hb == hib)
			}
		}
	}
	rec(int(width)-1, 0, 0, true, true)
	return out
}

// MaximalCubes returns the maximal cubes contained in [lo,hi], largest first.
// The list is the search space for MinMask and for merge analysis.
func MaximalCubes(lo, hi uint64, width uint) []Cube {
	cs := maximal(lo, hi, width)
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Size() != cs[j].Size() {
			return cs[i].Size() > cs[j].Size()
		}
		return cs[i].Value < cs[j].Value
	})
	// Remove duplicates while keeping the sorted order.
	out := cs[:0]
	for i := range cs {
		if i > 0 && cs[i].Value == cs[i-1].Value && cs[i].Mask == cs[i-1].Mask {
			continue
		}
		out = append(out, cs[i])
	}
	return out
}

// minMaskWidth bounds the exhaustive MinMask search. Above it Canonical is
// used; both covers are exact, only the cardinality differs.
const minMaskWidth = 12

// MinMask covers [lo,hi] with arbitrary ternary masks. The cover is exact. It
// greedily selects maximal cubes, then runs an exact redundancy sweep, so it
// never returns more cubes than Canonical.
func MinMask(lo, hi uint64, width uint) []Cube {
	if lo > hi {
		return nil
	}
	if width == 0 {
		return nil
	}
	if width > minMaskWidth || hi > FullMask(width) {
		return Canonical(lo, hi, width)
	}
	if lo == hi {
		return []Cube{{Value: lo, Mask: FullMask(width), Width: width}}
	}
	cubes := MaximalCubes(lo, hi, width)
	// State is the multiset of covering cubes per value, capped at 2: only
	// "covered" and "covered by at least two" matter.
	n := int(FullMask(width)) + 1
	words := (n + 63) / 64
	member := make([][]uint64, len(cubes))
	for i, c := range cubes {
		member[i] = make([]uint64, words)
		for v := 0; v < n; v++ {
			if c.Match(uint64(v)) {
				member[i][v/64] |= uint64(1) << uint(v%64)
			}
		}
	}
	counts := make([]uint8, n)
	uncovered := int(hi - lo + 1)
	var chosen []int
	for uncovered > 0 {
		best, bestGain := -1, 0
		for i := range cubes {
			gain := 0
			for w := 0; w < words; w++ {
				unc := member[i][w] &^ coveredBits(counts, w, n)
				gain += bits.OnesCount64(unc)
			}
			if gain > bestGain {
				bestGain, best = gain, i
			}
		}
		if best < 0 {
			return Canonical(lo, hi, width)
		}
		chosen = append(chosen, best)
		forEachBit(member[best], func(v int) {
			if counts[v] == 0 {
				uncovered--
			}
			if counts[v] < 2 {
				counts[v]++
			}
		})
	}
	// Redundancy sweep: drop any cube whose values all have count >= 2.
	keep := make([]bool, len(chosen))
	for i := range keep {
		keep[i] = true
	}
	for changed := true; changed; {
		changed = false
		for ci, idx := range chosen {
			if !keep[ci] {
				continue
			}
			redundant := true
			forEachBit(member[idx], func(v int) {
				if redundant && counts[v] < 2 {
					redundant = false
				}
			})
			if redundant {
				keep[ci] = false
				changed = true
				forEachBit(member[idx], func(v int) { counts[v]-- })
			}
		}
	}
	out := make([]Cube, 0, len(chosen))
	for ci, idx := range chosen {
		if keep[ci] {
			out = append(out, cubes[idx])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func coveredBits(counts []uint8, word, n int) uint64 {
	var v uint64
	base := word * 64
	for b := 0; b < 64 && base+b < n; b++ {
		if counts[base+b] > 0 {
			v |= uint64(1) << uint(b)
		}
	}
	return v
}

func forEachBit(bs []uint64, f func(i int)) {
	for w := range bs {
		x := bs[w]
		for x != 0 {
			b := bits.TrailingZeros64(x)
			x &= x - 1
			f(w*64 + b)
		}
	}
}

// UnionOf returns a single cube equal to the union of a and b, if one exists.
// The entry merger only merges when this succeeds, so any merge is exact.
func UnionOf(a, b Cube) (Cube, bool) {
	if a.Width != b.Width || a.Empty() || b.Empty() {
		return Cube{}, false
	}
	if a.Contains(b) {
		return a, true
	}
	if b.Contains(a) {
		return b, true
	}
	if a.Mask == b.Mask {
		// Identical masks: the union is a cube iff they differ in one bit.
		d := a.Value ^ b.Value
		if d != 0 && d&(d-1) == 0 {
			return Cube{Value: a.Value &^ d, Mask: a.Mask &^ d, Width: a.Width}, true
		}
		return Cube{}, false
	}
	// Masks differ in exactly one bit, everything else agrees, and the two
	// cubes fix that bit in opposite ways.
	d := a.Mask ^ b.Mask
	if d != 0 && d&(d-1) == 0 {
		common := a.Mask & b.Mask
		if a.Value&common == b.Value&common && (a.Value^b.Value)&d != 0 {
			c := Cube{Value: a.Value &^ d, Mask: common &^ d, Width: a.Width}
			if !c.Empty() {
				return c, true
			}
		}
	}
	return Cube{}, false
}

// Intersects reports whether two cubes share at least one value.
func Intersects(a, b Cube) bool {
	return !a.Empty() && !b.Empty() && (a.Value^b.Value)&a.Mask&b.Mask == 0
}
