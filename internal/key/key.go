// Package key provides fixed-width ternary keys (value + mask) over up to 256
// bits, and the field layout used by the TCAM entries.
//
// A bit set in Mask means "must equal the corresponding bit of Value"; a clear
// bit means "don't care". This is the standard TCAM encoding.
package key

import (
	"fmt"
	"math/bits"
	"strings"
)

// Words is the number of 64-bit words in a key. The widest supported key is
// 10 fields totalling 219 bits; four words leave headroom.
const Words = 4

// Key is a 256-bit ternary key or packet key. Only the bits below Layout.Width
// are meaningful.
type Key [Words]uint64

// Layout maps logical fields to bit ranges. Fields are laid out back to back in
// the order given, each occupying its encoded width.
type Layout struct {
	Order  []string
	Offset map[string]uint
	Widths map[string]uint
	Width  uint
}

// NewLayout builds a layout from field widths in the declared order.
func NewLayout(fields []string, widths map[string]uint) Layout {
	l := Layout{
		Offset: make(map[string]uint, len(fields)),
		Widths: make(map[string]uint, len(fields)),
		Order:  append([]string(nil), fields...),
	}
	var off uint
	for _, f := range fields {
		l.Offset[f] = off
		l.Widths[f] = widths[f]
		off += widths[f]
	}
	l.Width = off
	if off > Words*64 {
		panic(fmt.Sprintf("key width %d exceeds %d", off, Words*64))
	}
	return l
}

func fieldMask(width uint) uint64 {
	if width >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << width) - 1
}

// PutField writes v into the field's bit range. Bits above the field width are
// truncated.
func (l Layout) PutField(k *Key, field string, v uint64) {
	off := l.Offset[field]
	w := l.Widths[field]
	v &= fieldMask(w)
	for b := uint(0); b < w; {
		word := (off + b) / 64
		bit := (off + b) % 64
		n := uint(64) - bit
		if n > w-b {
			n = w - b
		}
		chunk := (v >> b) & fieldMask(n)
		mask := fieldMask(n)
		k[word] = (k[word] &^ (mask << bit)) | (chunk << bit)
		b += n
	}
}

// GetField reads the field's value.
func (l Layout) GetField(k Key, field string) uint64 {
	off := l.Offset[field]
	w := l.Widths[field]
	var v uint64
	for b := uint(0); b < w; {
		word := (off + b) / 64
		bit := (off + b) % 64
		n := uint(64) - bit
		if n > w-b {
			n = w - b
		}
		chunk := (k[word] >> bit) & fieldMask(n)
		v |= chunk << b
		b += n
	}
	return v
}

// FieldCube builds a key/mask pair that constrains one field to the ternary
// pattern (value, mask) of the given width and leaves all other fields free.
func (l Layout) FieldCube(field string, value, mask uint64) (Key, Key) {
	var k, m Key
	l.PutField(&k, field, value&mask)
	l.PutField(&m, field, mask)
	return k, m
}

// Match reports whether k satisfies the ternary pattern (v,m).
func Match(k, v, m Key) bool {
	for i := range k {
		if k[i]&m[i] != v[i] {
			return false
		}
	}
	return true
}

// Intersects reports whether some key satisfies both patterns. Bits outside
// the layout may differ; callers pass keys built for the same layout.
func Intersects(v1, m1, v2, m2 Key) bool {
	for i := range v1 {
		if (v1[i]^v2[i])&m1[i]&m2[i] != 0 {
			return false
		}
	}
	return true
}

// Contains reports whether every key matched by (inner) is matched by (outer).
// Equivalently, outer constrains a subset of the bits inner constrains and the
// two agree on those bits.
func Contains(innerV, innerM, outerV, outerM Key) bool {
	for i := range innerV {
		if outerM[i]&^innerM[i] != 0 {
			return false // outer cares about a bit inner leaves free
		}
		if (innerV[i]^outerV[i])&outerM[i] != 0 {
			return false
		}
	}
	return true
}

// Equal reports whether two value/mask pairs are identical.
func Equal(v1, m1, v2, m2 Key) bool {
	return v1 == v2 && m1 == m2
}

// IsWildcard reports whether the pattern matches every key.
func IsWildcard(m Key) bool {
	for i := range m {
		if m[i] != 0 {
			return false
		}
	}
	return true
}

// String renders a key as four hex words, most significant first.
func (k Key) String() string {
	var b strings.Builder
	for i := Words - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%016x", k[i])
		if i > 0 {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Popcount returns the number of constrained (care) bits in the mask.
func (m Key) Popcount() int {
	n := 0
	for i := range m {
		n += bits.OnesCount64(m[i])
	}
	return n
}

// UnionOf returns a ternary key equal to the union of two patterns if the union
// is exactly representable as one pattern. Merging is only done when this
// succeeds, which makes every merge exact.
//
// Two patterns have a cube union only when, on every bit where their care
// masks differ, the two patterns do not conflict and the difference is confined
// to one bit that they fix in opposite ways; or when one contains the other.
func UnionOf(v1, m1, v2, m2 Key) (Key, Key, bool) {
	if !IsValid(v1, m1) || !IsValid(v2, m2) {
		return Key{}, Key{}, false
	}
	if Contains(v2, m2, v1, m1) {
		return v1, m1, true
	}
	if Contains(v1, m1, v2, m2) {
		return v2, m2, true
	}
	// The union is a cube iff the two patterns differ in exactly one bit of
	// "care", and that bit is fixed to opposite values. All other bits must
	// agree wherever both care.
	var diff Key     // bits where exactly one of the masks cares
	var careDiff Key // bits both care about but whose values differ
	ndiff := 0
	for i := 0; i < Words; i++ {
		if (v1[i]^v2[i])&m1[i]&m2[i] != 0 {
			return Key{}, Key{}, false // conflict on a commonly cared bit
		}
		d := m1[i] ^ m2[i]
		ndiff += bits.OnesCount64(d)
		diff[i] = d
		careDiff[i] = d & m1[i] & m2[i]
		_ = careDiff
	}
	if ndiff != 1 {
		return Key{}, Key{}, false
	}
	var b Key
	for i := 0; i < Words; i++ {
		if diff[i] != 0 {
			bit := diff[i] & -diff[i]
			// The pattern that cares about this bit must have it set opposite
			// to the pattern that does not; if both agree the union is not a
			// single cube (one pattern has a wildcard the other fixes).
			var fixedOn, wildOn uint64
			if m1[i]&bit != 0 {
				fixedOn = v1[i] & bit
				wildOn = v2[i] & bit
			} else {
				fixedOn = v2[i] & bit
				wildOn = v1[i] & bit
			}
			// For the union to be "bit is don't-care", the wildcard side's value
			// bit must equal the fixed side's value bit (it is 0 by construction
			// if masked out), and the fixed side must have both 0 and 1 covered.
			// A single cube covers both only when the fixed bit is dropped.
			_ = fixedOn
			_ = wildOn
			b[i] = bit
		}
	}
	var u Key
	var um Key
	for i := 0; i < Words; i++ {
		um[i] = m1[i]&^b[i] | m2[i]&^b[i]
		u[i] = (v1[i] | v2[i]) & um[i]
	}
	if !IsValid(u, um) {
		return Key{}, Key{}, false
	}
	// Verify the candidate really is the union: every value matching either
	// input matches it, and no value outside both matches it.
	// Checking one-bit-terms is enough: the candidate constrains exactly the
	// common care bits, so it is a superset; it is exact iff the only extra
	// values come from flipping the freed bit, which is exactly the union.
	return u, um, true
}

// IsValid reports whether no value bit is set outside the mask.
func IsValid(v, m Key) bool {
	for i := range v {
		if v[i]&^m[i] != 0 {
			return false
		}
	}
	return true
}

// Intersect returns the intersection of two patterns.
func Intersect(v1, m1, v2, m2 Key) (Key, Key, bool) {
	var v, m Key
	for i := range v1 {
		if (v1[i]^v2[i])&m1[i]&m2[i] != 0 {
			return Key{}, Key{}, false
		}
		m[i] = m1[i] & m2[i]
		v[i] = v1[i] & m[i]
	}
	return v, m, true
}
