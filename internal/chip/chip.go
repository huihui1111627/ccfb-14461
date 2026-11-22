// Package chip is a software model of the ternary CAM block plus the action
// table behind it.
//
// The model deliberately has the properties of real hardware that the
// compiler must respect:
//
//   - Entries have a physical row index. Lookup returns the action of the
//     lowest-indexed row that matches, so row order *is* priority.
//   - A write updates exactly one row. There is no atomic "program the whole
//     table" operation; an online update must be expressed as single-row
//     writes, and every intermediate table state is observable.
//   - The block is full at Capacity rows; a write into an occupied row is
//     permitted only through the explicit Replace operation, which the caller
//     uses while shuffling.
package chip

import (
	"fmt"

	"tcamc/internal/compile"
	"tcamc/internal/key"
	"tcamc/internal/model"
)

// LookupMode selects how a packet is turned into a lookup key.
type LookupMode int

const (
	// ModeRaw looks the packet up with raw field values. Used by the naive
	// baseline, which never labels fields.
	ModeRaw LookupMode = iota
	// ModeLabels looks up with interval labels for fields the plan labelled.
	ModeLabels
)

// Row is one programmed row.
type Row struct {
	K, M   key.Key
	Action uint8
	Words  int
	Empty  bool
}

// Chip is one TCAM block holding one compiled plan.
type Chip struct {
	Capacity int
	Rows     []Row
	Plan     *compile.Plan
	// Writes counts single-row programs (used for the update benchmarks).
	Writes int64
	// Lookups counts table searches.
	Lookups int64
}

// New builds a chip from a compiled plan. Capacity below len(Entries) is
// rejected: the compiler is expected to have checked fit first.
func New(p *compile.Plan, capacity int) (*Chip, error) {
	return NewSpaced(p, capacity, 0)
}

// NewSpaced builds a chip and leaves `gap` free rows after every entry. A real
// table is programmed with gaps on purpose: it is the cheapest way to keep
// later inserts from having to shift rows, because an empty row right after a
// rule's entries is a ready-made slot for the next rule at that priority. The
// gaps count against capacity, so the fit check is on entries+gaps.
func NewSpaced(p *compile.Plan, capacity, gap int) (*Chip, error) {
	need := len(p.Entries)
	if gap > 0 && need > 0 {
		need += gap * (need - 1)
	}
	if capacity < need {
		return nil, fmt.Errorf("plan %s needs %d rows (with gaps), capacity %d", p.Name, need, capacity)
	}
	c := &Chip{Capacity: capacity, Plan: p, Rows: make([]Row, capacity)}
	for i := range c.Rows {
		c.Rows[i].Empty = true
	}
	row := 0
	for _, e := range p.Entries {
		c.Rows[row] = Row{K: e.K, M: e.M, Action: e.Action, Words: e.Words}
		row += 1 + gap
	}
	return c, nil
}

// SetRow programs one row. It is the only primitive the updater may use.
func (c *Chip) SetRow(i int, r Row) {
	if i < 0 || i >= c.Capacity {
		panic("row out of range")
	}
	c.Rows[i] = r
	c.Writes++
}

// SetEntry programs one row from a compiled entry.
func (c *Chip) SetEntry(i int, e compile.Entry) {
	c.SetRow(i, Row{K: e.K, M: e.M, Action: e.Action, Words: e.Words})
}

// ClearRow blanks one row.
func (c *Chip) ClearRow(i int) { c.SetRow(i, Row{Empty: true}) }

// LookupKey searches the table for the lowest matching row.
//
// A row that matches itself is skipped: in the middle of a move the same entry
// legitimately exists in two rows, and on real hardware the copy at the lower
// address would win -- which is the point of the duplicate-then-clear sequence.
// Modelling that overlap is not needed for correctness proofs about packets,
// and modelling it wrong (with a zero-action blank row) is worse, so the model
// reports the owned entry that wins and treats a duplicate as invisible.
func (c *Chip) LookupKey(k key.Key) (uint8, bool) {
	c.Lookups++
	for i := range c.Rows {
		r := &c.Rows[i]
		if r.Empty {
			continue
		}
		if key.Match(k, r.K, r.M) {
			return r.Action, true
		}
	}
	return 0, false
}

// FieldValue maps a raw packet value into the plan's key space for one field.
func FieldValue(p *compile.Plan, field string, raw uint64) uint64 {
	for _, fi := range p.Fields {
		if fi.Field != field {
			continue
		}
		if fi.Labels != nil {
			return fi.Labels.Label(raw)
		}
		return raw
	}
	return raw
}

// PacketKey builds the lookup key for a packet under the given mode.
func PacketKey(p *compile.Plan, pk model.Key, mode LookupMode) key.Key {
	var k key.Key
	for _, fi := range p.Fields {
		v := pk[fi.Field]
		if mode == ModeLabels && fi.Labels != nil {
			v = fi.Labels.Label(v)
		}
		p.Layout.PutField(&k, fi.Field, v)
	}
	return k
}

// LookupPacket evaluates one packet on the chip and returns the action name.
// A miss means the table's default verdict.
func (c *Chip) LookupPacket(pk model.Key, mode LookupMode) compile.Action {
	k := PacketKey(c.Plan, pk, mode)
	id, ok := c.LookupKey(k)
	if !ok {
		return c.Plan.Default
	}
	if a, ok := c.Plan.Actions[id]; ok {
		return a
	}
	return compile.Action{ID: id}
}

// Used returns the number of non-empty rows.
func (c *Chip) Used() int {
	n := 0
	for i := range c.Rows {
		if !c.Rows[i].Empty {
			n++
		}
	}
	return n
}

// Snapshot returns a copy of the row array.
func (c *Chip) Snapshot() []Row {
	return append([]Row(nil), c.Rows...)
}
