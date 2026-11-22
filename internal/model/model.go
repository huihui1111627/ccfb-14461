// Package model defines the rule language, packet keys and the reference
// (software) semantics that compiled tables must reproduce exactly.
package model

import "fmt"

// FieldKind describes how a header field is matched.
type FieldKind int

const (
	// KindExact matches a single value exactly (equivalent to a full mask).
	KindExact FieldKind = iota
	// KindPrefix matches an IPv4 prefix (value, prefix length).
	KindPrefix
	// KindRange matches an inclusive numeric range [Lo, Hi] (ports, vlan ids...).
	KindRange
	// KindMask matches (value AND mask) == value on a key word; used for
	// protocol/flag style fields.
	KindMask
)

// Field names understood by the compiler. The chip key word width is
// implied by the field, so a clashing configuration is rejected at load.
const (
	FieldSrcIP       = "src_ip"
	FieldDstIP       = "dst_ip"
	FieldSrcPort     = "src_port"
	FieldDstPort     = "dst_port"
	FieldVLAN        = "vlan"
	FieldProto       = "proto"
	FieldDSCP        = "dscp"
	FieldEstablished = "est"
	FieldSRCMAC      = "src_mac"
	FieldDstMAC      = "dst_mac"
)

// FieldMeta gives key width and display information for a field.
type FieldMeta struct {
	Width  uint // number of key bits
	Kind   FieldKind
	Pretty string
}

// Fields is the canonical field order. The compiled key is the concatenation
// of these fields in this order. Keeping a fixed, explicit order makes table
// layout deterministic and easy to inspect.
var Fields = []string{
	FieldSrcIP, FieldDstIP, FieldProto, FieldSrcPort, FieldDstPort,
	FieldVLAN, FieldDSCP, FieldEstablished, FieldSRCMAC, FieldDstMAC,
}

// Meta maps every supported field to its width and type.
var Meta = map[string]FieldMeta{
	FieldSrcIP:       {32, KindPrefix, "source IPv4 prefix"},
	FieldDstIP:       {32, KindPrefix, "destination IPv4 prefix"},
	FieldProto:       {8, KindMask, "IP protocol / IP protocol set"},
	FieldSrcPort:     {16, KindRange, "L4 source port range"},
	FieldDstPort:     {16, KindRange, "L4 destination port range"},
	FieldVLAN:        {12, KindMask, "802.1Q VLAN id"},
	FieldDSCP:        {6, KindMask, "DSCP value"},
	FieldEstablished: {1, KindExact, "TCP established flag"},
	FieldSRCMAC:      {48, KindExact, "source MAC"},
	FieldDstMAC:      {48, KindExact, "destination MAC"},
}

// Match is one field constraint of a rule. The meaning depends on Kind:
//
//	KindExact  -> Value is the exact key word (Width bits)
//	KindPrefix -> Value holds the network address, Plen the prefix length
//	KindRange  -> [Lo,Hi] inclusive
//	KindMask   -> (key & Mask) == Value
//
// For KindExact, Mask is ignored. For KindRange, Mask and Plen are ignored.
type Match struct {
	Field string
	Kind  FieldKind
	Value uint64
	Mask  uint64
	Plen  uint8
	Lo    uint64
	Hi    uint64
}

// Action identifies what a matched rule does. The chip stores the action id;
// its meaning lives in the control plane.
type Action struct {
	ID     uint8
	Name   string
	Permit bool
}

// Rule is one access-control rule. Rules are evaluated in slice order; the
// first rule whose match covers the packet decides.
type Rule struct {
	ID       string
	Bindings []string // (port, direction) the rule is attached to, e.g. "ge1:in"
	Matches  []Match
	Action   Action
	Comment  string
}

// RuleSet is a named ordered list of rules.
type RuleSet struct {
	Name  string
	Rules []*Rule
}

// PortDir is a physical attachment point.
type PortDir struct {
	Port string
	Dir  string
}

// Key is a packet key split per field. Values are already width-limited;
// fields absent from a packet (e.g. ports for ICMP) are zero.
type Key map[string]uint64

// Packet is a synthetic packet used for differential testing.
type Packet struct {
	Key Key
	Tag string
}

// MatchKey reports whether a match covers key.
func (m *Match) MatchKey(k Key) bool {
	v := k[m.Field] & maskOf(Meta[m.Field].Width)
	switch m.Kind {
	case KindExact:
		return v == m.Value
	case KindPrefix:
		if m.Plen == 0 {
			return true
		}
		// Compare the top Plen bits of the field, not of the 64-bit word.
		sh := Meta[m.Field].Width - uint(m.Plen)
		return (v >> sh) == (m.Value >> sh)
	case KindRange:
		return v >= m.Lo && v <= m.Hi
	case KindMask:
		return v&m.Mask == m.Value
	}
	return false
}

func maskOf(w uint) uint64 {
	if w >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << w) - 1
}

// MatchRule reports whether every match of r covers k.
func (r *Rule) MatchRule(k Key) bool {
	for i := range r.Matches {
		if !r.Matches[i].MatchKey(k) {
			return false
		}
	}
	return true
}

// Decide evaluates rules in order and returns the first matching rule.
func Decide(rules []*Rule, k Key) *Rule {
	for _, r := range rules {
		if r.MatchRule(k) {
			return r
		}
	}
	return nil
}

// Validate performs structural checks and returns an error for unsupported
// constructs. Semantic errors that need the chip geometry are checked later.
func (rs *RuleSet) Validate() error {
	if len(rs.Rules) == 0 {
		return fmt.Errorf("ruleset %q is empty", rs.Name)
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule without id")
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		mf := map[string]bool{}
		for i := range r.Matches {
			m := &r.Matches[i]
			meta, ok := Meta[m.Field]
			if !ok {
				return fmt.Errorf("rule %q: unknown field %q", r.ID, m.Field)
			}
			if mf[m.Field] {
				return fmt.Errorf("rule %q: field %q matched twice", r.ID, m.Field)
			}
			mf[m.Field] = true
			max := maskOf(meta.Width)
			switch meta.Kind {
			case KindPrefix:
				if m.Plen > uint8(meta.Width) {
					return fmt.Errorf("rule %q: %s prefix length %d exceeds %d", r.ID, m.Field, m.Plen, meta.Width)
				}
				if m.Value&^max != 0 {
					return fmt.Errorf("rule %q: %s value does not fit %d bits", r.ID, m.Field, meta.Width)
				}
			case KindRange:
				if m.Lo > m.Hi {
					return fmt.Errorf("rule %q: %s range [%d,%d] is empty", r.ID, m.Field, m.Lo, m.Hi)
				}
				if m.Hi > max {
					return fmt.Errorf("rule %q: %s range end %d exceeds %d bits", r.ID, m.Field, m.Hi, meta.Width)
				}
			case KindExact, KindMask:
				if m.Value&^max != 0 {
					return fmt.Errorf("rule %q: %s value does not fit %d bits", r.ID, m.Field, meta.Width)
				}
				if m.Kind == KindMask && m.Value&^m.Mask != 0 {
					return fmt.Errorf("rule %q: %s value has bits outside mask", r.ID, m.Field)
				}
			}
		}
	}
	return nil
}

// KeyWidth is the total width of the compiled key.
func KeyWidth() uint {
	var w uint
	for _, f := range Fields {
		w += Meta[f].Width
	}
	return w
}

// Max returns the largest value a field can hold.
func (m FieldMeta) Max() uint64 {
	if m.Width >= 64 {
		return ^uint64(0)
	}
	return uint64(1)<<m.Width - 1
}
