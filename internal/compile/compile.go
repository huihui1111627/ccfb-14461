// Package compile turns ordered rule sets into TCAM tables.
//
// The pipeline for each ACL (rule set + the ports/directions it is bound to):
//
//  1. Expand list-valued fields into one clause per combination, and encode
//     each field's constraint as a set of ternary cubes (package cover).
//  2. Merge adjacent clauses that have the same action and whose union is
//     exactly one cube (requirement 2). Only adjacency makes this sound: with
//     no clause in between, no packet's verdict can change.
//  3. Lay the clauses out in priority order. Every linear order consistent with
//     the precedence constraints implements the same first-match function, so
//     the compiler records which entries are free to move (requirement 3) and
//     those become the slack the online updater uses.
//  4. Deduplicate identical entries and merge adjacent entries with equal
//     actions whose key union is still a cube.
//
// One table is built per ACL and shared by every (port, direction) the ACL is
// bound to (requirement 5).
package compile

import (
	"sort"

	"tcamc/internal/encode"
	"tcamc/internal/key"
	"tcamc/internal/model"
)

// Options control the optimiser. The zero value compiles the naive baseline:
// canonical prefix expansion, no merging, no label encoding.
type Options struct {
	// Labels selects fields that are indexed by interval labels instead of
	// raw values. A field may only be labelled when every constraint on it is
	// an exact value or a range (labels preserve neither prefixes nor masks).
	Labels map[string]bool
	// MinMask uses arbitrary ternary masks for ranges instead of only aligned
	// prefixes. Slightly fewer entries, slightly more compile time.
	MinMask bool
	// MergeClauses merges same-rule clauses whose union is exactly one cube.
	MergeClauses bool
	// MergeEntries deduplicates rows and merges adjacent same-action rows.
	// The online updater needs this off: an entry that holds parts of several
	// rules cannot be deleted row by row without splitting it first.
	MergeEntries bool
}

// Naive returns the textbook baseline: prefix expansion of every range, one
// entry per rule expansion, no merging, no label encoding.
func Naive() Options { return Options{} }

// Online returns options suitable for a table that will be updated online:
// label encoding is still allowed, clause merging is on, but rows never merge.
func Online() Options { return Options{MinMask: true, MergeClauses: true} }

// Optimized returns the fully enabled optimiser.
func Optimized() Options {
	return Options{MinMask: true, MergeClauses: true, MergeEntries: true}
}

// Entry is one TCAM row.
type Entry struct {
	K, M   key.Key
	Action uint8
	// Parts records the clauses this row was built from. A merged row has more
	// than one part; Parts[0] is the row's primary (earliest) priority.
	Parts []Part
	// Words is the number of key words holding constrained bits. Lookup skips
	// the rest.
	Words int
}

// Part is one source clause of an entry.
type Part struct {
	K, M  key.Key
	Prio  int
	Rule  string
	Label string
}

// MinPrio and MaxPrio bound the entry's priority range.
func (e *Entry) MinPrio() int { return e.Parts[0].Prio }

// MaxPrio returns the highest source priority of the entry.
func (e *Entry) MaxPrio() int {
	p := e.Parts[0].Prio
	for _, q := range e.Parts[1:] {
		if q.Prio > p {
			p = q.Prio
		}
	}
	return p
}

// Action identifies the verdict.
type Action = model.Action

// FieldInfo describes how one field is encoded in this plan's key.
type FieldInfo struct {
	Field     string
	RawWidth  uint
	PackWidth uint
	Offset    uint
	Labels    *encode.IntervalMap // nil when the field is raw
}

// Plan is the compiled table for one ACL.
type Plan struct {
	Name     string
	Bindings []model.PortDir
	Layout   key.Layout
	Fields   []FieldInfo
	Entries  []Entry
	Default  Action
	Actions  map[uint8]Action

	// Rule order used to assign priorities.
	RuleIDs []string

	// Stats captured during compilation.
	Stats PlanStats
}

// Program is a compiled rule library: one plan per ACL plus the binding map.
type Program struct {
	ACLs    []*Plan
	ByACL   map[string]*Plan
	Binding map[string]*Plan // "port:dir" -> plan
	Encoder EncoderStats
	Options Options
}

// EncoderStats counts the entries needed by the value->label encoder stage that
// is shared by all plans.
type EncoderStats struct {
	Enabled bool
	Fields  map[string]int // field -> encoder entries
	Total   int
}

// Build compiles every ACL in the rule sets. Rules are grouped into ACLs by
// their exact set of bindings: the same rule set bound to several
// ports/directions becomes one ACL, so its entries are shared. An attachment
// point has exactly one ACL in effect -- its ordered rule list -- so all rules
// bound to it are merged into that ACL regardless of how they were grouped
// upstream (requirement 5).
func Build(sets []*model.RuleSet, opts Options) (*Program, error) {
	if opts.Labels == nil && opts.MergeClauses {
		// Auto-select label encoding by measured cost.
		return buildAuto(sets, opts)
	}
	return buildWith(sets, opts)
}

// ACLSpec is one ordered rule list bound to one or more attachment points.
type ACLSpec struct {
	Name     string
	Bindings []model.PortDir
	Rules    []*model.Rule
}

// SplitACLs builds one ACL per attachment point. Every rule bound to the
// attachment point contributes, in its global order, so the first-match
// verdict on that port is exactly what the reference evaluator computes.
//
// Rules with identical binding sets produce identical ACLs; buildWith folds
// those into a single plan so the table is stored and shared once.
func SplitACLs(sets []*model.RuleSet) []ACLSpec {
	attach := map[string]*ACLSpec{}
	var order []string
	for _, rs := range sets {
		for _, r := range rs.Rules {
			seen := map[string]bool{}
			for _, b := range r.Bindings {
				if seen[b] {
					continue
				}
				seen[b] = true
				g, ok := attach[b]
				if !ok {
					pd := parseBindings([]string{b})
					g = &ACLSpec{Name: rs.Name, Bindings: pd}
					attach[b] = g
					order = append(order, b)
				}
				g.Rules = append(g.Rules, r)
			}
		}
	}
	sort.Strings(order)
	var out []ACLSpec
	for _, b := range order {
		out = append(out, *attach[b])
	}
	return out
}

func bindingSignature(bs []string) string {
	s := append([]string(nil), bs...)
	sort.Strings(s)
	out := ""
	for _, b := range s {
		out += b + ","
	}
	return out
}

func parseBindings(bs []string) []model.PortDir {
	var out []model.PortDir
	for _, b := range bs {
		for i := 0; i < len(b); i++ {
			if b[i] == ':' {
				out = append(out, model.PortDir{Port: b[:i], Dir: b[i+1:]})
				break
			}
		}
	}
	return out
}

// candidateLabelFields returns fields that may use interval labelling.
func candidateLabelFields(specs []ACLSpec) []string {
	ok := map[string]bool{}
	seen := map[string]bool{}
	for _, sp := range specs {
		for _, r := range sp.Rules {
			for _, m := range r.Matches {
				meta := model.Meta[m.Field]
				if meta.Width > 16 {
					ok[m.Field] = false
				}
				if m.Kind != model.KindExact && m.Kind != model.KindRange {
					ok[m.Field] = false
				}
				seen[m.Field] = true
				if _, set := ok[m.Field]; !set {
					ok[m.Field] = true
				}
			}
		}
	}
	var out []string
	for f := range seen {
		if ok[f] {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func buildAuto(sets []*model.RuleSet, opts Options) (*Program, error) {
	specs := SplitACLs(sets)
	cands := candidateLabelFields(specs)
	// The subset search is exponential in the number of candidate fields, so
	// bound it. Two fields (typically the two ports) capture nearly all of the
	// benefit; with many rules even four subsets is enough to keep compile time
	// bounded.
	maxCands := 4
	if totalRules(specs) > 400 {
		maxCands = 2
	}
	if len(cands) > maxCands {
		cands = cands[:maxCands]
	}
	best := -1
	var bestOpts Options
	for mask := 0; mask < 1<<len(cands); mask++ {
		o := opts
		o.Labels = map[string]bool{}
		for i, f := range cands {
			if mask&(1<<i) != 0 {
				o.Labels[f] = true
			}
		}
		p, err := buildWith(sets, o)
		if err != nil {
			return nil, err
		}
		// The encoder is a separate stage (see README): its rows are not TCAM
		// rows, so label encoding is chosen to minimise TCAM entries, with
		// encoder rows only breaking ties.
		cost := 0
		for _, a := range p.ACLs {
			cost += len(a.Entries)
		}
		cost = cost*1000000 + p.Encoder.Total
		if best < 0 || cost < best {
			best = cost
			bestOpts = o
		}
	}
	return buildWith(sets, bestOpts)
}

func totalRules(specs []ACLSpec) int {
	n := 0
	for _, sp := range specs {
		n += len(sp.Rules)
	}
	return n
}
