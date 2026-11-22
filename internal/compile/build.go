package compile

import (
	"fmt"
	"sort"
	"strings"

	"tcamc/internal/cover"
	"tcamc/internal/encode"
	"tcamc/internal/key"
	"tcamc/internal/model"
)

// clause is one expanded match of one rule: a single combination of the
// rule's field cubes, before merging.
type clause struct {
	K, M  key.Key
	Prio  int // rule index; smaller is higher priority
	Rule  string
	Label string
}

// buildWith runs the pipeline for explicit options.
//
// Plans with byte-identical compiled content are folded: one plan is stored and
// every attachment point that produced it points at the same plan. This is the
// table-sharing path (requirement 5): the same ACL on eight ports costs one
// table, not eight.
func buildWith(sets []*model.RuleSet, opts Options) (*Program, error) {
	specs := SplitACLs(sets)
	prog := &Program{
		ByACL:   map[string]*Plan{},
		Binding: map[string]*Plan{},
		Options: opts,
		Encoder: EncoderStats{Enabled: len(opts.Labels) > 0, Fields: map[string]int{}},
	}
	byContent := map[string]*Plan{}
	for _, sp := range specs {
		p, err := buildPlan(sp, opts)
		if err != nil {
			return nil, err
		}
		sig := planSignature(p)
		if shared, ok := byContent[sig]; ok {
			shared.Bindings = append(shared.Bindings, p.Bindings...)
			sortBindings(shared.Bindings)
			for _, b := range p.Bindings {
				prog.Binding[b.Port+":"+b.Dir] = shared
			}
			continue
		}
		byContent[sig] = p
		prog.ACLs = append(prog.ACLs, p)
		prog.ByACL[p.Name] = p
		for _, b := range p.Bindings {
			prog.Binding[b.Port+":"+b.Dir] = p
		}
		for _, fi := range p.Fields {
			if fi.Labels != nil {
				prog.Encoder.Fields[fi.Field] = len(fi.Labels.Cuts())
			}
		}
	}
	for _, n := range prog.Encoder.Fields {
		prog.Encoder.Total += n
	}
	return prog, nil
}

// planSignature identifies plans that produce the same TCAM contents, so they
// can share one table. Bindings are excluded on purpose: sharing is about the
// contents, not about which ports point at them.
func planSignature(p *Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "w=%d;", p.Layout.Width)
	for _, fi := range p.Fields {
		fmt.Fprintf(&b, "%s:%d:%d;", fi.Field, fi.PackWidth, fi.Offset)
		if fi.Labels != nil {
			for _, c := range fi.Labels.Cuts() {
				fmt.Fprintf(&b, "%d,", c)
			}
		}
	}
	for _, e := range p.Entries {
		fmt.Fprintf(&b, "%s|%s|%d;", e.K.String(), e.M.String(), e.Action)
	}
	return b.String()
}

func buildPlan(sp ACLSpec, opts Options) (*Plan, error) {
	p := &Plan{
		Name:     sp.Name,
		Bindings: sp.Bindings,
		Actions:  map[uint8]Action{},
		Default:  Action{ID: 0, Name: "permit", Permit: true},
	}
	if len(sp.Rules) == 0 {
		return p, nil
	}

	fields := append([]string(nil), model.Fields...)
	widths := map[string]uint{}
	for _, f := range fields {
		widths[f] = model.Meta[f].Width
	}

	// Interval maps for labelled fields. Cuts are the boundaries of every
	// exact value / range used anywhere in this ACL, so each constraint maps to
	// a contiguous label run.
	labelMaps := map[string]*encode.IntervalMap{}
	for f, on := range opts.Labels {
		if !on {
			continue
		}
		var ranges [][2]uint64
		for _, r := range sp.Rules {
			for _, m := range r.Matches {
				if m.Field != f {
					continue
				}
				switch m.Kind {
				case model.KindRange:
					ranges = append(ranges, [2]uint64{m.Lo, m.Hi})
				case model.KindExact:
					ranges = append(ranges, [2]uint64{m.Value, m.Value})
				}
			}
		}
		lm := encode.BuildIntervalMap(f, model.Meta[f].Width, ranges)
		labelMaps[f] = lm
		widths[f] = lm.LabelBits()
	}

	layout := key.NewLayout(fields, widths)
	p.Layout = layout
	for _, f := range fields {
		fi := FieldInfo{Field: f, RawWidth: model.Meta[f].Width, PackWidth: widths[f], Offset: layout.Offset[f]}
		if lm := labelMaps[f]; lm != nil {
			fi.Labels = lm
		}
		p.Fields = append(p.Fields, fi)
	}

	for _, r := range sp.Rules {
		p.RuleIDs = append(p.RuleIDs, r.ID)
		p.Actions[r.Action.ID] = r.Action
	}

	// Expand every rule into clauses, in rule order.
	var clauses []clause
	for band, r := range sp.Rules {
		cs, err := expandRule(r, layout, labelMaps, opts)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			c.Rule = r.ID
			c.Prio = band
			clauses = append(clauses, c)
		}
	}
	rawClauses := len(clauses)

	if opts.MergeClauses {
		clauses = mergeClauses(clauses)
	}

	entries := make([]Entry, 0, len(clauses))
	for _, c := range clauses {
		e := Entry{K: c.K, M: c.M, Action: sp.Rules[c.Prio].Action.ID}
		e.Parts = []Part{{K: c.K, M: c.M, Prio: c.Prio, Rule: c.Rule, Label: c.Label}}
		e.Words = constrainedWords(c.K, c.M)
		entries = append(entries, e)
	}
	if opts.MergeEntries {
		entries = mergeEntries(entries)
		// The cross-rule pass is quadratic-ish in the number of rows and pays off
		// only while the table is small; on very large tables the adjacent merge
		// above already removed the easy wins and the scan would dominate
		// compile time.
		if len(entries) <= 500 {
			labelled := labelledWords(layout, p.Fields)
			entries = crossRuleMerge(entries, labelled)
		}
	}
	p.Entries = entries
	p.Stats = summarize(p, sp, rawClauses, opts)
	return p, nil
}

// labelledWords returns, per key word, whether it contains any labelled field.
func labelledWords(layout key.Layout, fields []FieldInfo) []bool {
	out := make([]bool, key.Words)
	for _, fi := range fields {
		if fi.Labels == nil || fi.PackWidth == 0 {
			continue
		}
		lo := layout.Offset[fi.Field]
		hi := lo + layout.Widths[fi.Field] - 1
		for w := lo / 64; w <= hi/64 && int(w) < len(out); w++ {
			out[w] = true
		}
	}
	return out
}

func constrainedWords(v, m key.Key) int {
	n := 0
	for i := range m {
		if m[i] != 0 {
			n = i + 1
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

// expandRule turns one rule into clauses, one per combination of field cubes.
func expandRule(r *model.Rule, layout key.Layout, labels map[string]*encode.IntervalMap, opts Options) ([]clause, error) {
	type perField struct {
		field string
		cubes []cover.Cube
	}
	var per []perField
	for _, m := range r.Matches {
		meta := model.Meta[m.Field]
		lm := labels[m.Field]
		var cubes []cover.Cube
		switch m.Kind {
		case model.KindExact:
			v := m.Value
			if lm != nil {
				v = lm.Label(v)
			}
			w := meta.Width
			if lm != nil {
				w = lm.LabelBits()
			}
			cubes = []cover.Cube{{Value: v, Mask: cover.FullMask(w), Width: w}}
		case model.KindMask:
			cubes = []cover.Cube{{Value: m.Value, Mask: m.Mask, Width: meta.Width}}
		case model.KindPrefix:
			mask := cover.FullMask(uint(m.Plen))
			if meta.Width > uint(m.Plen) {
				mask <<= meta.Width - uint(m.Plen)
			}
			cubes = []cover.Cube{{Value: m.Value & mask, Mask: mask, Width: meta.Width}}
		case model.KindRange:
			if lm != nil {
				lo, hi := lm.LabelRange(m.Lo, m.Hi)
				// Label-space covers are large and numerous; the exhaustive
				// MinMask search costs far more there than the row or two it
				// saves, so use the canonical cover above 8 label bits.
				useMin := opts.MinMask && lm.LabelBits() <= 8
				cubes = coverRange(lo, hi, lm.LabelBits(), useMin)
			} else {
				cubes = coverRange(m.Lo, m.Hi, meta.Width, opts.MinMask)
			}
		}
		if len(cubes) == 0 {
			return nil, fmt.Errorf("rule %q: %s produced no cover", r.ID, m.Field)
		}
		per = append(per, perField{field: m.Field, cubes: cubes})
	}

	var out []clause
	var build func(idx int, v, m key.Key)
	build = func(idx int, v, m key.Key) {
		if idx == len(per) {
			out = append(out, clause{K: v, M: m})
			return
		}
		pf := per[idx]
		for _, c := range pf.cubes {
			fv, fm := layout.FieldCube(pf.field, c.Value, c.Mask)
			var nv, nm key.Key
			for i := range nv {
				nv[i] = v[i] | fv[i]
				nm[i] = m[i] | fm[i]
			}
			build(idx+1, nv, nm)
		}
	}
	build(0, key.Key{}, key.Key{})
	return out, nil
}

func coverRange(lo, hi uint64, width uint, useMinMask bool) []cover.Cube {
	if useMinMask {
		return cover.MinMask(lo, hi, width)
	}
	return cover.Canonical(lo, hi, width)
}

// mergeClauses fuses clauses of the same rule when their key union is exactly
// one cube. Clauses of one rule are consecutive in the final order and share an
// action, and the union is only accepted when it is exact, so no verdict can
// change. Because every clause of a rule is in the group, a merge cannot
// swallow packets that belong to another rule.
func mergeClauses(cs []clause) []clause {
	byRule := map[int][]clause{}
	var order []int
	for i := range cs {
		b := cs[i].Prio
		if _, ok := byRule[b]; !ok {
			order = append(order, b)
		}
		byRule[b] = append(byRule[b], cs[i])
	}
	var out []clause
	for _, b := range order {
		group := byRule[b]
		// Clauses of one rule are interchangeable, so only *adjacent* pairs are
		// tried; that is O(k) per sweep and captures every union that a merge
		// can express. Making the full pairwise pass would be O(k^2) and matters
		// only for rules with thousands of clauses, where it is far too slow.
		for changed := true; changed && len(group) > 1; {
			changed = false
			next := group[:0]
			for i := 0; i < len(group); i++ {
				if i+1 < len(group) {
					if v, mv, ok := key.UnionOf(group[i].K, group[i].M, group[i+1].K, group[i+1].M); ok {
						next = append(next, clause{K: v, M: mv, Prio: b})
						i++
						changed = true
						continue
					}
				}
				next = append(next, group[i])
			}
			group = next
		}
		out = append(out, group...)
	}
	return out
}

// mergeEntries deduplicates identical rows and merges adjacent same-action rows
// whose key union is exactly one cube. Adjacency is required: two same-action
// rows separated by a different action may have that action win for packets in
// the gap, so merging them would change verdicts.
func mergeEntries(es []Entry) []Entry {
	seen := map[[2]key.Key]bool{}
	dedup := es[:0]
	for _, e := range es {
		k := [2]key.Key{e.K, e.M}
		if seen[k] {
			continue
		}
		seen[k] = true
		dedup = append(dedup, e)
	}
	es = dedup
	// Merge adjacent same-action rows whose key union is exactly one cube.
	//
	// Adjacency is required. Two same-action rows separated by other rows may be
	// fused only if every skipped row is disjoint from the whole fused pattern,
	// and proving that per pair is easy to get wrong; a wrong merge silently
	// changes verdicts. Clause merging inside one rule (mergeClauses) already
	// removes most of the redundancy, so the adjacent rule is enough here.
	out := make([]Entry, 0, len(es))
	for _, e := range es {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Action == e.Action {
				if v, m, ok := key.UnionOf(last.K, last.M, e.K, e.M); ok {
					last.K, last.M = v, m
					last.Parts = append(last.Parts, e.Parts...)
					last.Words = maxInt(last.Words, e.Words)
					continue
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// crossRuleMerge fuses same-action rows whose key union is exactly one row and
// no row in between can be affected.
//
// Why label fields block the merge: on a labelled field a key bit says "this
// value belongs to interval k", not "this raw bit is 1". An exact union of two
// label patterns is not the label pattern of the raw union: intervals between
// the two ranges would be swallowed. So a merge is only attempted when every
// labelled field has *identical* (value, mask) in both rows, in which case the
// label part of the union is that shared pattern. Raw fields merge as usual.
//
// Soundness for the rest is the same argument as mergeEntries: the two sources
// and the fused row all live at position i, every skipped row is disjoint from
// both sources (so it decides exactly the packets it decided before), and the
// union is exact (so the fused row decides exactly the union).
func crossRuleMerge(es []Entry, labelled []bool) []Entry {
	const window = 64
	used := make([]bool, len(es))
	out := make([]Entry, 0, len(es))
	for i := range es {
		if used[i] {
			continue
		}
		cur := es[i]
		limit := i + window
		if limit > len(es) {
			limit = len(es)
		}
		for j := i + 1; j < limit; j++ {
			if used[j] || es[j].Action != cur.Action {
				continue
			}
			u, um, ok := key.UnionOf(cur.K, cur.M, es[j].K, es[j].M)
			if !ok {
				continue
			}
			if !labelledUnionOK(cur, es[j], u, um, labelled) {
				continue
			}
			clear := true
			for k := i + 1; k < j; k++ {
				if used[k] {
					continue
				}
				if key.Intersects(es[k].K, es[k].M, cur.K, cur.M) ||
					key.Intersects(es[k].K, es[k].M, es[j].K, es[j].M) {
					clear = false
					break
				}
			}
			if !clear {
				continue
			}
			cur.K, cur.M = u, um
			cur.Parts = append(cur.Parts, es[j].Parts...)
			cur.Words = maxInt(cur.Words, es[j].Words)
			used[j] = true
		}
		out = append(out, cur)
	}
	return out
}

// labelledUnionOK checks the labelled fields survived the union untouched.
func labelledUnionOK(a, b Entry, u, um key.Key, labelled []bool) bool {
	for i := range labelled {
		if !labelled[i] {
			continue
		}
		if a.K[i] != b.K[i] || a.M[i] != b.M[i] {
			return false
		}
		if u[i] != a.K[i] || um[i] != a.M[i] {
			return false
		}
	}
	return true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PlanStats records what the optimiser did.
type PlanStats struct {
	MinMask      bool
	RawClauses   int
	MergedClaus  int
	Entries      int
	NaiveEntries int
	PerRule      map[string]int
	RangeExpand  int // entries attributable to range constraints
}

func summarize(p *Plan, sp ACLSpec, rawClauses int, opts Options) PlanStats {
	s := PlanStats{
		MinMask:     opts.MinMask,
		RawClauses:  rawClauses,
		Entries:     len(p.Entries),
		PerRule:     map[string]int{},
		MergedClaus: rawClauses - len(p.Entries),
	}
	for _, e := range p.Entries {
		for _, part := range e.Parts {
			s.PerRule[part.Rule]++
		}
	}
	return s
}

func sortBindings(bs []model.PortDir) {
	sort.Slice(bs, func(i, j int) bool {
		if bs[i].Port != bs[j].Port {
			return bs[i].Port < bs[j].Port
		}
		return bs[i].Dir < bs[j].Dir
	})
}
