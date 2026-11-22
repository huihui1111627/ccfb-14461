// Package stats produces the operator-facing reports: table sizes, compression
// ratios, where the entries went, and -- when a rule set does not fit -- the
// shortfall, the most expensive rules, and cheaper equivalent spellings.
package stats

import (
	"fmt"
	"sort"

	"tcamc/internal/compile"
	"tcamc/internal/cover"
	"tcamc/internal/encode"
	"tcamc/internal/model"
)

// Capacity is the TCAM size of the target part. The customer's part has 2000
// entries per direction; the default here matches.
const DefaultCapacity = 2000

// PlanReport is the per-ACL part of the report.
type PlanReport struct {
	Name           string
	Bindings       int
	Rules          int
	NaiveEntries   int
	CompiledEnt    int
	LabelsEnabled  []string
	EntriesPerRule map[string]int
}

// Compression is the ratio naive/compiled.
func (p PlanReport) Compression() float64 {
	if p.CompiledEnt == 0 {
		return 0
	}
	return float64(p.NaiveEntries) / float64(p.CompiledEnt)
}

// Report is the whole rule set report.
type Report struct {
	RuleSet      string
	Capacity     int
	Plans        []PlanReport
	NaiveTotal   int
	Optimized    int
	EncoderCost  int
	Fits         bool
	Shortfall    int
	WorstRules   []RuleCost
	Suggestions  []Suggestion
	SharedSaving int
	// Range-specific accounting (requirement 1): how many rows each range
	// costs under plain prefix expansion vs under the optimiser's encoding.
	Ranges          int
	RangePrefixRows int
	RangeMaskRows   int
	RangeLabelRows  int
}

// rangeAccounting measures the per-range cost three ways. "prefix" is the
// textbook aligned-block expansion, "mask" allows arbitrary ternary masks on
// the raw value, and "label" is what the optimiser emits for a labelled field
// (dense interval labels, where a range becomes a short label run).
func (r *Report) rangeAccounting(rs *model.RuleSet, opt *compile.Program) {
	// MinMask's exhaustive search is bounded to small widths; use it for the
	// accounting only up to the same bound, so the report stays fast.
	minRows := func(lo, hi uint64, w uint) int {
		if w <= 10 {
			return len(cover.MinMask(lo, hi, w))
		}
		return len(cover.Canonical(lo, hi, w))
	}
	lms := map[string]*encode.IntervalMap{}
	for _, p := range opt.ACLs {
		for _, fi := range p.Fields {
			if fi.Labels != nil {
				lms[fi.Field] = fi.Labels
			}
		}
	}
	for _, rule := range rs.Rules {
		for _, m := range rule.Matches {
			if m.Kind != model.KindRange {
				continue
			}
			w := model.Meta[m.Field].Width
			r.Ranges++
			r.RangePrefixRows += len(cover.Canonical(m.Lo, m.Hi, w))
			// MinMask is an exhaustive search up to 12 bits; above that it falls
			// back to Canonical, so this is bounded. The accounting is a report,
			// not the compiled table, so it prefers the exact-but-slower cover and
			// uses the cheap one once there are many ranges.
			r.RangeMaskRows += minRows(m.Lo, m.Hi, w)
			if lm := lms[m.Field]; lm != nil {
				lo, hi := lm.LabelRange(m.Lo, m.Hi)
				r.RangeLabelRows += minRows(lo, hi, lm.LabelBits())
			} else {
				r.RangeLabelRows += minRows(m.Lo, m.Hi, w)
			}
		}
	}
}

// RuleCost is one rule's share of the table.
type RuleCost struct {
	RuleID  string
	Entries int
	Naive   int
	Comment string
	Reason  string
}

// Suggestion is an equivalent-but-cheaper rewrite.
type Suggestion struct {
	RuleID  string
	Before  int
	After   int
	Kind    string
	Message string
	Rewrite string
}

// Analyze builds the report for one rule set at the given capacity.
func Analyze(rs *model.RuleSet, capacity int) (*Report, error) {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	opt, err := compile.Build([]*model.RuleSet{rs}, compile.Optimized())
	if err != nil {
		return nil, err
	}
	naive, err := compile.Build([]*model.RuleSet{rs}, compile.Naive())
	if err != nil {
		return nil, err
	}
	r := &Report{RuleSet: rs.Name, Capacity: capacity, EncoderCost: opt.Encoder.Total}
	r.rangeAccounting(rs, opt)

	// Map plans to the attachments they serve, counting the entries once even
	// when many ports share the table.
	planNaive := map[*compile.Plan]int{}
	for _, p := range naive.ACLs {
		planNaive[p] = len(p.Entries)
	}
	for _, p := range opt.ACLs {
		pr := PlanReport{
			Name:           p.Name,
			Bindings:       len(p.Bindings),
			Rules:          len(p.RuleIDs),
			CompiledEnt:    len(p.Entries),
			EntriesPerRule: p.Stats.PerRule,
		}
		// The naive baseline for the same attachment set.
		for q, n := range planNaive {
			if sameBindings(p, q) {
				pr.NaiveEntries = n
			}
		}
		for _, fi := range p.Fields {
			if fi.Labels != nil {
				pr.LabelsEnabled = append(pr.LabelsEnabled, fi.Field)
			}
		}
		r.Plans = append(r.Plans, pr)
		r.NaiveTotal += pr.NaiveEntries
		r.Optimized += pr.CompiledEnt
		if pr.Bindings > 1 {
			r.SharedSaving += pr.CompiledEnt * (pr.Bindings - 1)
		}
	}

	// Worst rules: count entries attributable to each rule across plans.
	cost := map[string]*RuleCost{}
	for _, p := range opt.ACLs {
		for _, e := range p.Entries {
			for _, part := range e.Parts {
				rc, ok := cost[part.Rule]
				if !ok {
					rc = &RuleCost{RuleID: part.Rule}
					cost[part.Rule] = rc
				}
				rc.Entries++
			}
		}
	}
	for id, rc := range cost {
		for _, rule := range rs.Rules {
			if rule.ID == id {
				rc.Comment = rule.Comment
				rc.Reason = expensiveReason(rule)
				rc.Naive = naiveCost(rule)
				break
			}
		}
	}
	for _, rc := range cost {
		r.WorstRules = append(r.WorstRules, *rc)
	}
	sort.Slice(r.WorstRules, func(i, j int) bool {
		if r.WorstRules[i].Entries != r.WorstRules[j].Entries {
			return r.WorstRules[i].Entries > r.WorstRules[j].Entries
		}
		return r.WorstRules[i].RuleID < r.WorstRules[j].RuleID
	})

	if r.Optimized > capacity {
		r.Fits = false
		r.Shortfall = r.Optimized - capacity
	} else {
		r.Fits = true
	}
	r.Suggestions = suggest(rs, cost, capacity-r.Optimized)
	return r, nil
}

func sameBindings(a, b *compile.Plan) bool {
	if len(a.Bindings) != len(b.Bindings) {
		return false
	}
	am := map[string]bool{}
	for _, x := range a.Bindings {
		am[x.Port+":"+x.Dir] = true
	}
	for _, x := range b.Bindings {
		if !am[x.Port+":"+x.Dir] {
			return false
		}
	}
	return true
}

// naiveCost is the canonical prefix expansion cost of one rule.
func naiveCost(r *model.Rule) int {
	n := 1
	for _, m := range r.Matches {
		meta := model.Meta[m.Field]
		switch m.Kind {
		case model.KindRange:
			n *= len(cover.Canonical(m.Lo, m.Hi, meta.Width))
		case model.KindPrefix, model.KindExact, model.KindMask:
			n *= 1
		}
	}
	return n
}

func expensiveReason(r *model.Rule) string {
	var ranges int
	var widest uint64
	for _, m := range r.Matches {
		if m.Kind == model.KindRange {
			ranges++
			if w := m.Hi - m.Lo; w > widest {
				widest = w
			}
		}
	}
	if ranges == 0 {
		return "prefix/mask only"
	}
	return fmt.Sprintf("%d range constraint(s), widest span %d", ranges, widest)
}
