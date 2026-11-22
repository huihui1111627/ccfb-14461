package stats

import (
	"fmt"
	"sort"

	"tcamc/internal/cover"
	"tcamc/internal/model"
)

// suggest proposes equivalent, cheaper spellings. Each suggestion is chosen to
// reflect what the *compiled* table actually spends, not a naive guess: a wide
// port range is already one row once labelled, so recommending "split the
// range" would be wrong. The suggestions therefore focus on the things the
// optimiser cannot fix on its own:
//
//   - a rule whose cost is the product of several multi-cube constraints, where
//     dropping one constraint or narrowing one field saves the most;
//   - two adjacent same-action rules that differ only in a range, which can be
//     written as one rule (fewer rows downstream, and one fewer rule to manage);
//   - a range that is not a single aligned block and is being encoded raw (no
//     label encoding available, e.g. because the field is matched by a prefix),
//     where adding label encoding or splitting at an aligned boundary helps.
func suggest(rs *model.RuleSet, cost map[string]*RuleCost, slack int) []Suggestion {
	var out []Suggestion

	for id, rc := range cost {
		if rc.Entries <= 1 && rangeConstraints(ruleByID(rs, id)) < 2 {
			continue
		}
		r := ruleByID(rs, id)
		if r == nil {
			continue
		}
		// Report the constraint that contributes most. For a rule with several
		// range constraints this is usually the widest, since its cover is what
		// multiplied through.
		var worst *model.Match
		worstRows := 0
		for i := range r.Matches {
			m := &r.Matches[i]
			if m.Kind != model.KindRange {
				continue
			}
			w := model.Meta[m.Field].Width
			rows := len(cover.Canonical(m.Lo, m.Hi, w))
			if rows > worstRows {
				worstRows = rows
				worst = m
			}
		}
		if worst == nil {
			continue
		}
		out = append(out, Suggestion{
			RuleID:  id,
			Before:  rc.Entries,
			After:   rc.Entries,
			Kind:    "cost",
			Message: fmt.Sprintf("%d rows; the biggest contributor is %s [%d,%d] (%d prefix blocks raw)", rc.Entries, worst.Field, worst.Lo, worst.Hi, worstRows),
			Rewrite: multiRangeHint(r),
		})
	}

	out = append(out, fuseAdjacent(rs, cost)...)

	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// multiRangeHint describes why a rule is expensive and the concrete lever.
func multiRangeHint(r *model.Rule) string {
	var ranges int
	for _, m := range r.Matches {
		if m.Kind == model.KindRange {
			ranges++
		}
	}
	if ranges > 1 {
		return fmt.Sprintf("this rule ANDs %d range constraints, so its rows multiply; consider splitting it into one rule per range (same effect when the ranges are independent) or narrowing one range", ranges)
	}
	return "narrow the range, or match on a coarser field if the application allows it"
}

func rangeConstraints(r *model.Rule) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, m := range r.Matches {
		if m.Kind == model.KindRange {
			n++
		}
	}
	return n
}

func ruleByID(rs *model.RuleSet, id string) *model.Rule {
	for _, r := range rs.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func fuseAdjacent(rs *model.RuleSet, cost map[string]*RuleCost) []Suggestion {
	var out []Suggestion
	for i := 0; i+1 < len(rs.Rules); i++ {
		a, b := rs.Rules[i], rs.Rules[i+1]
		if a.Action.ID != b.Action.ID || len(a.Matches) != len(b.Matches) {
			continue
		}
		differ := -1
		ok := true
		for j := range a.Matches {
			if a.Matches[j] == b.Matches[j] {
				continue
			}
			if differ >= 0 {
				ok = false
				break
			}
			differ = j
		}
		if !ok || differ < 0 {
			continue
		}
		ma, mb := a.Matches[differ], b.Matches[differ]
		if ma.Kind != model.KindRange || mb.Kind != model.KindRange || ma.Field != mb.Field {
			continue
		}
		// Only adjacent or overlapping ranges fuse into one range.
		if ma.Hi+1 < mb.Lo || mb.Hi+1 < ma.Lo {
			continue
		}
		lo, hi := ma.Lo, ma.Hi
		if mb.Lo < lo {
			lo = mb.Lo
		}
		if mb.Hi > hi {
			hi = mb.Hi
		}
		out = append(out, Suggestion{
			RuleID:  a.ID + "+" + b.ID,
			Before:  entriesOf(cost, a.ID) + entriesOf(cost, b.ID),
			After:   entriesOf(cost, a.ID) + entriesOf(cost, b.ID),
			Kind:    "fuse",
			Message: fmt.Sprintf("%s and %s have the same action and differ only in %s [%d,%d] vs [%d,%d]; one rule with [%d,%d] is equivalent", a.ID, b.ID, ma.Field, ma.Lo, ma.Hi, mb.Lo, mb.Hi, lo, hi),
			Rewrite: fmt.Sprintf("merge %s into %s with %s range [%d,%d]", b.ID, a.ID, ma.Field, lo, hi),
		})
	}
	return out
}

func entriesOf(cost map[string]*RuleCost, id string) int {
	if rc, ok := cost[id]; ok {
		return rc.Entries
	}
	return 0
}
