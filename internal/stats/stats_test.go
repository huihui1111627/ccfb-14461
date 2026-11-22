package stats

import (
	"math/rand"
	"testing"

	"tcamc/internal/gen"
	"tcamc/internal/model"
)

func TestAnalyzeAllProfiles(t *testing.T) {
	for _, rs := range gen.All(11) {
		rep, err := Analyze(rs, DefaultCapacity)
		if err != nil {
			t.Fatalf("%s: %v", rs.Name, err)
		}
		if rep.Optimized <= 0 {
			t.Errorf("%s: no entries", rs.Name)
		}
		if rep.Optimized > rep.NaiveTotal {
			t.Errorf("%s: optimiser made it worse (%d > %d)", rs.Name, rep.Optimized, rep.NaiveTotal)
		}
		if len(rep.WorstRules) == 0 {
			t.Errorf("%s: no per-rule costs", rs.Name)
		}
		// Ordered worst first.
		for i := 1; i < len(rep.WorstRules); i++ {
			if rep.WorstRules[i].Entries > rep.WorstRules[i-1].Entries {
				t.Errorf("%s: worst rules not sorted", rs.Name)
			}
		}
		// Range accounting is consistent.
		if rep.RangePrefixRows < rep.RangeLabelRows {
			t.Errorf("%s: label encoding increased range rows (%d > %d)", rs.Name, rep.RangeLabelRows, rep.RangePrefixRows)
		}
	}
}

// TestShortfallReport checks the "does it fit" answer and that the shortfall
// equals the arithmetic difference.
func TestShortfallReport(t *testing.T) {
	rs := gen.All(12)[0]
	rep, err := Analyze(rs, 8)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fits {
		t.Fatalf("expected %d entries not to fit in 8", rep.Optimized)
	}
	if rep.Shortfall != rep.Optimized-8 {
		t.Fatalf("shortfall %d, want %d", rep.Shortfall, rep.Optimized-8)
	}
}

// TestSuggestionsEquivalent verifies every "fuse" suggestion really is
// equivalent: applying the rewrite leaves every packet's verdict unchanged.
func TestSuggestionsEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for _, rs := range gen.All(13) {
		rep, err := Analyze(rs, DefaultCapacity)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range rep.Suggestions {
			if s.Kind != "fuse" {
				continue
			}
			// Find the pair and union their ranges, then compare verdicts.
			var a, b *model.Rule
			ids := splitFuse(s.RuleID)
			for _, r := range rs.Rules {
				if r.ID == ids[0] {
					a = r
				}
				if r.ID == ids[1] {
					b = r
				}
			}
			if a == nil || b == nil {
				t.Fatalf("fuse suggestion names missing rules %v", ids)
			}
			merged := &model.Rule{ID: "merged", Bindings: a.Bindings, Action: a.Action, Matches: append([]model.Match(nil), a.Matches...)}
			for i := range merged.Matches {
				ma, mb := a.Matches[i], b.Matches[i]
				if ma == mb {
					continue
				}
				lo, hi := ma.Lo, ma.Hi
				if mb.Lo < lo {
					lo = mb.Lo
				}
				if mb.Hi > hi {
					hi = mb.Hi
				}
				merged.Matches[i].Lo, merged.Matches[i].Hi = lo, hi
			}
			for p := 0; p < 5000; p++ {
				k := randomKey(rng)
				old := firstAction([]*model.Rule{a, b}, k)
				nw := firstAction([]*model.Rule{merged}, k)
				if old != nw {
					t.Fatalf("%s: fused rule changes verdict at %v (%d vs %d)", s.RuleID, k, old, nw)
				}
			}
		}
	}
}

func splitFuse(id string) [2]string {
	for i := 0; i < len(id); i++ {
		if id[i] == '+' {
			return [2]string{id[:i], id[i+1:]}
		}
	}
	return [2]string{id, ""}
}

func firstAction(rules []*model.Rule, k model.Key) uint8 {
	if r := model.Decide(rules, k); r != nil {
		return r.Action.ID
	}
	return 0
}

func randomKey(rng *rand.Rand) model.Key {
	k := model.Key{}
	for _, f := range model.Fields {
		w := model.Meta[f].Width
		switch w {
		case 32:
			k[f] = uint64(10)<<24 | rng.Uint64()&0xffffff
		default:
			k[f] = rng.Uint64() & (uint64(1)<<w - 1)
		}
	}
	return k
}
