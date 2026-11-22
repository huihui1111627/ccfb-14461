package update_test

import (
	"fmt"
	"math/rand"
	"testing"

	"tcamc/internal/chip"
	"tcamc/internal/compile"
	"tcamc/internal/gen"
	"tcamc/internal/model"
	"tcamc/internal/ref"
	"tcamc/internal/update"
)

func setup(t *testing.T, rs *model.RuleSet, binding string, opts compile.Options) (*update.Updater, []*model.Rule) {
	t.Helper()
	prog, err := compile.Build([]*model.RuleSet{rs}, opts)
	if err != nil {
		t.Fatal(err)
	}
	p := prog.Binding[binding]
	if p == nil {
		t.Fatalf("no plan for %s", binding)
	}
	// Leave a free row after each entry, the layout an operator uses on a table
	// expected to change.
	c, err := chip.NewSpaced(p, len(p.Entries)*2+256, 1)
	if err != nil {
		t.Fatal(err)
	}
	var rules []*model.Rule
	for _, r := range rs.Rules {
		for _, b := range r.Bindings {
			if b == binding {
				rules = append(rules, r)
				break
			}
		}
	}
	u, err := update.NewUpdater(c, rules)
	if err != nil {
		t.Fatal(err)
	}
	return u, rules
}

func pkID(pk model.Key) string {
	s := ""
	for _, f := range model.Fields {
		s += fmt.Sprintf("%d,", pk[f])
	}
	return s
}

// transition records, per packet, the only two verdicts that are acceptable in
// any intermediate state of one update: the verdict before it and the verdict
// after it. "Old or new, never anything else" is exactly the no-wrong-match
// invariant for a table being edited one row at a time.
type transition struct {
	binding string
	pkts    []model.Key
	oldAct  map[string]uint8
	newAct  map[string]uint8
}

func newTransition(binding string, oldRules, newRules []*model.Rule, pkts []model.Key) *transition {
	tr := &transition{
		binding: binding,
		pkts:    pkts,
		oldAct:  map[string]uint8{},
		newAct:  map[string]uint8{},
	}
	for _, pk := range pkts {
		id := pkID(pk)
		tr.oldAct[id] = ref.ActionIDOn(oldRules, binding, pk)
		tr.newAct[id] = ref.ActionIDOn(newRules, binding, pk)
	}
	return tr
}

func (tr *transition) check(c *chip.Chip) error {
	for _, pk := range tr.pkts {
		got := c.LookupPacket(pk, chip.ModeLabels).ID
		id := pkID(pk)
		o, n := tr.oldAct[id], tr.newAct[id]
		if got != o && got != n {
			return fmt.Errorf("verdict %d is neither old %d nor new %d for %v", got, o, n, pk)
		}
	}
	return nil
}

// TestInsertIntermediateStates inserts rules at random positions and verifies,
// after *every* single-row write, that each packet sees its old or new verdict.
func TestInsertIntermediateStates(t *testing.T) {
	for _, rs := range gen.All(5) {
		t.Run(rs.Name, func(t *testing.T) {
			binding := "ge1:in"
			u, _ := setup(t, rs, binding, compile.Online())
			pkts := gen.Packets(rs, 3000, 99)
			rng := rand.New(rand.NewSource(11))
			applied := 0
			for step := 0; step < 10; step++ {
				r := randomRule(rng, step, binding, rangesIn(rs))
				if err := u.Chip.Plan.CheckInsertable(r); err != nil {
					continue
				}
				at := rng.Intn(len(u.Rules) + 1)
				oldRules := append([]*model.Rule(nil), u.Rules...)
				// The planner may shift the placement within the equal-action
				// run; ask it first so the reference order matches.
				place := u.PlanPosition(at, r)
				newRules := append([]*model.Rule(nil), oldRules...)
				newRules = append(newRules[:place], append([]*model.Rule{r}, newRules[place:]...)...)
				tr := newTransition(binding, oldRules, newRules, pkts)
				u.Verifier = tr.check
				res, err := u.Insert(at, r)
				if err != nil {
					t.Fatalf("insert at %d: %v", at, err)
				}
				if res.Moved > 0 {
					t.Logf("  moved %d rows; steps: %v", res.Moved, stepSummary(res))
				}
				u.Verifier = nil
				if err := tr.check(u.Chip); err != nil {
					t.Fatalf("final state after insert %s at %d: %v", r.ID, at, err)
				}
				t.Logf("insert %s at %d/%d: %d writes (%d moved rows)", r.ID, at, len(newRules), res.Writes, res.Moved)
				applied++
			}
			if applied == 0 {
				t.Fatal("no insert was applicable")
			}
		})
	}
}

// TestDeleteIntermediateStates deletes rules and verifies after every row clear.
func TestDeleteIntermediateStates(t *testing.T) {
	for _, rs := range gen.All(6) {
		t.Run(rs.Name, func(t *testing.T) {
			binding := "ge1:in"
			u, _ := setup(t, rs, binding, compile.Online())
			pkts := gen.Packets(rs, 2000, 123)
			rng := rand.New(rand.NewSource(21))
			for len(u.Rules) > 3 {
				id := u.Rules[rng.Intn(len(u.Rules))].ID
				oldRules := append([]*model.Rule(nil), u.Rules...)
				var newRules []*model.Rule
				for _, r := range oldRules {
					if r.ID != id {
						newRules = append(newRules, r)
					}
				}
				tr := newTransition(binding, oldRules, newRules, pkts)
				u.Verifier = tr.check
				res, err := u.Delete(id)
				if err != nil {
					t.Fatalf("delete %s: %v", id, err)
				}
				u.Verifier = nil
				if err := tr.check(u.Chip); err != nil {
					t.Fatalf("final state after delete %s: %v", id, err)
				}
				t.Logf("delete %s (%d rows): %d writes", id, len(res.Removed), res.Writes)
			}
		})
	}
}

// TestEndStateCorrectAfterManyUpdates applies a long random sequence, then
// does one full reference comparison so drift cannot hide.
func TestEndStateCorrectAfterManyUpdates(t *testing.T) {
	for _, rs := range gen.All(7) {
		t.Run(rs.Name, func(t *testing.T) {
			binding := "ge1:in"
			u, _ := setup(t, rs, binding, compile.Online())
			pkts := gen.Packets(rs, 4000, 77)
			rng := rand.New(rand.NewSource(31))
			for step := 0; step < 40; step++ {
				if rng.Intn(2) == 0 && len(u.Rules) > 2 {
					id := u.Rules[rng.Intn(len(u.Rules))].ID
					_ = id
					if _, err := u.Delete(id); err != nil {
						t.Fatalf("step %d delete %s: %v", step, id, err)
					}
				} else {
					r := randomRule(rng, step, binding, rangesIn(rs))
					if err := u.Chip.Plan.CheckInsertable(r); err != nil {
						continue
					}
					// Make ids unique across steps.
					r.ID = fmt.Sprintf("new%03d", step)
					at := rng.Intn(len(u.Rules) + 1)
					place := u.PlanPosition(at, r)
					res, err := u.Insert(at, r)
					if err != nil {
						t.Fatalf("step %d insert: %v", step, err)
					}
					if res.PlannedAt != place {
						t.Fatalf("step %d: planner said %d, insert used %d", step, place, res.PlannedAt)
					}
					t.Logf("step %d inserted %s at %d (planned %d)", step, r.ID, at, place)
				}
			}
			for _, pk := range pkts {
				got := u.Chip.LookupPacket(pk, chip.ModeLabels).ID
				want := ref.ActionIDOn(u.Rules, binding, pk)
				if got != want {
					t.Fatalf("%v: chip %d reference %d", pk, got, want)
				}
			}
			t.Logf("%d rules, %d rows used", len(u.Rules), u.Chip.Used())
		})
	}
}

// rangesIn collects every range from the rule set so inserted rules reuse
// existing label cuts. A label-encoded table can only accept online inserts
// whose boundaries are already cuts; new boundaries would force a relabel.
func rangesIn(rs *model.RuleSet) [][2]uint64 {
	var out [][2]uint64
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			if m.Kind == model.KindRange {
				out = append(out, [2]uint64{m.Lo, m.Hi})
			}
		}
	}
	return out
}

func randomRule(rng *rand.Rand, step int, binding string, catalogue [][2]uint64) *model.Rule {
	p := catalogue[rng.Intn(len(catalogue))]
	act := gen.Permit
	if step%3 == 2 {
		act = gen.Deny
	}
	return &model.Rule{
		ID:       fmt.Sprintf("new%02d", step),
		Bindings: []string{binding},
		Matches: []model.Match{
			{Field: "src_ip", Kind: model.KindPrefix, Value: uint64(10)<<24 | uint64(rng.Intn(256))<<16, Plen: 16},
			{Field: "dst_port", Kind: model.KindRange, Lo: p[0], Hi: p[1]},
		},
		Action: act,
	}
}

func stepSummary(res *update.Result) string {
	out := ""
	for _, s := range res.Steps {
		out += fmt.Sprintf("r%d", s.Row)
		if s.To.Empty {
			out += "x"
		}
		out += " "
	}
	if len(out) > 400 {
		out = out[:400]
	}
	return out
}
