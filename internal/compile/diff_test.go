package compile_test

import (
	"testing"

	"tcamc/internal/chip"
	"tcamc/internal/compile"
	"tcamc/internal/gen"
	"tcamc/internal/model"
	"tcamc/internal/ref"
)

// TestDifferential compiles every generated rule set with the fully optimised
// pipeline and checks several hundred thousand packets against the reference
// evaluator. The check is on the action, not on the rule id: two rules with the
// same action are interchangeable.
func TestDifferential(t *testing.T) {
	sets := gen.All(1)
	for _, rs := range sets {
		rs := rs
		t.Run(rs.Name, func(t *testing.T) {
			if err := rs.Validate(); err != nil {
				t.Fatalf("invalid rule set: %v", err)
			}
			prog, err := compile.Build([]*model.RuleSet{rs}, compile.Optimized())
			if err != nil {
				t.Fatal(err)
			}
			// Every attachment point of the rule set resolves to a plan.
			pkts := gen.Packets(rs, 60000, 42)
			for _, b := range bindingsOf(rs) {
				p := prog.Binding[b]
				if p == nil {
					t.Fatalf("no plan bound to %s", b)
				}
				c, err := chip.New(p, len(p.Entries)+64)
				if err != nil {
					t.Fatal(err)
				}
				for i, pk := range pkts {
					got := c.LookupPacket(pk, chip.ModeLabels).ID
					want := ref.ActionIDOn(rs.Rules, b, pk)
					if got != want {
						t.Fatalf("%s pkt %d %v: chip action %d, reference %d", b, i, pk, got, want)
					}
				}
			}
			t.Logf("%d rules -> %d entries (raw clauses %d)", len(rs.Rules), len(prog.ACLs[0].Entries), prog.ACLs[0].Stats.RawClauses)
		})
	}
}

func bindingsOf(rs *model.RuleSet) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs.Rules {
		for _, b := range r.Bindings {
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	return out
}

// TestNaiveDifferential checks that the baseline compiler is also correct; its
// output is the denominator of the compression ratios.
func TestNaiveDifferential(t *testing.T) {
	for _, rs := range gen.All(2) {
		prog, err := compile.Build([]*model.RuleSet{rs}, compile.Naive())
		if err != nil {
			t.Fatal(err)
		}
		b0 := bindingsOf(rs)[0]
		p := prog.Binding[b0]
		c, err := chip.New(p, len(p.Entries)+8)
		if err != nil {
			t.Fatal(err)
		}
		for _, pk := range gen.Packets(rs, 20000, 7) {
			got := c.LookupPacket(pk, chip.ModeRaw).ID
			want := ref.ActionIDOn(rs.Rules, b0, pk)
			if got != want {
				t.Fatalf("%s %v: naive chip %d reference %d", rs.Name, pk, got, want)
			}
		}
	}
}
