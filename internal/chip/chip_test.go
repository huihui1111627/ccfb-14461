package chip

import (
	"testing"

	"tcamc/internal/compile"
	"tcamc/internal/gen"
	"tcamc/internal/model"
	"tcamc/internal/ref"
)

func TestRowPriorityIsFirstMatch(t *testing.T) {
	// Two rules that both match, at different rows: the lower row index wins.
	rs, err := compile.Build([]*model.RuleSet{mustSet(t)}, compile.Online())
	if err != nil {
		t.Fatal(err)
	}
	p := rs.Binding["ge1:in"]
	c, err := New(p, len(p.Entries)+8)
	if err != nil {
		t.Fatal(err)
	}
	// A packet that matches the first rule.
	k := model.Key{"dst_port": 80, "vlan": 30}
	got := c.LookupPacket(k, ModeLabels)
	want := ref.ActionIDOn(mustSet(t).Rules, "ge1:in", k)
	if got.ID != want {
		t.Fatalf("chip %d reference %d", got.ID, want)
	}
}

func TestSpacedLayoutSameVerdicts(t *testing.T) {
	rs := mustSet(t)
	prog, err := compile.Build([]*model.RuleSet{rs}, compile.Online())
	if err != nil {
		t.Fatal(err)
	}
	p := prog.Binding["ge1:in"]
	dense, err := New(p, len(p.Entries)+8)
	if err != nil {
		t.Fatal(err)
	}
	spaced, err := NewSpaced(p, len(p.Entries)*3+8, 2)
	if err != nil {
		t.Fatal(err)
	}
	pkts := gen.Packets(rs, 5000, 3)
	for _, k := range pkts {
		a := dense.LookupPacket(k, ModeLabels).ID
		b := spaced.LookupPacket(k, ModeLabels).ID
		if a != b {
			t.Fatalf("dense %d spaced %d at %v", a, b, k)
		}
		if a != ref.ActionIDOn(rs.Rules, "ge1:in", k) {
			t.Fatalf("verdict %d disagrees with reference at %v", a, k)
		}
	}
}

func TestFullTableRejected(t *testing.T) {
	prog, err := compile.Build([]*model.RuleSet{mustSet(t)}, compile.Online())
	if err != nil {
		t.Fatal(err)
	}
	p := prog.Binding["ge1:in"]
	if _, err := New(p, len(p.Entries)-1); err == nil {
		t.Fatal("expected capacity error")
	}
}

func mustSet(t *testing.T) *model.RuleSet {
	t.Helper()
	rs := &model.RuleSet{Name: "t", Rules: []*model.Rule{
		{ID: "a", Bindings: []string{"ge1:in"}, Action: model.Action{ID: 2},
			Matches: []model.Match{{Field: "vlan", Kind: model.KindMask, Value: 30, Mask: 0xfff}, {Field: "dst_port", Kind: model.KindRange, Lo: 80, Hi: 90}}},
		{ID: "b", Bindings: []string{"ge1:in"}, Action: model.Action{ID: 1},
			Matches: []model.Match{{Field: "dst_port", Kind: model.KindRange, Lo: 80, Hi: 90}}},
		{ID: "c", Bindings: []string{"ge1:in"}, Action: model.Action{ID: 3},
			Matches: []model.Match{{Field: "est", Kind: model.KindExact, Value: 1}}},
	}}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}
	return rs
}
