package main

import (
	"strings"
	"testing"

	"tcamc/internal/model"
	"tcamc/internal/stats"
)

const sampleRules = `
ruleset park-test
action 1 permit
action 2 deny
bind ge1:in ge2:in
rule deny-guest deny
  vlan 30/0xfff
  dst_ip 10.30.0.0/16
  comment guests cannot reach servers
rule guest-web permit
  vlan 30/0xfff
  dst_port 8000-8999
rule plc permit
  src_ip 10.40.1.0/24
  dst_port 4840-4850
rule est permit
  est 1
`

func TestParseRuleSet(t *testing.T) {
	rs, err := ParseRuleSet(sampleRules)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Name != "park-test" {
		t.Errorf("name %q", rs.Name)
	}
	if len(rs.Rules) != 4 {
		t.Fatalf("got %d rules", len(rs.Rules))
	}
	if len(rs.Rules[0].Bindings) != 2 {
		t.Errorf("bindings %v", rs.Rules[0].Bindings)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"ruleset x\nrule r1 permit\n  dst_port 80",
		"ruleset x\nbind ge1:in\nrule r1 bogus\n  dst_port 80",
		"ruleset x\nbind ge1:in\nrule r1 permit\n  dst_port 1-2-3",
		"ruleset x\nbind ge1:in\nrule r1 permit\n  src_ip 300.1.1.1/8",
		"ruleset x\nbind ge1:in\nrule r1 permit\n  nope 1",
	}
	for i, c := range cases {
		if _, err := ParseRuleSet(c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestCompileText(t *testing.T) {
	resp := CompileText(sampleRules, 2000)
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	if resp.Report == nil {
		t.Fatal("no report")
	}
	if resp.Report.Optimized == 0 || resp.Report.NaiveTotal == 0 {
		t.Fatal("empty report totals")
	}
	if len(resp.ACLs) == 0 || len(resp.ACLs[0].Entries) == 0 {
		t.Fatal("no ACL entries")
	}
	// The shared ACL must be one plan serving both ports.
	if resp.ACLs[0].Bindings == nil || len(resp.ACLs[0].Bindings) != 2 {
		t.Fatalf("bindings %v", resp.ACLs[0].Bindings)
	}
}

func TestHTMLRenders(t *testing.T) {
	rep, err := stats.Analyze(mustRuleSet(t), 2000)
	if err != nil {
		t.Fatal(err)
	}
	html, err := RenderHTML(mustRuleSet(t), rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "park-test") {
		t.Error("report missing rule set name")
	}
	if !strings.Contains(html, "optimised") {
		t.Error("report missing the comparison table")
	}
}

func mustRuleSet(t *testing.T) *model.RuleSet {
	t.Helper()
	rs, err := ParseRuleSet(sampleRules)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
