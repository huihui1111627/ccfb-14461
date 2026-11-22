package model

import (
	"math/rand"
	"testing"
)

func TestMatchSemantics(t *testing.T) {
	// Prefix: /24 must cover 10.1.2.x and nothing else.
	m := Match{Field: FieldSrcIP, Kind: KindPrefix, Value: 10<<24 | 1<<16 | 2<<8, Plen: 24}
	for i := 0; i < 256; i++ {
		if !m.MatchKey(Key{FieldSrcIP: uint64(10<<24 | 1<<16 | 2<<8 | i)}) {
			t.Fatalf("10.1.2.%d should match /24", i)
		}
	}
	for _, v := range []uint64{10<<24 | 1<<16 | 3<<8, 10<<24 | 2<<16 | 2<<8, 11 << 24} {
		if m.MatchKey(Key{FieldSrcIP: v}) {
			t.Fatalf("%#x should not match /24", v)
		}
	}
	// /0 matches everything.
	z := Match{Field: FieldDstIP, Kind: KindPrefix, Value: 0, Plen: 0}
	if !z.MatchKey(Key{FieldDstIP: 12345}) {
		t.Fatal("/0 should match everything")
	}
	// Range is inclusive.
	r := Match{Field: FieldDstPort, Kind: KindRange, Lo: 100, Hi: 200}
	for _, v := range []uint64{99, 201, 1000} {
		if r.MatchKey(Key{FieldDstPort: v}) {
			t.Fatalf("%d should not match [100,200]", v)
		}
	}
	for _, v := range []uint64{100, 150, 200} {
		if !r.MatchKey(Key{FieldDstPort: v}) {
			t.Fatalf("%d should match [100,200]", v)
		}
	}
	// Mask.
	mk := Match{Field: FieldVLAN, Kind: KindMask, Value: 30, Mask: 0xfff}
	if !mk.MatchKey(Key{FieldVLAN: 30}) || mk.MatchKey(Key{FieldVLAN: 31}) {
		t.Fatal("mask match wrong")
	}
}

// TestDecideFirstWins checks the first-match rule order.
func TestDecideFirstWins(t *testing.T) {
	deny := Rule{ID: "d", Action: Action{ID: 2}, Matches: []Match{{Field: FieldDstPort, Kind: KindRange, Lo: 0, Hi: 65535}}}
	permit := Rule{ID: "p", Action: Action{ID: 1}, Matches: []Match{{Field: FieldDstPort, Kind: KindRange, Lo: 80, Hi: 80}}}
	rules := []*Rule{&deny, &permit}
	if got := Decide(rules, Key{FieldDstPort: 80}); got.ID != "d" {
		t.Fatalf("want d, got %s", got.ID)
	}
	rules = []*Rule{&permit, &deny}
	if got := Decide(rules, Key{FieldDstPort: 80}); got.ID != "p" {
		t.Fatalf("want p, got %s", got.ID)
	}
}

func TestValidate(t *testing.T) {
	bad := []*RuleSet{
		{Name: "x", Rules: nil},
		{Name: "x", Rules: []*Rule{{ID: "a", Matches: []Match{{Field: "nope", Kind: KindExact}}}}},
		{Name: "x", Rules: []*Rule{{ID: "a", Matches: []Match{{Field: FieldSrcIP, Kind: KindPrefix, Plen: 33}}}}},
		{Name: "x", Rules: []*Rule{{ID: "a", Matches: []Match{{Field: FieldDstPort, Kind: KindRange, Lo: 10, Hi: 5}}}}},
		{Name: "x", Rules: []*Rule{{ID: "a"}, {ID: "a"}}},
	}
	for i, rs := range bad {
		if err := rs.Validate(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// TestRangeMatchAgainstCover cross-checks the reference range test against the
// cube cover, on random ranges.
func TestRangeMatchAgainstCover(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 300; trial++ {
		lo := uint64(rng.Intn(512))
		hi := lo + uint64(rng.Intn(512-int(lo)))
		m := Match{Field: FieldVLAN, Kind: KindRange, Lo: lo, Hi: hi}
		for v := uint64(0); v < 512; v++ {
			if m.MatchKey(Key{FieldVLAN: v}) != (v >= lo && v <= hi) {
				t.Fatalf("[%d,%d] wrong at %d", lo, hi, v)
			}
		}
	}
}
