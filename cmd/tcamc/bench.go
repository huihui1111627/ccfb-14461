package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"

	"tcamc/internal/chip"
	"tcamc/internal/compile"
	"tcamc/internal/gen"
	"tcamc/internal/model"
	"tcamc/internal/ref"
	"tcamc/internal/stats"
	"tcamc/internal/update"
)

// BenchResult is the JSON shape the web page and scripts consume.
type BenchResult struct {
	Seed        int64           `json:"seed"`
	Capacity    int             `json:"capacity"`
	VerifyCount int             `json:"verify_packets"`
	RuleSets    []RuleSetResult `json:"rulesets"`
	Totals      Totals          `json:"totals"`
	GeneratedAt string          `json:"generated_at,omitempty"`
}

// RuleSetResult is one rule set's benchmark row.
type RuleSetResult struct {
	Name        string  `json:"name"`
	Rules       int     `json:"rules"`
	Bindings    int     `json:"bindings"`
	RangeCons   int     `json:"range_constraints"`
	RangePrefix int     `json:"range_prefix_rows"`
	RangeMask   int     `json:"range_mask_rows"`
	RangeLabel  int     `json:"range_label_rows"`
	Naive       int     `json:"naive_entries"`
	Optimized   int     `json:"optimized_entries"`
	Ratio       float64 `json:"ratio"`
	EncoderCost int     `json:"encoder_entries"`
	Fits        bool    `json:"fits"`
	Shortfall   int     `json:"shortfall"`
	// Per-port entries if every attachment point had its own copy.
	PerPortNaive     int `json:"per_port_naive_entries"`
	PerPortOptimized int `json:"per_port_optimized_entries"`
	// Online updates, averaged over the trials.
	Inserts      int     `json:"insert_trials"`
	InsertWrites float64 `json:"insert_avg_writes"`
	InsertMoved  float64 `json:"insert_avg_moved_rows"`
	Deletes      int     `json:"delete_trials"`
	DeleteWrites float64 `json:"delete_avg_writes"`
	// Same inserts on a densely packed table (no spare row between entries):
	// shows what the spare rows are buying.
	DenseInsertWrites float64 `json:"dense_insert_avg_writes"`
	DenseInsertMoved  float64 `json:"dense_insert_avg_moved_rows"`
	VerifyPackets     int     `json:"verify_packets"`
	Verified          bool    `json:"verified"`
	VerifyNote        string  `json:"verify_note,omitempty"`
}

// Totals aggregates across rule sets.
type Totals struct {
	Naive     int     `json:"naive_entries"`
	Optimized int     `json:"optimized_entries"`
	Ratio     float64 `json:"ratio"`
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	mustFlag(fs)
	verify := fs.Int("verify", 1000000, "packets per rule set for the differential check")
	capacity := fs.Int("capacity", stats.DefaultCapacity, "TCAM entries per direction")
	seed := fs.Int64("seed", 1, "rule generator seed")
	updates := fs.Int("updates", 12, "online insert/delete trials per rule set")
	jsonOut := fs.String("json", "", "write results as JSON")
	htmlOut := fs.String("html", "", "write an HTML report")
	quiet := fs.Bool("quiet", false, "only print the summary table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res := RunBenchmark(*seed, *capacity, *verify, *updates)
	PrintBench(os.Stdout, res, *quiet)
	if *jsonOut != "" {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("\nJSON written to %s\n", *jsonOut)
	}
	if *htmlOut != "" {
		html, err := RenderBenchHTML(res)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*htmlOut, []byte(html), 0o644); err != nil {
			return err
		}
		fmt.Printf("HTML written to %s\n", *htmlOut)
	}
	return nil
}

// RunBenchmark builds and verifies every generated rule set.
func RunBenchmark(seed int64, capacity, verify, updateTrials int) *BenchResult {
	sets := gen.All(seed)
	res := &BenchResult{Seed: seed, Capacity: capacity, VerifyCount: verify}
	for _, rs := range sets {
		res.RuleSets = append(res.RuleSets, benchOne(rs, capacity, verify, updateTrials, seed))
	}
	for _, r := range res.RuleSets {
		res.Totals.Naive += r.Naive
		res.Totals.Optimized += r.Optimized
	}
	if res.Totals.Optimized > 0 {
		res.Totals.Ratio = float64(res.Totals.Naive) / float64(res.Totals.Optimized)
	}
	return res
}

func benchOne(rs *model.RuleSet, capacity, verify, updateTrials int, seed int64) RuleSetResult {
	out := RuleSetResult{Name: rs.Name, Rules: len(rs.Rules)}
	bindings := map[string]bool{}
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			if m.Kind == model.KindRange {
				out.RangeCons++
			}
		}
		for _, b := range r.Bindings {
			bindings[b] = true
		}
	}
	out.Bindings = len(bindings)

	opt, err := compile.Build([]*model.RuleSet{rs}, compile.Optimized())
	if err != nil {
		out.VerifyNote = err.Error()
		return out
	}
	naive, err := compile.Build([]*model.RuleSet{rs}, compile.Naive())
	if err != nil {
		out.VerifyNote = err.Error()
		return out
	}
	rep, err := stats.Analyze(rs, capacity)
	if err != nil {
		out.VerifyNote = err.Error()
		return out
	}
	out.RangePrefix = rep.RangePrefixRows
	out.RangeMask = rep.RangeMaskRows
	out.RangeLabel = rep.RangeLabelRows
	out.Naive = rep.NaiveTotal
	out.Optimized = rep.Optimized
	out.Fits = rep.Fits
	out.Shortfall = rep.Shortfall
	out.EncoderCost = rep.EncoderCost
	if out.Optimized > 0 {
		out.Ratio = float64(out.Naive) / float64(out.Optimized)
	}

	// Per-port cost: sum over attachment points, as if each had its own copy.
	for b := range bindings {
		if p := naive.Binding[b]; p != nil {
			out.PerPortNaive += len(p.Entries)
		}
		if p := opt.Binding[b]; p != nil {
			out.PerPortOptimized += len(p.Entries)
		}
	}

	// Differential verification. Every attachment point is checked on its own
	// plan; the packet budget is divided across ports.
	ports := sortedKeys(bindings)
	perPort := verify / maxInt(len(ports), 1)
	if perPort < 1000 {
		perPort = 1000
	}
	out.Verified = true
	out.VerifyPackets = 0
	for _, b := range ports {
		p := opt.Binding[b]
		if p == nil {
			out.Verified = false
			out.VerifyNote = "no plan for " + b
			continue
		}
		c, err := chip.New(p, len(p.Entries)+16)
		if err != nil {
			out.Verified = false
			out.VerifyNote = err.Error()
			continue
		}
		pkts := gen.Packets(rs, perPort, seed*1000+int64(len(b)))
		for i, pk := range pkts {
			got := c.LookupPacket(pk, chip.ModeLabels).ID
			want := ref.ActionIDOn(rs.Rules, b, pk)
			if got != want {
				out.Verified = false
				out.VerifyNote = fmt.Sprintf("%s packet %d: chip %d reference %d", b, i, got, want)
				break
			}
			out.VerifyPackets++
		}
		if !out.Verified {
			break
		}
	}

	// Also check the naive baseline, on a sample, to keep the ratio honest.
	if out.Verified {
		b := ports[0]
		p := naive.Binding[b]
		c, err := chip.New(p, len(p.Entries)+8)
		if err == nil {
			for i, pk := range gen.Packets(rs, 5000, seed*7+3) {
				got := c.LookupPacket(pk, chip.ModeRaw).ID
				want := ref.ActionIDOn(rs.Rules, b, pk)
				if got != want {
					out.Verified = false
					out.VerifyNote = fmt.Sprintf("naive %s packet %d: %d vs %d", b, i, got, want)
					break
				}
			}
		}
	}

	// Online update benchmark.
	ins, del, inserts, deletes := benchUpdates(rs, capacity, updateTrials, seed, 1)
	dins, _, denseInserts, _ := benchUpdates(rs, capacity, updateTrials, seed, 0)
	out.Inserts, out.Deletes = inserts, deletes
	if inserts > 0 {
		out.InsertWrites = float64(ins.writes) / float64(inserts)
		out.InsertMoved = float64(ins.moved) / float64(inserts)
	}
	if deletes > 0 {
		out.DeleteWrites = float64(del.writes) / float64(deletes)
	}
	if denseInserts > 0 {
		out.DenseInsertWrites = float64(dins.writes) / float64(denseInserts)
		out.DenseInsertMoved = float64(dins.moved) / float64(denseInserts)
	}
	return out
}

type updStat struct{ writes, moved int }

// benchUpdates inserts and deletes rules online against a live table, verifying
// every intermediate state on a packet sample.
func benchUpdates(rs *model.RuleSet, capacity, trials int, seed int64, gap int) (ins, del updStat, inserts, deletes int) {
	binding := "ge1:in"
	has := false
	for _, r := range rs.Rules {
		for _, b := range r.Bindings {
			if b == binding {
				has = true
			}
		}
	}
	if !has {
		for _, r := range rs.Rules {
			if len(r.Bindings) > 0 {
				binding = r.Bindings[0]
				has = true
				break
			}
		}
	}
	if !has {
		return
	}
	prog, err := compile.Build([]*model.RuleSet{rs}, compile.Online())
	if err != nil {
		return
	}
	p := prog.Binding[binding]
	if p == nil {
		return
	}
	// Program the table with one free row after each entry: this is the layout
	// an operator would use on a table that is expected to change, and it is
	// what makes inserts cheap. The gap costs capacity, which the benchmark
	// accounts for by holding at least entries*2+16 rows.
	cap := capacity
	if need := len(p.Entries)*2 + 64; cap < need {
		cap = need
	}
	c, err := chip.NewSpaced(p, cap, gap)
	if err != nil {
		return
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
		return
	}
	sample := gen.Packets(rs, 1500, seed*13+5)
	// Inserted rules reuse existing range boundaries so they are expressible on
	// the label-encoded table.
	var catalogue [][2]uint64
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			if m.Kind == model.KindRange {
				catalogue = append(catalogue, [2]uint64{m.Lo, m.Hi})
			}
		}
	}
	if len(catalogue) == 0 {
		catalogue = [][2]uint64{{80, 80}, {443, 443}, {1024, 2047}}
	}
	rng := rand.New(rand.NewSource(seed*31 + 9))
	inserted := []string{}
	for i := 0; i < trials; i++ {
		r := synthRule(rng, i, binding, catalogue)
		if err := u.Chip.Plan.CheckInsertable(r); err != nil {
			// Retry with a different catalogue range before giving up: a range
			// whose boundaries are not cuts cannot be inserted online, and the
			// benchmark wants to measure inserts that are possible.
			for tries := 0; tries < 8; tries++ {
				r = synthRule(rng, i, binding, catalogue)
				if u.Chip.Plan.CheckInsertable(r) == nil {
					break
				}
			}
			if err := u.Chip.Plan.CheckInsertable(r); err != nil {
				continue
			}
		}
		at := rng.Intn(len(u.Rules) + 1)
		oldRules := append([]*model.Rule(nil), u.Rules...)
		newRules := append([]*model.Rule(nil), oldRules...)
		newRules = append(newRules[:at], append([]*model.Rule{r}, newRules[at:]...)...)
		tr := newTransition(binding, oldRules, newRules, sample)
		u.Verifier = tr.check
		res, err := u.Insert(at, r)
		u.Verifier = nil
		if err != nil {
			continue
		}
		if err := tr.check(u.Chip); err != nil {
			continue
		}
		inserts++
		ins.writes += res.Writes
		ins.moved += res.Moved
		inserted = append(inserted, r.ID)
	}
	for _, id := range inserted {
		oldRules := append([]*model.Rule(nil), u.Rules...)
		var newRules []*model.Rule
		for _, r := range oldRules {
			if r.ID != id {
				newRules = append(newRules, r)
			}
		}
		tr := newTransition(binding, oldRules, newRules, sample)
		u.Verifier = tr.check
		res, err := u.Delete(id)
		u.Verifier = nil
		if err != nil {
			continue
		}
		deletes++
		del.writes += res.Writes
	}
	return
}

func synthRule(rng *rand.Rand, i int, binding string, catalogue [][2]uint64) *model.Rule {
	p := catalogue[rng.Intn(len(catalogue))]
	act := gen.Permit
	if i%4 == 3 {
		act = gen.Deny
	}
	return &model.Rule{
		ID:       fmt.Sprintf("bench%03d", i),
		Bindings: []string{binding},
		Matches: []model.Match{
			{Field: "src_ip", Kind: model.KindPrefix, Value: uint64(10)<<24 | uint64(rng.Intn(256))<<16, Plen: 16},
			{Field: "dst_port", Kind: model.KindRange, Lo: p[0], Hi: p[1]},
		},
		Action: act,
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PrintBench writes the summary.
func PrintBench(w *os.File, res *BenchResult, quiet bool) {
	fmt.Printf("tcamc benchmark  seed=%d capacity=%d verify=%d packets/rule set\n\n", res.Seed, res.Capacity, res.VerifyCount)
	fmt.Printf("%-16s %5s %4s %5s %8s %8s %7s %7s %8s %6s %6s\n",
		"rule set", "rules", "ports", "ranges", "naive", "opt", "ratio", "range exp", "fits", "ins wr", "ins mv")
	for _, r := range res.RuleSets {
		fits := "yes"
		if !r.Fits {
			fits = fmt.Sprintf("SHORT %d", r.Shortfall)
		}
		rexp := "-"
		if r.RangePrefix > 0 {
			rexp = fmt.Sprintf("%d>%d", r.RangePrefix, r.RangeLabel)
		}
		fmt.Printf("%-16s %5d %4d %5d %8d %8d %6.2fx %8s %7s %6.1f %6.1f\n",
			r.Name, r.Rules, r.Bindings, r.RangeCons, r.Naive, r.Optimized, r.Ratio, rexp, fits,
			r.InsertWrites, r.InsertMoved)
	}
	fmt.Printf("%-16s %5s %4s %5s %8d %8d %6.2fx\n", "TOTAL", "", "", "", res.Totals.Naive, res.Totals.Optimized, res.Totals.Ratio)
	ok := true
	totalVerified := 0
	for _, r := range res.RuleSets {
		totalVerified += r.VerifyPackets
		if !r.Verified {
			ok = false
		}
	}
	if ok {
		fmt.Printf("\ndifferential check: %d packets, all verdicts equal to the reference\n", totalVerified)
	} else {
		fmt.Printf("\ndifferential check: FAILED\n")
		for _, r := range res.RuleSets {
			if !r.Verified {
				fmt.Printf("  %s: %s\n", r.Name, r.VerifyNote)
			}
		}
	}
	if quiet {
		return
	}
	fmt.Printf("\nport-range expansion (rows needed by the range constraints alone):\n")
	fmt.Printf("  %-16s %10s %10s %10s\n", "rule set", "prefix", "min-mask", "optimised")
	for _, r := range res.RuleSets {
		fmt.Printf("  %-16s %10d %10d %10d\n", r.Name, r.RangePrefix, r.RangeMask, r.RangeLabel)
	}

	fmt.Printf("\nonline updates (average per operation):\n")
	fmt.Printf("  %-16s %8s %8s %10s %10s\n", "rule set", "inserts", "deletes", "ins writes", "ins moved")
	for _, r := range res.RuleSets {
		fmt.Printf("  %-16s %8d %8d %10.1f %10.1f\n", r.Name, r.Inserts, r.Deletes, r.InsertWrites, r.InsertMoved)
	}
	fmt.Printf("\nsame inserts on a densely packed table (no spare rows), for comparison:\n")
	fmt.Printf("  %-16s %10s %10s\n", "rule set", "avg writes", "avg moved")
	for _, r := range res.RuleSets {
		fmt.Printf("  %-16s %10.1f %10.1f\n", r.Name, r.DenseInsertWrites, r.DenseInsertMoved)
	}

	fmt.Printf("\nper-port cost if every attachment had its own copy (sharing saving):\n")
	fmt.Printf("  %-16s %12s %12s\n", "rule set", "plain", "optimised")
	for _, r := range res.RuleSets {
		fmt.Printf("  %-16s %12d %12d\n", r.Name, r.PerPortNaive, r.PerPortOptimized)
	}
}
