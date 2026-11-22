package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"tcamc/internal/compile"
	"tcamc/internal/model"
	"tcamc/internal/stats"
)

func runCompile(args []string) error {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	mustFlag(fs)
	file := fs.String("ruleset", "", "rule set file (required)")
	capacity := fs.Int("capacity", stats.DefaultCapacity, "TCAM entries available per direction")
	jsonOut := fs.String("json", "", "write the report as JSON to this path")
	htmlOut := fs.String("html", "", "write an HTML report to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("-ruleset is required")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	rs, err := ParseRuleSet(string(data))
	if err != nil {
		return fmt.Errorf("%s: %w", *file, err)
	}
	if err := rs.Validate(); err != nil {
		return err
	}
	rep, err := stats.Analyze(rs, *capacity)
	if err != nil {
		return err
	}
	opt, err := compile.Build([]*model.RuleSet{rs}, compile.Optimized())
	if err != nil {
		return err
	}
	naive, err := compile.Build([]*model.RuleSet{rs}, compile.Naive())
	if err != nil {
		return err
	}
	PrintReport(os.Stdout, rs, rep, opt, naive)
	if *jsonOut != "" {
		if err := WriteJSON(*jsonOut, rs, rep); err != nil {
			return err
		}
		fmt.Printf("\nJSON report written to %s\n", *jsonOut)
	}
	if *htmlOut != "" {
		html, err := RenderHTML(rs, rep)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*htmlOut, []byte(html), 0o644); err != nil {
			return err
		}
		fmt.Printf("HTML report written to %s\n", *htmlOut)
	}
	return nil
}

// PrintReport writes the human-readable compilation report.
func PrintReport(w *os.File, rs *model.RuleSet, rep *stats.Report, opt, naive *compile.Program) {
	fmt.Printf("rule set: %s\n", rs.Name)
	var ranges, prefixes, masks int
	bound := map[string]bool{}
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			switch m.Kind {
			case model.KindRange:
				ranges++
			case model.KindPrefix:
				prefixes++
			case model.KindMask:
				masks++
			}
		}
		for _, b := range r.Bindings {
			bound[b] = true
		}
	}
	fmt.Printf("  %d rules, %d attachment point(s), %d range / %d prefix / %d mask constraints\n",
		len(rs.Rules), len(bound), ranges, prefixes, masks)
	fmt.Printf("  capacity %d entries per direction\n\n", rep.Capacity)

	fmt.Printf("%-28s %7s %7s %9s %7s %9s\n", "ACL", "ports", "rules", "naive", "opt", "ratio")
	for _, p := range rep.Plans {
		fmt.Printf("%-28s %7d %7d %9d %7d %8.2fx\n",
			truncate(p.Name, 28), p.Bindings, p.Rules, p.NaiveEntries, p.CompiledEnt, p.Compression())
	}
	fmt.Printf("\ntotal: naive %d entries, optimized %d entries, ratio %.2fx\n",
		rep.NaiveTotal, rep.Optimized, float64(rep.NaiveTotal)/float64(maxInt(rep.Optimized, 1)))
	if rep.EncoderCost > 0 {
		fmt.Printf("value->label encoder: %d rows (shared by all ACLs)\n", rep.EncoderCost)
	}
	if rep.SharedSaving > 0 {
		fmt.Printf("table sharing: %d entries saved by storing shared ACLs once\n", rep.SharedSaving)
	}
	if rep.Fits {
		fmt.Printf("fits: yes, %d/%d entries used, %d free\n", rep.Optimized, rep.Capacity, rep.Capacity-rep.Optimized)
	} else {
		fmt.Printf("FITS: NO -- short by %d entries (%d needed, %d available)\n", rep.Shortfall, rep.Optimized, rep.Capacity)
	}

	fmt.Printf("\nmost expensive rules:\n")
	fmt.Printf("  %-10s %7s %7s  %s\n", "rule", "entries", "naive", "comment")
	limit := len(rep.WorstRules)
	if limit > 10 {
		limit = 10
	}
	for _, rc := range rep.WorstRules[:limit] {
		fmt.Printf("  %-10s %7d %7d  %s\n", rc.RuleID, rc.Entries, rc.Naive, truncate(rc.Comment, 44))
	}

	if len(rep.Suggestions) > 0 {
		fmt.Printf("\ncheaper equivalent spellings:\n")
		for _, s := range rep.Suggestions {
			fmt.Printf("  [%s] %s: %s\n", s.Kind, s.RuleID, s.Message)
			if s.Rewrite != "" {
				fmt.Printf("      -> %s\n", s.Rewrite)
			}
		}
	}

	// Show the largest plan's entries for the reader who wants to see the
	// encoding itself.
	if len(opt.ACLs) > 0 {
		p := opt.ACLs[0]
		fmt.Printf("\nfirst ACL %s: %d entries, %d-bit key in %d words\n",
			p.Name, len(p.Entries), p.Layout.Width, wordCount(p))
		for _, fi := range p.Fields {
			if fi.Labels != nil {
				fmt.Printf("  field %-8s labelled: %d intervals, %d bits (raw %d)\n",
					fi.Field, len(fi.Labels.Cuts())-1, fi.PackWidth, fi.RawWidth)
			}
		}
		show := len(p.Entries)
		if show > 12 {
			show = 12
		}
		fmt.Printf("  %-4s %-6s %s\n", "row", "action", "key / mask")
		for i := 0; i < show; i++ {
			e := p.Entries[i]
			fmt.Printf("  %-4d %-6d %s\n", i, e.Action, describeEntry(p, e))
		}
		if len(p.Entries) > show {
			fmt.Printf("  ... %d more rows\n", len(p.Entries)-show)
		}
	}
}

func describeEntry(p *compile.Plan, e compile.Entry) string {
	var parts []string
	for _, fi := range p.Fields {
		v := p.Layout.GetField(e.K, fi.Field)
		m := p.Layout.GetField(e.M, fi.Field)
		if m == 0 {
			continue
		}
		full := fi.PackWidth
		mask := e.M
		_ = mask
		if fi.Labels != nil {
			parts = append(parts, fmt.Sprintf("%s=label%d/%d", fi.Field, v, m))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%#x/%#x", fi.Field, v, m&(1<<full-1)))
		}
	}
	return strings.Join(parts, " ")
}

func wordCount(p *compile.Plan) int {
	n := 0
	for _, e := range p.Entries {
		if e.Words > n {
			n = e.Words
		}
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = sort.Strings
