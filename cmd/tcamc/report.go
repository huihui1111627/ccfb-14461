package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"tcamc/internal/model"
	"tcamc/internal/stats"
)

type jsonSuggestion struct {
	RuleID  string `json:"rule_id"`
	Kind    string `json:"kind"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
	Message string `json:"message"`
	Rewrite string `json:"rewrite,omitempty"`
}

type jsonPlan struct {
	Name          string   `json:"name"`
	Bindings      int      `json:"bindings"`
	Rules         int      `json:"rules"`
	NaiveEntries  int      `json:"naive_entries"`
	OptimizedEnt  int      `json:"optimized_entries"`
	Ratio         string   `json:"ratio"`
	LabelledField []string `json:"labelled_fields,omitempty"`
}

type jsonRuleCost struct {
	RuleID  string `json:"rule_id"`
	Entries int    `json:"entries"`
	Naive   int    `json:"naive_entries"`
	Comment string `json:"comment,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type jsonReport struct {
	RuleSet     string           `json:"ruleset"`
	Capacity    int              `json:"capacity"`
	Rules       int              `json:"rules"`
	NaiveTotal  int              `json:"naive_entries"`
	Optimized   int              `json:"optimized_entries"`
	Ratio       float64          `json:"ratio"`
	EncoderCost int              `json:"encoder_entries"`
	Fits        bool             `json:"fits"`
	Shortfall   int              `json:"shortfall"`
	Plans       []jsonPlan       `json:"plans"`
	WorstRules  []jsonRuleCost   `json:"worst_rules"`
	Suggestions []jsonSuggestion `json:"suggestions"`
}

func buildJSON(rs *model.RuleSet, rep *stats.Report) jsonReport {
	jr := jsonReport{
		RuleSet:     rs.Name,
		Capacity:    rep.Capacity,
		Rules:       len(rs.Rules),
		NaiveTotal:  rep.NaiveTotal,
		Optimized:   rep.Optimized,
		EncoderCost: rep.EncoderCost,
		Fits:        rep.Fits,
		Shortfall:   rep.Shortfall,
	}
	if rep.Optimized > 0 {
		jr.Ratio = float64(rep.NaiveTotal) / float64(rep.Optimized)
	}
	for _, p := range rep.Plans {
		jp := jsonPlan{
			Name:          p.Name,
			Bindings:      p.Bindings,
			Rules:         p.Rules,
			NaiveEntries:  p.NaiveEntries,
			OptimizedEnt:  p.CompiledEnt,
			Ratio:         fmt.Sprintf("%.2fx", p.Compression()),
			LabelledField: p.LabelsEnabled,
		}
		jr.Plans = append(jr.Plans, jp)
	}
	for _, rc := range rep.WorstRules {
		jr.WorstRules = append(jr.WorstRules, jsonRuleCost{
			RuleID: rc.RuleID, Entries: rc.Entries, Naive: rc.Naive,
			Comment: rc.Comment, Reason: rc.Reason,
		})
	}
	for _, s := range rep.Suggestions {
		jr.Suggestions = append(jr.Suggestions, jsonSuggestion{
			RuleID: s.RuleID, Kind: s.Kind, Before: s.Before, After: s.After,
			Message: s.Message, Rewrite: s.Rewrite,
		})
	}
	return jr
}

// WriteJSON writes the machine-readable report.
func WriteJSON(path string, rs *model.RuleSet, rep *stats.Report) error {
	jr := buildJSON(rs, rep)
	b, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

const htmlBody = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{.RuleSet}} - tcamc report</title>
<style>
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.5rem;margin-bottom:.2rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0}th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #eee}
th{background:#f7f7f7;font-weight:600;font-size:.85rem;color:#555}td.n{text-align:right;font-variant-numeric:tabular-nums}
.bad{color:#b00020;font-weight:600}.good{color:#0a7d32;font-weight:600}.muted{color:#777}
code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px;font-size:.9em}
</style></head><body>
<h1>{{.RuleSet}}</h1>
<p class="muted">{{.Rules}} rules, capacity {{.Capacity}} entries</p>
<table>
<tr><th>plain prefix expansion</th><th>optimised</th><th>compression</th><th>status</th></tr>
<tr><td class="n">{{.NaiveTotal}}</td><td class="n">{{.Optimized}}</td><td class="n">{{printf "%.2f" .Ratio}}x</td>
<td>{{if .Fits}}<span class="good">fits</span>{{else}}<span class="bad">short by {{.Shortfall}}</span>{{end}}</td></tr>
</table>
{{if .EncoderCost}}<p class="muted">value-to-label encoder: {{.EncoderCost}} rows, shared by all ACLs</p>{{end}}
<h2>ACLs</h2>
<table><tr><th>ACL</th><th class="n">ports</th><th class="n">rules</th><th class="n">plain</th><th class="n">optimised</th><th class="n">ratio</th><th>labelled fields</th></tr>
{{range .Plans}}<tr><td>{{.Name}}</td><td class="n">{{.Bindings}}</td><td class="n">{{.Rules}}</td><td class="n">{{.NaiveEntries}}</td><td class="n">{{.OptimizedEnt}}</td><td class="n">{{.Ratio}}</td><td class="muted">{{range .LabelledField}}{{.}} {{end}}</td></tr>{{end}}</table>
<h2>Most expensive rules</h2>
<table><tr><th>rule</th><th class="n">entries</th><th class="n">plain</th><th>why</th><th>comment</th></tr>
{{range .WorstRules}}<tr><td><code>{{.RuleID}}</code></td><td class="n">{{.Entries}}</td><td class="n">{{.Naive}}</td><td class="muted">{{.Reason}}</td><td>{{.Comment}}</td></tr>{{end}}</table>
{{if .Suggestions}}<h2>Cheaper equivalent spellings</h2>
<table><tr><th>rule</th><th>kind</th><th>finding</th><th>rewrite</th></tr>
{{range .Suggestions}}<tr><td><code>{{.RuleID}}</code></td><td>{{.Kind}}</td><td>{{.Message}}</td><td class="muted">{{.Rewrite}}</td></tr>{{end}}</table>{{end}}
<p class="muted">generated by tcamc</p>
</body></html>`

// RenderHTML renders the standalone report page.
func RenderHTML(rs *model.RuleSet, rep *stats.Report) (string, error) {
	t, err := template.New("report").Parse(htmlBody)
	if err != nil {
		return "", err
	}
	var b stringWriter
	if err := t.Execute(&b, buildJSON(rs, rep)); err != nil {
		return "", err
	}
	return b.String(), nil
}

type stringWriter struct{ s []byte }

func (w *stringWriter) Write(p []byte) (int, error) {
	w.s = append(w.s, p...)
	return len(p), nil
}
func (w *stringWriter) String() string { return string(w.s) }

// RenderBenchHTML renders a standalone benchmark report.
func RenderBenchHTML(res *BenchResult) (string, error) {
	t, err := template.New("bench").Funcs(template.FuncMap{"f1": func(f float64) string { return fmt.Sprintf("%.1f", f) }, "f2": func(f float64) string { return fmt.Sprintf("%.2f", f) }}).Parse(benchHTML)
	if err != nil {
		return "", err
	}
	var b stringWriter
	if err := t.Execute(&b, res); err != nil {
		return "", err
	}
	return b.String(), nil
}

const benchHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>tcamc benchmark</title>
<style>
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:2rem auto;max-width:64rem;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0}th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #eee}
th{background:#f7f7f7;font-size:.85rem;color:#555}td.n{text-align:right;font-variant-numeric:tabular-nums}
.good{color:#0a7d32;font-weight:600}.bad{color:#b00020;font-weight:600}.muted{color:#777}
</style></head><body>
<h1>tcamc benchmark</h1>
<p class="muted">seed {{.Seed}}, capacity {{.Capacity}} entries per direction, {{.VerifyCount}} packets per rule set</p>
<table><tr><th>rule set</th><th class="n">rules</th><th class="n">ports</th><th class="n">range constraints</th><th class="n">plain</th><th class="n">optimised</th><th class="n">ratio</th><th>fits</th><th class="n">insert writes</th><th class="n">insert moved</th></tr>
{{range .RuleSets}}<tr><td>{{.Name}}</td><td class="n">{{.Rules}}</td><td class="n">{{.Bindings}}</td><td class="n">{{.RangeCons}}</td><td class="n">{{.Naive}}</td><td class="n">{{.Optimized}}</td><td class="n">{{f2 .Ratio}}x</td><td>{{if .Fits}}<span class="good">yes</span>{{else}}<span class="bad">short {{.Shortfall}}</span>{{end}}</td><td class="n">{{f1 .InsertWrites}}</td><td class="n">{{f1 .InsertMoved}}</td></tr>{{end}}
<tr><th>TOTAL</th><th></th><th></th><th></th><th class="n">{{.Totals.Naive}}</th><th class="n">{{.Totals.Optimized}}</th><th class="n">{{f2 .Totals.Ratio}}x</th><th></th><th></th><th></th></tr></table>
<h2>Online updates</h2>
<table><tr><th>rule set</th><th class="n">insert trials</th><th class="n">avg writes per insert</th><th class="n">avg rows moved</th><th class="n">delete trials</th><th class="n">avg writes per delete</th></tr>
{{range .RuleSets}}<tr><td>{{.Name}}</td><td class="n">{{.Inserts}}</td><td class="n">{{f1 .InsertWrites}}</td><td class="n">{{f1 .InsertMoved}}</td><td class="n">{{.Deletes}}</td><td class="n">{{f1 .DeleteWrites}}</td></tr>{{end}}</table>
<h2>Table sharing</h2>
<table><tr><th>rule set</th><th class="n">per-port copies, plain</th><th class="n">per-port copies, optimised</th><th class="n">shared, optimised</th></tr>
{{range .RuleSets}}<tr><td>{{.Name}}</td><td class="n">{{.PerPortNaive}}</td><td class="n">{{.PerPortOptimized}}</td><td class="n">{{.Optimized}}</td></tr>{{end}}</table>
<h2>Differential check</h2>
<p>{{range .RuleSets}}{{.Name}}: {{if .Verified}}<span class="good">verified {{.VerifyPackets}} packets</span>{{else}}<span class="bad">FAILED {{.VerifyNote}}</span>{{end}}<br>{{end}}</p>
</body></html>`
