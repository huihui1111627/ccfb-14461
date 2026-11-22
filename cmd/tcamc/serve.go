package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"tcamc/internal/compile"
	"tcamc/internal/model"
	"tcamc/internal/stats"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	mustFlag(fs)
	addr := fs.String("addr", ":8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/compile", handleCompile)
	fmt.Printf("tcamc web UI on http://localhost%s\n", *addr)
	return http.ListenAndServe(*addr, mux)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

type compileRequest struct {
	Ruleset  string `json:"ruleset"`
	Capacity int    `json:"capacity"`
}

// compileResponse is what the page renders.
type compileResponse struct {
	Error  string      `json:"error,omitempty"`
	Report *jsonReport `json:"report,omitempty"`
	ACLs   []aclView   `json:"acls,omitempty"`
}

type aclView struct {
	Name     string      `json:"name"`
	Bindings []string    `json:"bindings"`
	Entries  []entryRow  `json:"entries"`
	Width    uint        `json:"width"`
	Words    int         `json:"words"`
	Fields   []fieldView `json:"fields"`
}

type entryRow struct {
	Row    int    `json:"row"`
	Action string `json:"action"`
	Key    string `json:"key"`
	Mask   string `json:"mask"`
	Rule   string `json:"rule"`
}

type fieldView struct {
	Field     string `json:"field"`
	Offset    uint   `json:"offset"`
	PackWidth uint   `json:"pack_width"`
	RawWidth  uint   `json:"raw_width"`
	Labelled  bool   `json:"labelled"`
	Intervals int    `json:"intervals"`
}

func handleCompile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req compileRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(compileResponse{Error: err.Error()})
		return
	}
	resp := CompileText(req.Ruleset, req.Capacity)
	json.NewEncoder(w).Encode(resp)
}

// CompileText is the page's compile entry point, also used by tests.
func CompileText(text string, capacity int) compileResponse {
	rs, err := ParseRuleSet(text)
	if err != nil {
		return compileResponse{Error: err.Error()}
	}
	if err := rs.Validate(); err != nil {
		return compileResponse{Error: err.Error()}
	}
	rep, err := stats.Analyze(rs, capacity)
	if err != nil {
		return compileResponse{Error: err.Error()}
	}
	opt, err := compile.Build([]*model.RuleSet{rs}, compile.Optimized())
	if err != nil {
		return compileResponse{Error: err.Error()}
	}
	resp := compileResponse{Report: ptrReport(buildJSON(rs, rep))}
	for _, p := range opt.ACLs {
		if len(resp.ACLs) >= 4 {
			break
		}
		v := aclView{Name: p.Name, Width: p.Layout.Width}
		for _, e := range p.Entries {
			if e.Words > v.Words {
				v.Words = e.Words
			}
		}
		for _, b := range p.Bindings {
			v.Bindings = append(v.Bindings, b.Port+":"+b.Dir)
		}
		for _, fi := range p.Fields {
			fv := fieldView{Field: fi.Field, Offset: fi.Offset, PackWidth: fi.PackWidth, RawWidth: fi.RawWidth}
			if fi.Labels != nil {
				fv.Labelled = true
				fv.Intervals = len(fi.Labels.Cuts()) - 1
			}
			v.Fields = append(v.Fields, fv)
		}
		for i, e := range p.Entries {
			if i >= 400 {
				break
			}
			rule := ""
			if len(e.Parts) > 0 {
				rule = e.Parts[0].Rule
			}
			v.Entries = append(v.Entries, entryRow{
				Row: i, Action: actionName(p, e.Action), Key: e.K.String(), Mask: e.M.String(), Rule: rule,
			})
		}
		resp.ACLs = append(resp.ACLs, v)
	}
	return resp
}

func actionName(p *compile.Plan, id uint8) string {
	if a, ok := p.Actions[id]; ok {
		return a.Name
	}
	return fmt.Sprintf("action %d", id)
}

func ptrReport(j jsonReport) *jsonReport { return &j }

// runDemo writes a self-contained HTML page with an embedded example rule set.
func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	mustFlag(fs)
	out := fs.String("out", "tcamc-demo.html", "output path")
	logo := fs.Bool("example", true, "embed the example rule set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ex := exampleRuleset
	if !*logo {
		ex = ""
	}
	page := strings.ReplaceAll(indexHTML, "__EXAMPLE__", jsString(ex))
	if err := os.WriteFile(*out, []byte(page), 0o644); err != nil {
		return err
	}
	fmt.Printf("demo page written to %s\n", *out)
	return nil
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// exampleRuleset is the "paste a rule set" sample.
const exampleRuleset = `# Industrial park edge switch, uplink direction.
# Ranges are deliberately unaligned: this is what overflows a 2000-entry TCAM
# when every range is expanded to plain prefixes.
ruleset park-edge

action 1 permit
action 2 deny
action 3 log

bind ge1:in ge2:in ge3:in ge4:in

rule deny-guest-servers deny
  vlan 30/0xfff
  dst_ip 10.30.0.0/16
  comment guest VLAN cannot reach the server farm

rule deny-guest-workshop deny
  vlan 30/0xfff
  dst_ip 10.40.0.0/16
  comment guest VLAN cannot reach PLC networks

rule guest-web permit
  vlan 30/0xfff
  dst_port 80-80
  comment guest HTTP

rule guest-https permit
  vlan 30/0xfff
  dst_port 443-443
  comment guest HTTPS

rule guest-dns permit
  vlan 30/0xfff
  dst_port 53-68
  comment guest DNS and DHCP

rule guest-ssh-block deny
  vlan 30/0xfff
  dst_port 22-22
  comment no guest SSH

rule plc-scada permit
  src_ip 10.40.1.0/24
  dst_port 4840-4850
  comment line controller to PLC

rule plc-modbus permit
  src_ip 10.40.2.0/24
  dst_port 502-520
  comment modbus

rule plc-eip permit
  src_ip 10.40.3.0/24
  dst_port 44818-44820
  comment EtherNet/IP

rule scada-src permit
  src_ip 10.42.0.0/22
  src_port 40000-40020
  dst_port 4840-4840
  comment SCADA master ephemeral range

rule app-db permit
  dst_ip 10.30.9.0/24
  dst_port 1433-1434
  comment SQL server

rule app-db-pg permit
  dst_ip 10.30.9.0/24
  dst_port 5432-5433
  comment PostgreSQL

rule block-telnet deny
  dst_ip 10.30.0.0/16
  dst_port 23-23
  comment no telnet to servers

rule established permit
  est 1
  comment return traffic

rule workshop-default deny
  src_ip 10.40.0.0/16
  comment workshop default deny
`
