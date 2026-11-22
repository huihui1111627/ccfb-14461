package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"tcamc/internal/model"
)

// ParseRuleSet reads the small text rule format used by tcamc and by the web
// page. Example:
//
//	ruleset campus
//	action 1 permit
//	action 2 deny
//
//	bind ge1:in ge2:in
//	rule r1 permit
//	  src_ip 10.20.0.0/16
//	  dst_port 3389-3400
//	  proto 6/0xff
//	  comment admin RDP range
//
// Matching. A line `field value` adds a constraint:
//
//	10.0.0.0/8       IPv4 prefix
//	10.0.0.1         IPv4 exact
//	8000-8100        inclusive range
//	443              exact value
//	6/0xff           (value & mask) == value, for mask fields
//
// `bind` sets the attachment points for the following rules and may appear more
// than once. `action` may be given before or after the rules that use it.
func ParseRuleSet(text string) (*model.RuleSet, error) {
	rs := &model.RuleSet{}
	actions := map[string]model.Action{
		"permit": {ID: 1, Name: "permit", Permit: true},
		"deny":   {ID: 2, Name: "deny", Permit: false},
		"log":    {ID: 3, Name: "permit+log", Permit: true},
	}
	actionIDs := map[string]uint8{"permit": 1, "deny": 2, "log": 3}
	var bindings []string
	var cur *model.Rule
	line := 0

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line++
		raw := sc.Text()
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}
		f := strings.Fields(s)
		switch f[0] {
		case "ruleset":
			if len(f) < 2 {
				return nil, fmt.Errorf("line %d: ruleset needs a name", line)
			}
			rs.Name = f[1]
		case "action":
			if len(f) < 3 {
				return nil, fmt.Errorf("line %d: action needs an id and a name", line)
			}
			id64, err := strconv.ParseUint(f[1], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad action id %q", line, f[1])
			}
			a := model.Action{ID: uint8(id64), Name: f[2], Permit: f[2] != "deny"}
			actions[f[2]] = a
			actionIDs[f[2]] = a.ID
		case "bind":
			if len(f) < 2 {
				return nil, fmt.Errorf("line %d: bind needs at least one port:dir", line)
			}
			bindings = append([]string(nil), f[1:]...)
			for _, b := range bindings {
				if !strings.Contains(b, ":") {
					return nil, fmt.Errorf("line %d: binding %q must be port:direction", line, b)
				}
			}
		case "rule":
			if len(f) < 3 {
				return nil, fmt.Errorf("line %d: rule needs an id and an action", line)
			}
			a, ok := actions[f[2]]
			if !ok {
				return nil, fmt.Errorf("line %d: unknown action %q", line, f[2])
			}
			cur = &model.Rule{ID: f[1], Action: a, Bindings: append([]string(nil), bindings...)}
			if len(cur.Bindings) == 0 {
				return nil, fmt.Errorf("line %d: no bind before rule %q", line, f[1])
			}
			rs.Rules = append(rs.Rules, cur)
		case "comment":
			if cur != nil {
				cur.Comment = strings.TrimSpace(strings.TrimPrefix(s, f[0]))
			}
		default:
			if cur == nil {
				return nil, fmt.Errorf("line %d: %q outside a rule", line, f[0])
			}
			m, err := parseMatch(f[0], f[1:], line)
			if err != nil {
				return nil, err
			}
			cur.Matches = append(cur.Matches, m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if rs.Name == "" {
		rs.Name = "unnamed"
	}
	if len(rs.Rules) == 0 {
		return nil, fmt.Errorf("no rules found")
	}
	// Re-point actions at the table so later `action` lines apply too.
	for _, r := range rs.Rules {
		if a, ok := actions[r.Action.Name]; ok {
			r.Action = a
		}
		_ = actionIDs
	}
	return rs, nil
}

func parseMatch(field string, args []string, line int) (model.Match, error) {
	meta, ok := model.Meta[field]
	if !ok {
		return model.Match{}, fmt.Errorf("line %d: unknown field %q", line, field)
	}
	if len(args) != 1 {
		return model.Match{}, fmt.Errorf("line %d: %s needs exactly one value", line, field)
	}
	v := args[0]
	m := model.Match{Field: field}
	switch meta.Kind {
	case model.KindPrefix:
		if strings.Contains(v, "/") {
			parts := strings.SplitN(v, "/", 2)
			addr, err := parseIPv4(parts[0])
			if err != nil {
				return m, fmt.Errorf("line %d: %v", line, err)
			}
			plen, err := strconv.ParseUint(parts[1], 10, 8)
			if err != nil || plen > 32 {
				return m, fmt.Errorf("line %d: bad prefix length %q", line, parts[1])
			}
			m.Kind = model.KindPrefix
			m.Value = uint64(addr)
			m.Plen = uint8(plen)
			return m, nil
		}
		addr, err := parseIPv4(v)
		if err != nil {
			return m, fmt.Errorf("line %d: %v", line, err)
		}
		m.Kind = model.KindPrefix
		m.Value = uint64(addr)
		m.Plen = 32
		return m, nil
	case model.KindRange:
		if strings.Contains(v, "-") {
			parts := strings.SplitN(v, "-", 2)
			lo, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 64)
			hi, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 64)
			if err1 != nil || err2 != nil {
				return m, fmt.Errorf("line %d: bad range %q", line, v)
			}
			m.Kind = model.KindRange
			m.Lo, m.Hi = lo, hi
			return m, nil
		}
		n, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			return m, fmt.Errorf("line %d: bad value %q", line, v)
		}
		m.Kind = model.KindRange
		m.Lo, m.Hi = n, n
		return m, nil
	case model.KindMask:
		if strings.Contains(v, "/") {
			parts := strings.SplitN(v, "/", 2)
			val, err1 := strconv.ParseUint(parts[0], 0, 64)
			mask, err2 := strconv.ParseUint(parts[1], 0, 64)
			if err1 != nil || err2 != nil {
				return m, fmt.Errorf("line %d: bad value/mask %q", line, v)
			}
			m.Kind = model.KindMask
			m.Value, m.Mask = val, mask
			return m, nil
		}
		n, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			return m, fmt.Errorf("line %d: bad value %q", line, v)
		}
		m.Kind = model.KindMask
		m.Value, m.Mask = n, meta.Max()
		return m, nil
	case model.KindExact:
		n, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			return m, fmt.Errorf("line %d: bad value %q", line, v)
		}
		m.Kind = model.KindExact
		m.Value = n
		return m, nil
	}
	return m, fmt.Errorf("line %d: field %q cannot be parsed", line, field)
}

func parseIPv4(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("bad IPv4 address %q", s)
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("bad IPv4 address %q", s)
		}
		v = v<<8 | uint32(n)
	}
	return v, nil
}
