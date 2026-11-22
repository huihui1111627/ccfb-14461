package compile

import (
	"errors"
	"fmt"

	"tcamc/internal/cover"
	"tcamc/internal/encode"
	"tcamc/internal/key"
	"tcamc/internal/model"
)

// ErrIncompatibleCuts is returned when a rule cannot be added to an existing
// plan because it uses a field value that the plan's label map did not cut at.
//
// Why this exists: raw-encoded plans are context free -- a rule's entries
// depend only on the rule -- so any rule can be inserted online. Label-encoded
// plans are not: a range is compact only because the plan already cut the field
// at that range's boundaries. A new boundary would relabel every value above
// it and therefore change entries of unrelated rules, which is exactly the
// full reload the online updater must avoid. The updater reports this instead
// of silently doing the reload; the caller can either add the rule in raw form
// or schedule a maintenance-window recompile.
var ErrIncompatibleCuts = errors.New("rule introduces a range boundary the plan's label map does not have")

// CompileRule compiles one rule into table entries using the plan's frozen
// layout. It is what the online updater calls for every insert.
func CompileRule(p *Plan, r *model.Rule) ([]Entry, error) {
	if r == nil {
		return nil, errors.New("nil rule")
	}
	if err := (&model.RuleSet{Name: p.Name, Rules: []*model.Rule{r}}).Validate(); err != nil {
		return nil, err
	}
	labels := map[string]*encode.IntervalMap{}
	for _, fi := range p.Fields {
		if fi.Labels != nil {
			labels[fi.Field] = fi.Labels
		}
	}
	cs, err := expandRule(r, p.Layout, labels, Options{MinMask: p.Stats.MinMask})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(cs))
	for _, c := range cs {
		e := Entry{K: c.K, M: c.M, Action: r.Action.ID, Parts: []Part{{K: c.K, M: c.M, Prio: c.Prio, Rule: r.ID, Label: c.Label}}}
		e.Words = constrainedWords(c.K, c.M)
		out = append(out, e)
	}
	return out, nil
}

// CheckInsertable reports whether rule r can be compiled against this plan
// without changing any other rule's entries.
func (p *Plan) CheckInsertable(r *model.Rule) error {
	if r == nil {
		return errors.New("nil rule")
	}
	if err := (&model.RuleSet{Name: p.Name, Rules: []*model.Rule{r}}).Validate(); err != nil {
		return err
	}
	for _, m := range r.Matches {
		var lm *encode.IntervalMap
		for _, fi := range p.Fields {
			if fi.Field == m.Field {
				lm = fi.Labels
				break
			}
		}
		if lm == nil {
			continue
		}
		switch m.Kind {
		case model.KindRange:
			if !lm.HasCut(m.Lo) || !lm.HasCut(m.Hi+1) {
				return fmt.Errorf("%w: %s [%d,%d]", ErrIncompatibleCuts, m.Field, m.Lo, m.Hi)
			}
		case model.KindExact:
			if !lm.HasCut(m.Value) || !lm.HasCut(m.Value+1) {
				return fmt.Errorf("%w: %s exact %d", ErrIncompatibleCuts, m.Field, m.Value)
			}
		case model.KindPrefix, model.KindMask:
			return fmt.Errorf("%w: %s uses %v matching, which label encoding cannot express",
				ErrIncompatibleCuts, m.Field, m.Kind)
		}
	}
	return nil
}

// RawCube returns the ternary key constraint for a single-field match, for
// callers that want to inspect or display the encoding.
func RawCube(layout key.Layout, m model.Match) (key.Key, key.Key, error) {
	meta := model.Meta[m.Field]
	switch m.Kind {
	case model.KindExact:
		k, mm := layout.FieldCube(m.Field, m.Value, cover.FullMask(meta.Width))
		return k, mm, nil
	case model.KindMask:
		k, mm := layout.FieldCube(m.Field, m.Value, m.Mask)
		return k, mm, nil
	case model.KindPrefix:
		mask := cover.FullMask(uint(m.Plen))
		if meta.Width > uint(m.Plen) {
			mask <<= meta.Width - uint(m.Plen)
		}
		k, mm := layout.FieldCube(m.Field, m.Value&mask, mask)
		return k, mm, nil
	case model.KindRange:
		return key.Key{}, key.Key{}, errors.New("range expands to several cubes")
	}
	return key.Key{}, key.Key{}, fmt.Errorf("unsupported match kind")
}
