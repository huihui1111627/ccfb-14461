// Package ref is the reference implementation the compiled tables are checked
// against. It is the obvious, slow, obviously-correct evaluator: walk the rules
// in order and evaluate every match directly on the packet. It shares no code
// with the compiler beyond the rule types themselves.
package ref

import "tcamc/internal/model"

// Decide returns the first rule matching the packet, or nil for the default
// permit. It is the ground truth for differential testing.
func Decide(rules []*model.Rule, p model.Key) *model.Rule {
	return model.Decide(rules, p)
}

// DecideOn is the ground truth for one attachment point: the first rule that is
// bound to the point and matches the packet. Rules bound to other ports or
// directions are not installed there and cannot match.
func DecideOn(rules []*model.Rule, binding string, p model.Key) *model.Rule {
	for _, r := range rules {
		if !boundTo(r, binding) {
			continue
		}
		if r.MatchRule(p) {
			return r
		}
	}
	return nil
}

func boundTo(r *model.Rule, binding string) bool {
	for _, b := range r.Bindings {
		if b == binding {
			return true
		}
	}
	return false
}

// ActionIDs maps rule sets to the action of the first matching rule, using the
// same "no match means default permit with id 0" convention as the chip.
func ActionID(rules []*model.Rule, p model.Key) uint8 {
	if r := Decide(rules, p); r != nil {
		return r.Action.ID
	}
	return 0
}

// ActionIDOn is ActionIDs scoped to one attachment point.
func ActionIDOn(rules []*model.Rule, binding string, p model.Key) uint8 {
	if r := DecideOn(rules, binding, p); r != nil {
		return r.Action.ID
	}
	return 0
}
