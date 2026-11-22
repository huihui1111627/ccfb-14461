package main

import (
	"fmt"

	"tcamc/internal/chip"
	"tcamc/internal/model"
	"tcamc/internal/ref"
)

// transition records, per packet, the only two verdicts acceptable during one
// online update: the verdict before and the verdict after. This is the
// no-wrong-match invariant for a table edited one row at a time.
type transition struct {
	pkts   []model.Key
	oldAct []uint8
	newAct []uint8
}

func newTransition(binding string, oldRules, newRules []*model.Rule, pkts []model.Key) *transition {
	tr := &transition{pkts: pkts, oldAct: make([]uint8, len(pkts)), newAct: make([]uint8, len(pkts))}
	for i, pk := range pkts {
		tr.oldAct[i] = ref.ActionIDOn(oldRules, binding, pk)
		tr.newAct[i] = ref.ActionIDOn(newRules, binding, pk)
	}
	return tr
}

func (tr *transition) check(c *chip.Chip) error {
	for i, pk := range tr.pkts {
		got := c.LookupPacket(pk, chip.ModeLabels).ID
		if got != tr.oldAct[i] && got != tr.newAct[i] {
			return fmt.Errorf("packet %d verdict %d is neither old %d nor new %d", i, got, tr.oldAct[i], tr.newAct[i])
		}
	}
	return nil
}
