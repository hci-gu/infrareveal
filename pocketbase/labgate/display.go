package labgate

import (
	"context"
	"net/netip"
	"time"
)

// Runs on the controller owner. Remove displays from the kernel selection and
// release their old decisions without disturbing other selected participants.
func (controller *Controller) refreshExclusions(state *controllerState) error {
	changed := false
	for client := range state.clients {
		if controller.excluded(client) {
			delete(state.clients, client)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	for _, decision := range pendingSnapshotPointers(state) {
		client, _ := netip.ParseAddr(decision.ClientIP)
		if _, selected := state.clients[client.Unmap()]; !selected {
			controller.applyTerminal(state, decision, DecisionDrained, VerdictAccept, SourceSystem, "display", "device entered display mode", time.Now())
		}
	}
	clear(state.decisionCache)
	if len(state.clients) == 0 {
		return controller.disarm(state)
	}
	if controller.rules != nil {
		clients := make([]netip.Addr, 0, len(state.clients))
		for client := range state.clients {
			clients = append(clients, client)
		}
		ctx, cancel := context.WithTimeout(controller.ctx, 2*time.Second)
		defer cancel()
		if err := controller.rules.Activate(ctx, RuleSelection{Mode: state.mode, Clients: clients, Strict: state.strict}); err != nil {
			controller.degrade(state, err)
			return err
		}
	}
	return nil
}
