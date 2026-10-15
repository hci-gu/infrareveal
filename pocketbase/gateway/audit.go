package gateway

import (
	"database/sql"
	"errors"

	"github.com/pocketbase/pocketbase/core"
)

// Called once before the controller starts. Old queued records cannot describe
// a live held packet after process restart; their actual verdict is unknown.
func recoverInterruptedAudit(app core.App) error {
	if _, err := app.FindCollectionByNameOrId("gate_events"); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return app.RunInTransaction(func(tx core.App) error {
		if _, err := tx.DB().NewQuery(`UPDATE sessions SET gate_audit_complete=false,
   gate_audit_drops=gate_audit_drops+(SELECT COUNT(*) FROM gate_events g WHERE g.session=sessions.id AND g.state='queued'), revision=revision+1
   WHERE EXISTS (SELECT 1 FROM gate_events g WHERE g.session=sessions.id AND g.state='queued')`).Execute(); err != nil {
			return err
		}
		_, err := tx.DB().NewQuery("UPDATE gate_events SET state='interrupted', verdict_source='system', reason='Gateway restarted before a terminal verdict was recorded' WHERE state='queued'").Execute()
		return err
	})
}
