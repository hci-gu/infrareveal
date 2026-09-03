package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		if sessions.Fields.GetByName("gate_audit_complete") == nil {
			sessions.Fields.Add(&core.BoolField{Name: "gate_audit_complete"})
		}
		if sessions.Fields.GetByName("gate_audit_drops") == nil {
			sessions.Fields.Add(&core.NumberField{Name: "gate_audit_drops", OnlyInt: true})
		}
		if err := txApp.Save(sessions); err != nil {
			return err
		}
		records, err := txApp.FindAllRecords(sessions)
		if err != nil {
			return err
		}
		for _, record := range records {
			record.Set("gate_audit_complete", true)
			record.Set("gate_audit_drops", 0)
			if err := txApp.Save(record); err != nil {
				return err
			}
		}
		return nil
	}, func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err != nil {
			return nil
		}
		sessions.Fields.RemoveByName("gate_audit_complete")
		sessions.Fields.RemoveByName("gate_audit_drops")
		return txApp.Save(sessions)
	})
}
