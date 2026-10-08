package observer

import (
	"errors"
	"myapp/testsupport"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func TestCatalogueCorrectionTransferRollsBackWithCheckpoint(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	now := time.Now().UTC()
	flow := testsupport.Save(t, app, "flows", map[string]any{"session": session.Id, "flow_key": "catalogue", "protocol": "tcp", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "start": now, "last_seen": now})
	attribution := testsupport.Save(t, app, "flow_attributions", map[string]any{"session": session.Id, "flow": flow.Id, "candidate_hostname": "api.example.com", "confidence": "medium", "source_signal": "dns_answer", "observed_at": now})
	if err := CollectDomainCatalogue(app, session.Id); err != nil {
		t.Fatal(err)
	}
	previous, err := app.FindFirstRecordByFilter("domain_catalogue", "domain='example.com'")
	if err != nil {
		t.Fatal(err)
	}
	previous.Set("review_status", "approved")
	previous.Set("notes", "keep this manual review")
	if err := app.Save(previous); err != nil {
		t.Fatal(err)
	}
	checkpoint := func() string {
		t.Helper()
		var row struct {
			Revision string `db:"revision"`
		}
		if err := app.DB().NewQuery("SELECT revision FROM _domain_catalogue_checkpoints WHERE source='flow_attributions' AND source_id={:id}").Bind(dbx.Params{"id": attribution.Id}).One(&row); err != nil {
			t.Fatal(err)
		}
		return row.Revision
	}
	before := checkpoint()
	// The event timestamp does not change. Revision detection must use content.
	attribution.Set("candidate_hostname", "www.other.net")
	attribution.Set("confidence", "high")
	if err := app.Save(attribution); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("new aggregate save failed")
	fail := true
	app.OnRecordCreate("domain_catalogue").BindFunc(func(e *core.RecordEvent) error {
		if fail && e.Record.GetString("domain") == "other.net" {
			return failure
		}
		return e.Next()
	})
	if err := CollectDomainCatalogue(app, session.Id); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	previous, err = app.FindRecordById("domain_catalogue", previous.Id)
	if err != nil || previous.GetInt("medium_flow_count") != 1 || checkpoint() != before {
		t.Fatal("failed transfer changed its old contribution or checkpoint", err)
	}
	if _, err := app.FindFirstRecordByFilter("domain_catalogue", "domain='other.net'"); err == nil {
		t.Fatal("new aggregate escaped rollback")
	}
	fail = false
	for range 2 {
		if err := CollectDomainCatalogue(app, session.Id); err != nil {
			t.Fatal(err)
		}
	}
	previous, _ = app.FindRecordById("domain_catalogue", previous.Id)
	next, err := app.FindFirstRecordByFilter("domain_catalogue", "domain='other.net'")
	if err != nil || previous.GetInt("medium_flow_count") != 0 || next.GetInt("high_flow_count") != 1 || checkpoint() == before {
		t.Fatal("retry lost or duplicated transfer", err)
	}
	if previous.GetString("review_status") != "approved" || previous.GetString("notes") != "keep this manual review" {
		t.Fatal("aggregate maintenance erased manual review")
	}
	// A correction to unusable evidence removes only its previous contribution.
	attribution.Set("confidence", "hidden")
	if err := app.Save(attribution); err != nil {
		t.Fatal(err)
	}
	if err := CollectDomainCatalogue(app, session.Id); err != nil {
		t.Fatal(err)
	}
	next, _ = app.FindRecordById("domain_catalogue", next.Id)
	if next.GetInt("high_flow_count") != 0 {
		t.Fatal("hidden correction retained a flow contribution")
	}
}
