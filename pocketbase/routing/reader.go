package routing

import (
	"myapp/data"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type EvidenceQuery struct {
	Session       string
	From, To      time.Time
	Limit, Offset int
}
type EvidencePage struct {
	Records []*core.Record
	More    bool
}

// QueryEvidence includes one pre-window path per exact binding/epoch and all
// applicable invalidations. Publication time controls visibility, not read time.
func QueryEvidence(app core.App, q EvidenceQuery) (EvidencePage, error) {
	if q.Offset < 0 {
		return EvidencePage{Records: []*core.Record{}}, nil
	}
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	records := []*core.Record{}
	filter := `session={:s} AND available_ms < {:to} AND (
 kind='network_invalidated' OR available_ms >= {:from} OR NOT EXISTS (
 SELECT 1 FROM route_evidence newer WHERE newer.session=route_evidence.session
 AND newer.kind='path' AND newer.network_epoch=route_evidence.network_epoch
 AND newer.binding_key=route_evidence.binding_key AND newer.available_ms < {:from}
 AND (newer.available_ms>route_evidence.available_ms OR (newer.available_ms=route_evidence.available_ms AND newer.id>route_evidence.id))))`
	err := app.RecordQuery("route_evidence").AndWhere(dbx.NewExp(filter, dbx.Params{"s": q.Session, "from": q.From.UnixMilli(), "to": q.To.UnixMilli()})).OrderBy("available_ms", "id").Limit(int64(limit + 1)).Offset(int64(q.Offset)).All(&records)
	if err != nil {
		return EvidencePage{}, err
	}
	more := len(records) > limit
	if more {
		records = records[:limit]
	}
	return EvidencePage{Records: records, More: more}, nil
}

// EvidenceAt never resurrects an older path when the newest known publication
// expires or is invalidated. The supplied records may arrive in any order.
func EvidenceAt(records []data.RouteEvidence, epoch, binding string, cursorMS int64) *data.RouteEvidence {
	var chosen *data.RouteEvidence
	invalidated := int64(0)
	for i := range records {
		e := &records[i]
		if e.NetworkEpoch != epoch || e.AvailableMS > cursorMS {
			continue
		}
		if e.Kind == "network_invalidated" {
			invalidated = max(invalidated, e.AvailableMS)
			continue
		}
		if e.Kind != "path" || e.BindingKey != binding {
			continue
		}
		if chosen == nil || e.AvailableMS > chosen.AvailableMS || (e.AvailableMS == chosen.AvailableMS && e.ID > chosen.ID) {
			chosen = e
		}
	}
	if chosen == nil || cursorMS >= chosen.ValidUntilMS || invalidated >= chosen.AvailableMS {
		return nil
	}
	return chosen
}
