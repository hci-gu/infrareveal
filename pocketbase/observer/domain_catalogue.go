package observer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type catalogueState struct {
	Domain  string `json:"domain"`
	Counter string `json:"counter"`
}
type cnameExample struct {
	Query string `json:"query"`
	Alias string `json:"alias"`
}

type catalogueSource struct {
	collection string
	revision   string
}

// Source revisions track relevant content, not millisecond updated timestamps:
// multiple DNS replies or attribution corrections can share a timestamp.
var catalogueSources = []catalogueSource{
	{"dns_queries", "json_array(dns_queries.query_name,dns_queries.timestamp,dns_queries.aliases)"},
	{"flow_attributions", "json_array(flow_attributions.candidate_hostname,flow_attributions.confidence,flow_attributions.observed_at)"},
}

type catalogueContribution struct {
	state    catalogueState
	hostname string
	at       time.Time
	aliases  []string
}

// CollectDomainCatalogue checkpoints each source revision in the same transaction
// as its aggregate. Markers expire with raw observations; no permanent per-device
// or per-flow ledger is created. Changed attributions transfer their count.
func CollectDomainCatalogue(app core.App, session string) error {
	for _, source := range catalogueSources {
		for {
			count := 0
			err := app.RunInTransaction(func(tx core.App) error {
				rows, err := source.pending(tx, session)
				if err != nil {
					return err
				}
				count = len(rows)
				for _, raw := range rows {
					old, err := source.checkpoint(tx, raw.Id)
					if err != nil {
						return err
					}
					next := source.contribution(raw)
					if err := updateCatalogueContribution(tx, old, next); err != nil {
						return err
					}
					if err := source.saveCheckpoint(tx, raw.Id, next.state); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if count < 250 {
				break
			}
		}
	}
	return nil
}

func (source catalogueSource) pending(app core.App, session string) ([]*core.Record, error) {
	rows := []*core.Record{}
	err := app.RecordQuery(source.collection).
		AndWhere(dbx.NewExp("session={:s} AND NOT EXISTS (SELECT 1 FROM _domain_catalogue_checkpoints c WHERE c.source={:source} AND c.source_id="+source.collection+".id AND c.revision="+source.revision+")", dbx.Params{"s": session, "source": source.collection})).
		OrderBy("updated", "id").Limit(250).All(&rows)
	return rows, err
}

func (source catalogueSource) contribution(raw *core.Record) catalogueContribution {
	c := catalogueContribution{hostname: raw.GetString("query_name"), at: raw.GetDateTime("timestamp").Time(), aliases: raw.GetStringSlice("aliases")}
	counter := "dns_count"
	if source.collection == "flow_attributions" {
		c.hostname, c.at = raw.GetString("candidate_hostname"), raw.GetDateTime("observed_at").Time()
		c.aliases = nil
		switch raw.GetString("confidence") {
		case "high":
			counter = "high_flow_count"
		case "medium":
			counter = "medium_flow_count"
		case "low":
			counter = "low_flow_count"
		default:
			counter = ""
		}
	}
	c.hostname = normalizeActivityHostname(c.hostname)
	if domain := registeredActivityDomain(c.hostname); domain != "" && counter != "" {
		c.state = catalogueState{Domain: domain, Counter: counter}
	}
	return c
}

func (source catalogueSource) checkpoint(app core.App, id string) (catalogueState, error) {
	var row struct {
		State string `db:"state"`
	}
	err := app.DB().NewQuery("SELECT state FROM _domain_catalogue_checkpoints WHERE source={:source} AND source_id={:id}").
		Bind(dbx.Params{"source": source.collection, "id": id}).One(&row)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return catalogueState{}, err
	}
	old := catalogueState{}
	if row.State != "" {
		err = json.Unmarshal([]byte(row.State), &old)
		return old, err
	}
	return old, nil
}

func (source catalogueSource) saveCheckpoint(app core.App, id string, state catalogueState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// Separate bookkeeping cannot be overwritten by a writer holding an older
	// source Record. Do not advance source updated or emit a realtime event.
	_, err = app.DB().NewQuery("INSERT OR REPLACE INTO _domain_catalogue_checkpoints (source,source_id,revision,state) SELECT {:source},id," + source.revision + ",{:state} FROM " + source.collection + " WHERE id={:id}").
		Bind(dbx.Params{"source": source.collection, "state": string(encoded), "id": id}).Execute()
	return err
}

// A contribution change is a transfer, including domain changes, confidence
// changes, and corrections to unusable evidence. Metadata may still change when
// the contribution itself does not, so those updates are not skipped.
func updateCatalogueContribution(app core.App, old catalogueState, next catalogueContribution) error {
	if old != next.state && old.Domain != "" {
		previous, err := app.FindFirstRecordByFilter("domain_catalogue", "domain={:d}", dbx.Params{"d": old.Domain})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			previous.Set(old.Counter, max(0, previous.GetInt(old.Counter)-1))
			if err := app.Save(previous); err != nil {
				return err
			}
		}
	}
	if next.state.Domain == "" {
		return nil
	}
	record, err := app.FindFirstRecordByFilter("domain_catalogue", "domain={:d}", dbx.Params{"d": next.state.Domain})
	if errors.Is(err, sql.ErrNoRows) {
		collection, err := app.FindCollectionByNameOrId("domain_catalogue")
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("domain", next.state.Domain)
		record.Set("review_status", "pending")
	} else if err != nil {
		return err
	}
	if old != next.state {
		record.Set(next.state.Counter, record.GetInt(next.state.Counter)+1)
	}
	at := next.at
	if at.IsZero() {
		at = time.Now().UTC()
	}
	first, last := record.GetDateTime("first_seen").Time(), record.GetDateTime("last_seen").Time()
	if first.IsZero() || at.Before(first) {
		record.Set("first_seen", at)
	}
	if at.After(last) {
		record.Set("last_seen", at)
	}
	record.Set("hostnames", boundedExample(record.GetStringSlice("hostnames"), next.hostname, 16))
	if next.state.Counter == "dns_count" {
		examples := []cnameExample{}
		if err := record.UnmarshalJSONField("cname_examples", &examples); err != nil {
			return err
		}
		for _, alias := range next.aliases {
			alias = normalizeActivityHostname(alias)
			if registeredActivityDomain(alias) == "" || alias == next.hostname {
				continue
			}
			candidate, found := (cnameExample{Query: next.hostname, Alias: alias}), false
			for _, example := range examples {
				if example == candidate {
					found = true
					break
				}
			}
			if !found && len(examples) < 16 {
				examples = append(examples, candidate)
			}
		}
		record.Set("cname_examples", examples)
	}
	return app.Save(record)
}

func boundedExample(values []string, value string, limit int) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	if len(values) < limit {
		return append(values, value)
	}
	return values
}

// Drop bookkeeping when its source expires, including records deleted manually.
func PruneDomainCatalogueCheckpoints(app core.App) error {
	for _, source := range catalogueSources {
		_, err := app.DB().NewQuery("DELETE FROM _domain_catalogue_checkpoints WHERE source={:source} AND NOT EXISTS (SELECT 1 FROM " + source.collection + " WHERE id=source_id)").Bind(dbx.Params{"source": source.collection}).Execute()
		if err != nil {
			return err
		}
	}
	return nil
}
