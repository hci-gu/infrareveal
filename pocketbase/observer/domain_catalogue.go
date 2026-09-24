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

// CollectDomainCatalogue checkpoints each source revision in the same transaction
// as its aggregate. Markers expire with raw observations; no permanent per-device
// or per-flow ledger is created. Changed attributions transfer their count.
func CollectDomainCatalogue(app core.App, session string) error {
	for _, source := range []string{"dns_queries", "flow_attributions"} {
		// Compare relevant content, not millisecond updated timestamps. Two DNS
		// replies may land in the same millisecond. Separate checkpoints cannot
		// be overwritten by a writer holding an older source Record instance.
		revision := "json_array(dns_queries.query_name,dns_queries.timestamp,dns_queries.aliases)"
		if source == "flow_attributions" {
			revision = "json_array(flow_attributions.candidate_hostname,flow_attributions.confidence,flow_attributions.observed_at)"
		}
		for {
			count := 0
			err := app.RunInTransaction(func(tx core.App) error {
				rows := []*core.Record{}
				err := tx.RecordQuery(source).AndWhere(dbx.NewExp("session={:s} AND NOT EXISTS (SELECT 1 FROM _domain_catalogue_checkpoints c WHERE c.source={:source} AND c.source_id="+source+".id AND c.revision="+revision+")", dbx.Params{"s": session, "source": source})).OrderBy("updated", "id").Limit(250).All(&rows)
				if err != nil {
					return err
				}
				count = len(rows)
				for _, raw := range rows {
					old := catalogueState{}
					var checkpoint struct {
						State string `db:"state"`
					}
					err := tx.DB().NewQuery("SELECT state FROM _domain_catalogue_checkpoints WHERE source={:source} AND source_id={:id}").Bind(dbx.Params{"source": source, "id": raw.Id}).One(&checkpoint)
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return err
					}
					if checkpoint.State != "" {
						if err = json.Unmarshal([]byte(checkpoint.State), &old); err != nil {
							return err
						}
					}
					hostname, counter, at := raw.GetString("query_name"), "dns_count", raw.GetDateTime("timestamp").Time()
					if source == "flow_attributions" {
						hostname, at = raw.GetString("candidate_hostname"), raw.GetDateTime("observed_at").Time()
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
					hostname = normalizeActivityHostname(hostname)
					domain := registeredActivityDomain(hostname)
					next := catalogueState{Domain: domain, Counter: counter}
					if domain == "" || counter == "" {
						next = catalogueState{}
					}
					if old != next && old.Domain != "" {
						previous, err := tx.FindFirstRecordByFilter("domain_catalogue", "domain={:d}", dbx.Params{"d": old.Domain})
						if err != nil && !errors.Is(err, sql.ErrNoRows) {
							return err
						}
						if err == nil {
							previous.Set(old.Counter, max(0, previous.GetInt(old.Counter)-1))
							if err = tx.Save(previous); err != nil {
								return err
							}
						}
					}
					if next.Domain != "" {
						rec, err := tx.FindFirstRecordByFilter("domain_catalogue", "domain={:d}", dbx.Params{"d": domain})
						if errors.Is(err, sql.ErrNoRows) {
							c, err := tx.FindCollectionByNameOrId("domain_catalogue")
							if err != nil {
								return err
							}
							rec = core.NewRecord(c)
							rec.Set("domain", domain)
							rec.Set("review_status", "pending")
						} else if err != nil {
							return err
						}
						if old != next {
							rec.Set(counter, rec.GetInt(counter)+1)
						}
						if at.IsZero() {
							at = time.Now().UTC()
						}
						first, last := rec.GetDateTime("first_seen").Time(), rec.GetDateTime("last_seen").Time()
						if first.IsZero() || at.Before(first) {
							rec.Set("first_seen", at)
						}
						if at.After(last) {
							rec.Set("last_seen", at)
						}
						hosts := rec.GetStringSlice("hostnames")
						hosts = boundedExample(hosts, hostname, 16)
						rec.Set("hostnames", hosts)
						if source == "dns_queries" {
							examples := []cnameExample{}
							if err = rec.UnmarshalJSONField("cname_examples", &examples); err != nil {
								return err
							}
							for _, alias := range raw.GetStringSlice("aliases") {
								alias = normalizeActivityHostname(alias)
								if registeredActivityDomain(alias) == "" || alias == hostname {
									continue
								}
								candidate, found := (cnameExample{Query: hostname, Alias: alias}), false
								for _, ex := range examples {
									if ex == candidate {
										found = true
										break
									}
								}
								if !found && len(examples) < 16 {
									examples = append(examples, candidate)
								}
							}
							rec.Set("cname_examples", examples)
						}
						if err = tx.Save(rec); err != nil {
							return err
						}
					}
					state, err := json.Marshal(next)
					if err != nil {
						return err
					}
					// Do not advance source updated or emit a realtime event for bookkeeping.
					_, err = tx.DB().NewQuery("INSERT OR REPLACE INTO _domain_catalogue_checkpoints (source,source_id,revision,state) SELECT {:source},id," + revision + ",{:state} FROM " + source + " WHERE id={:id}").Bind(dbx.Params{"source": source, "state": string(state), "id": raw.Id}).Execute()
					if err != nil {
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
	for _, source := range []string{"dns_queries", "flow_attributions"} {
		_, err := app.DB().NewQuery("DELETE FROM _domain_catalogue_checkpoints WHERE source={:source} AND NOT EXISTS (SELECT 1 FROM " + source + " WHERE id=source_id)").Bind(dbx.Params{"source": source}).Execute()
		if err != nil {
			return err
		}
	}
	return nil
}
