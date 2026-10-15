package data

import (
	"database/sql"
	"encoding/json"
	"github.com/pocketbase/dbx"
)

// ReadTraffic avoids building PocketBase record/export maps for dense sample
// arrays. Both block projection and map reads consume the same typed fact.
func ReadTraffic(query *dbx.SelectQuery) ([]TrafficChunk, error) {
	var rows []struct {
		TrafficChunk
		Samples  sql.NullString `db:"samples"`
		Evidence sql.NullString `db:"evidence"`
	}
	if err := query.All(&rows); err != nil {
		return nil, err
	}
	chunks := make([]TrafficChunk, 0, len(rows))
	for _, row := range rows {
		c := row.TrafficChunk
		if err := decodeNullableJSON(row.Samples, &c.Samples); err != nil {
			return nil, err
		}
		if err := decodeNullableJSON(row.Evidence, &c.Evidence); err != nil {
			return nil, err
		}
		chunks = append(chunks, c)
	}
	return chunks, nil
}

func decodeNullableJSON(raw sql.NullString, value any) error {
	if !raw.Valid || raw.String == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw.String), value)
}
