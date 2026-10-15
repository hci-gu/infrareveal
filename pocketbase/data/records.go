package data

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func ID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:15]
}

func NewID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes[:])[:15]
}

func Decode[T any](record *core.Record) (value T, err error) {
	encoded, err := json.Marshal(record.PublicExport())
	if err == nil {
		err = json.Unmarshal(encoded, &value)
	}
	return value, err
}

// Write stores one typed document. Transaction ownership belongs to the caller
// when replacing several documents or bumping a session revision together.
func Write(app core.App, collection string, value any) (*core.Record, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	var id string
	_ = json.Unmarshal(fields["id"], &id)
	var record *core.Record
	if id != "" {
		record, err = app.FindRecordById(collection, id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	if record == nil {
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			return nil, err
		}
		record = core.NewRecord(c)
		if id != "" {
			record.Id = id
		}
	}
	for name, field := range fields {
		if name == "id" {
			continue
		}
		var decoded any
		if err := json.Unmarshal(field, &decoded); err != nil {
			return nil, err
		}
		record.Set(name, decoded)
	}
	return record, app.Save(record)
}

// BumpRevision is called inside the same transaction as product fact writes.
// An SQL increment avoids recursively firing session lifecycle hooks.
func BumpRevision(app core.App, session string) error {
	_, err := app.DB().NewQuery("UPDATE sessions SET revision = revision + 1 WHERE id={:id}").Bind(dbx.Params{"id": session}).Execute()
	return err
}
