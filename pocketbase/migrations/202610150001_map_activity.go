package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
	"myapp/data"
)

// This is a fresh application schema. Development data is reset, not migrated.
func init() {
	m.Register(func(app core.App) error { return data.InstallCore(app) }, nil)
}
