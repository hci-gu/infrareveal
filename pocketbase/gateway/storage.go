package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"golang.org/x/sys/unix"
)

type filesystemUsage struct {
	Total     uint64 `json:"total_bytes"`
	Used      uint64 `json:"used_bytes"`
	Available uint64 `json:"available_bytes"`
	ReadOnly  bool   `json:"read_only"`
	State     string `json:"state"`
}
type databaseUsage struct {
	Name          string `json:"name"`
	Bytes         int64  `json:"bytes"`
	WALBytes      int64  `json:"wal_bytes"`
	ReusableBytes int64  `json:"reusable_bytes"`
}

func diskUsage(path string) (filesystemUsage, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return filesystemUsage{}, err
	}
	total, free, available := uint64(s.Blocks)*uint64(s.Bsize), uint64(s.Bfree)*uint64(s.Bsize), uint64(s.Bavail)*uint64(s.Bsize)
	u := filesystemUsage{Total: total, Used: total - free, Available: available, ReadOnly: s.Flags&1 != 0, State: "ok"}
	if total == 0 {
		u.State = "unknown"
	} else if available < 512*1024*1024 || float64(available)/float64(total) < 0.05 {
		u.State = "critical"
	} else if available < 2*1024*1024*1024 || float64(available)/float64(total) < 0.15 {
		u.State = "low"
	}
	if u.ReadOnly {
		u.State = "read_only"
	}
	return u, nil
}

func fileBytes(path string) int64 {
	if s, err := os.Stat(path); err == nil {
		return s.Size()
	}
	return 0
}

func databaseSize(db dbx.Builder, directory, name string) (databaseUsage, error) {
	var pageSize, free int64
	if err := db.NewQuery("PRAGMA page_size").Row(&pageSize); err != nil {
		return databaseUsage{}, err
	}
	if err := db.NewQuery("PRAGMA freelist_count").Row(&free); err != nil {
		return databaseUsage{}, err
	}
	path := filepath.Join(directory, name)
	return databaseUsage{Name: name, Bytes: fileBytes(path), WALBytes: fileBytes(path + "-wal"), ReusableBytes: free * pageSize}, nil
}

func (g *Runtime) registerStorageRoutes(r *router.Router[*core.RequestEvent]) {
	r.GET("/api/infrareveal/storage", func(e *core.RequestEvent) error {
		disk, err := diskUsage(g.app.DataDir())
		if err != nil {
			return e.InternalServerError("Cannot read gateway disk usage", err)
		}
		main, err := databaseSize(g.app.ConcurrentDB(), g.app.DataDir(), "data.db")
		if err != nil {
			return e.InternalServerError("Cannot read recording storage", err)
		}
		aux, err := databaseSize(g.app.AuxConcurrentDB(), g.app.DataDir(), "auxiliary.db")
		if err != nil {
			return e.InternalServerError("Cannot read application log storage", err)
		}
		// Counts use the session index; do not decode or total every sample payload.
		var counts []struct {
			Session string `db:"session" json:"session"`
			Chunks  int64  `db:"chunks" json:"chunks"`
		}
		if err = g.app.ConcurrentDB().NewQuery("SELECT session,count(*) chunks FROM traffic_chunks GROUP BY session").All(&counts); err != nil {
			return e.InternalServerError("Cannot read session storage", err)
		}
		g.maintenance.RLock()
		maintenance := g.maintenance.status
		g.maintenance.RUnlock()
		return e.JSON(http.StatusOK, map[string]any{"checked_ms": time.Now().UnixMilli(), "disk": disk, "databases": []databaseUsage{main, aux}, "session_counts": counts, "maintenance": maintenance, "hardware_health": "unavailable", "demo_enabled": g.config.Demo})
	})
	r.GET("/api/infrareveal/geoip", func(e *core.RequestEvent) error {
		if g.geo == nil {
			return e.JSON(http.StatusServiceUnavailable, map[string]string{"message": "GeoIP service is not running"})
		}
		e.Response.Header().Set("Cache-Control", "no-store")
		return e.JSON(http.StatusOK, g.geo.Status())
	})
	r.PUT("/api/infrareveal/geoip/settings", func(e *core.RequestEvent) error {
		if g.geo == nil {
			return e.JSON(http.StatusServiceUnavailable, map[string]string{"message": "GeoIP service is not running"})
		}
		var body struct {
			AccountID  string `json:"account_id"`
			LicenseKey string `json:"license_key"`
		}
		e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, 4096)
		if err := e.BindBody(&body); err != nil {
			return e.BadRequestError("Invalid MaxMind settings", nil)
		}
		if err := g.geo.Configure(body.AccountID, body.LicenseKey); err != nil {
			return e.BadRequestError(err.Error(), nil)
		}
		return e.JSON(http.StatusOK, g.geo.Status())
	})
	r.POST("/api/infrareveal/geoip/refresh", func(e *core.RequestEvent) error {
		if g.geo == nil {
			return e.JSON(http.StatusServiceUnavailable, map[string]string{"message": "GeoIP service is not running"})
		}
		if err := g.geo.Refresh(); err != nil {
			return e.BadRequestError(err.Error(), nil)
		}
		return e.JSON(http.StatusAccepted, g.geo.Status())
	})
}
