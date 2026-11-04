package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/displaymode"
)

// Only the local nginx proxy supplies X-Real-IP. Direct clients cannot select
// another device by sending a header or an address in the request body.
func displayClientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		if forwarded, err := netip.ParseAddr(request.Header.Get("X-Real-IP")); err == nil {
			ip = forwarded.Unmap()
		}
	}
	return ip.String()
}

func (g *Runtime) registerDisplayRoutes(r *router.Router[*core.RequestEvent]) {
	r.GET("/api/infrareveal/display-mode", func(e *core.RequestEvent) error {
		ip := displayClientIP(e.Request)
		e.Response.Header().Set("Cache-Control", "no-store")
		eligible := g.config.Observation.Scope.ContainsClient(ip) && g.displays.Eligible(ip)
		return e.JSON(http.StatusOK, map[string]any{"eligible": eligible, "active": eligible && g.displays.Excluded(ip, ""), "graceMs": displaymode.Grace.Milliseconds()})
	})
	for _, action := range []string{"start", "renew", "stop"} {
		r.POST("/api/infrareveal/display-mode/"+action, func(e *core.RequestEvent) error {
			e.Response.Header().Set("Cache-Control", "no-store")
			ip := displayClientIP(e.Request)
			if !g.config.Observation.Scope.ContainsClient(ip) {
				return e.JSON(http.StatusForbidden, map[string]string{"message": displaymode.ErrLease.Error()})
			}
			var body struct {
				Token string `json:"token"`
			}
			e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, 1024)
			if err := e.BindBody(&body); err != nil {
				return e.BadRequestError("Invalid display request", err)
			}
			var status displaymode.Status
			var err error
			switch action {
			case "start":
				status, err = g.displays.Start(ip)
			case "renew":
				status, err = g.displays.Renew(ip, body.Token)
			case "stop":
				g.displays.Stop(ip, body.Token)
				return e.JSON(http.StatusOK, map[string]bool{"active": false})
			}
			if err != nil {
				code := http.StatusConflict
				if errors.Is(err, displaymode.ErrLease) {
					code = http.StatusForbidden
				}
				return e.JSON(code, map[string]string{"message": err.Error()})
			}
			// Finish releasing any previously held packets before the browser
			// starts its map requests. Ordinary forwarding is never disabled.
			if g.gate != nil {
				if err := g.gate.RefreshExclusions(e.Request.Context()); err != nil {
					return e.InternalServerError("Could not release display traffic from the lab gate", err)
				}
			}
			return e.JSON(http.StatusOK, status)
		})
	}
}
