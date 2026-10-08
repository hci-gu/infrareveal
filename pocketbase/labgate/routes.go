package labgate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"myapp/netmeta"
)

const maxControlBodyBytes = 64 * 1024

type ControlRouteConfig struct {
	Token          []byte
	AllowedOrigins []string
	ClientSubnet   netip.Prefix
}

type statusResponse struct {
	RequestID string `json:"requestId"`
	Status    Status `json:"status"`
}

type pendingResponse struct {
	RequestID string        `json:"requestId"`
	Decisions []decisionDTO `json:"decisions"`
}

type decisionResponse struct {
	RequestID       string      `json:"requestId"`
	Result          decisionDTO `json:"result"`
	AlreadyTerminal bool        `json:"alreadyTerminal"`
	Status          Status      `json:"status"`
	Error           string      `json:"error,omitempty"`
}

type approveAllResponse struct {
	RequestID string        `json:"requestId"`
	Results   []decisionDTO `json:"results"`
	Status    Status        `json:"status"`
}

type errorResponse struct {
	RequestID string `json:"requestId"`
	Error     string `json:"error"`
}

// decisionDTO preserves the control protocol's epoch-millisecond timestamps.
// The policy Decision and durable gate_events record use their own time types.
type decisionDTO struct {
	ID            string            `json:"id"`
	FlowKey       string            `json:"flowKey"`
	SessionID     string            `json:"sessionId"`
	ClientIP      string            `json:"clientIp"`
	RemoteIP      string            `json:"remoteIp"`
	ClientPort    uint16            `json:"clientPort"`
	RemotePort    uint16            `json:"remotePort"`
	Protocol      string            `json:"protocol"`
	Mode          Mode              `json:"mode"`
	Direction     netmeta.Direction `json:"direction"`
	PacketCount   int               `json:"packetCount"`
	WireBytes     uint32            `json:"wireBytes"`
	PayloadBytes  uint32            `json:"payloadBytes"`
	TCPFlags      uint16            `json:"tcpFlags"`
	QueuedAtMS    int64             `json:"queuedAtMs"`
	DeadlineMS    int64             `json:"deadlineMs"`
	State         DecisionState     `json:"state"`
	Verdict       Verdict           `json:"verdict"`
	VerdictSource VerdictSource     `json:"verdictSource"`
	Actor         string            `json:"actor"`
	Reason        string            `json:"reason"`
	DecidedAtMS   int64             `json:"decidedAtMs"`
	WaitMS        int64             `json:"waitMs"`
}

func LoadControlToken(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("control token file is not configured")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read control token: %w", err)
	}
	token := []byte(strings.TrimSpace(string(contents)))
	if len(token) < 32 || len(token) > 512 {
		return nil, errors.New("control token must contain 32 to 512 non-whitespace bytes")
	}
	return token, nil
}

type routeLimiterEntry struct {
	start               time.Time
	failures, mutations int
}
type routeLimiter struct {
	mu      sync.Mutex
	entries map[string]routeLimiterEntry
}

type controlRoutes struct {
	app        core.App
	controller *Controller
	config     ControlRouteConfig
	origins    map[string]struct{}
	limiter    routeLimiter
}

func RegisterControlRoutes(r *router.Router[*core.RequestEvent], app core.App, controller *Controller, config ControlRouteConfig) {
	handler := &controlRoutes{app: app, controller: controller, config: config, origins: make(map[string]struct{}), limiter: routeLimiter{entries: make(map[string]routeLimiterEntry)}}
	for _, origin := range config.AllowedOrigins {
		handler.origins[strings.TrimSpace(origin)] = struct{}{}
	}
	r.OPTIONS("/api/infrareveal/lab-gate/{path...}", handler.options)
	r.GET("/api/infrareveal/lab-gate/status", handler.status)
	r.GET("/api/infrareveal/lab-gate/pending", handler.pending)
	r.POST("/api/infrareveal/lab-gate/arm", mutation(handler, handler.arm))
	r.POST("/api/infrareveal/lab-gate/pause", handler.simple(controller.Pause))
	r.POST("/api/infrareveal/lab-gate/resume", handler.simple(controller.Resume))
	r.POST("/api/infrareveal/lab-gate/drain", handler.simple(controller.Drain))
	r.POST("/api/infrareveal/lab-gate/disarm", handler.simple(controller.Disarm))
	r.POST("/api/infrareveal/lab-gate/decisions/{decisionID}", mutation(handler, handler.decision))
	r.POST("/api/infrareveal/lab-gate/approve-all", mutation(handler, handler.approveAll))
	r.POST("/api/infrareveal/lab-gate/strict/accept-next", mutation(handler, handler.acceptNext))
}

func (routes *controlRoutes) options(event *core.RequestEvent) error {
	if !routes.allowOrigin(event) {
		return routes.respondError(event, http.StatusForbidden, newRequestID(), "origin is not allowed")
	}
	event.Response.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	event.Response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	event.Response.Header().Set("Access-Control-Max-Age", "600")
	return event.NoContent(http.StatusNoContent)
}

func (routes *controlRoutes) status(event *core.RequestEvent) error {
	requestID := newRequestID()
	if !routes.allowOrigin(event) {
		return routes.respondError(event, http.StatusForbidden, requestID, "origin is not allowed")
	}
	status, err := routes.controller.Status(event.Request.Context())
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	return event.JSON(http.StatusOK, statusResponse{RequestID: requestID, Status: status})
}

func (routes *controlRoutes) pending(event *core.RequestEvent) error {
	requestID := newRequestID()
	if !routes.authorize(event, requestID) {
		return nil
	}
	pending, err := routes.controller.Pending(event.Request.Context())
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	return event.JSON(http.StatusOK, pendingResponse{RequestID: requestID, Decisions: decisionsForAPI(pending)})
}

type armBody struct {
	SessionID string   `json:"sessionId"`
	Mode      Mode     `json:"mode"`
	ClientIPs []string `json:"clientIps"`
	Strict    *struct {
		Protocol   string `json:"protocol"`
		ClientIP   string `json:"clientIp"`
		ClientPort int    `json:"clientPort"`
		RemoteIP   string `json:"remoteIp"`
		RemotePort int    `json:"remotePort"`
	} `json:"strict,omitempty"`
}

func (routes *controlRoutes) arm(event *core.RequestEvent, requestID string, body armBody) error {
	session, err := routes.app.FindRecordById("sessions", strings.TrimSpace(body.SessionID))
	if err != nil || !session.GetBool("active") {
		return routes.respondError(event, http.StatusConflict, requestID, "session is not active")
	}
	clients := make([]netip.Addr, 0, len(body.ClientIPs))
	for _, text := range body.ClientIPs {
		client, parseErr := netip.ParseAddr(strings.TrimSpace(text))
		if parseErr != nil || !routes.config.ClientSubnet.Contains(client.Unmap()) {
			return routes.respondError(event, http.StatusBadRequest, requestID, "client IP is outside the configured lab subnet")
		}
		clients = append(clients, client.Unmap())
	}
	var strict *netmeta.FlowTuple
	if body.Strict != nil {
		if body.Strict.ClientPort < 1 || body.Strict.ClientPort > 65535 || body.Strict.RemotePort < 1 || body.Strict.RemotePort > 65535 {
			return routes.respondError(event, http.StatusBadRequest, requestID, "strict client and remote ports must be between 1 and 65535")
		}
		tuple, valid := netmeta.ParseFlowTuple(body.Strict.Protocol, body.Strict.ClientIP, body.Strict.ClientPort, body.Strict.RemoteIP, body.Strict.RemotePort)
		if !valid {
			return routes.respondError(event, http.StatusBadRequest, requestID, "strict must contain a complete TCP or UDP tuple")
		}
		strict = &tuple
	}
	status, err := routes.controller.Arm(event.Request.Context(), ArmRequest{SessionID: session.Id, Mode: body.Mode, Clients: clients, Strict: strict})
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	return event.JSON(http.StatusOK, statusResponse{RequestID: requestID, Status: status})
}

type commandBody struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

func (routes *controlRoutes) simple(action func(context.Context) (Status, error)) func(*core.RequestEvent) error {
	return mutation(routes, func(event *core.RequestEvent, requestID string, _ commandBody) error {
		status, err := action(event.Request.Context())
		if err != nil {
			return routes.controllerError(event, requestID, err)
		}
		return event.JSON(http.StatusOK, statusResponse{RequestID: requestID, Status: status})
	})
}

type decisionBody struct {
	Verdict Verdict `json:"verdict"`
	Actor   string  `json:"actor"`
	Reason  string  `json:"reason"`
}

func (routes *controlRoutes) decision(event *core.RequestEvent, requestID string, body decisionBody) error {
	result, err := routes.controller.Decide(event.Request.Context(), DecisionCommand{
		DecisionID: event.Request.PathValue("decisionID"), Verdict: body.Verdict,
		Actor: safeActor(body.Actor), Reason: safeReason(body.Reason),
	})
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	status, _ := routes.controller.Status(event.Request.Context())
	payload := decisionResponse{RequestID: requestID, Result: decisionForAPI(result.Decision), AlreadyTerminal: result.AlreadyTerminal, Status: status}
	if result.AlreadyTerminal {
		payload.Error = "decision is already terminal"
		return event.JSON(http.StatusConflict, payload)
	}
	return event.JSON(http.StatusOK, payload)
}

func (routes *controlRoutes) approveAll(event *core.RequestEvent, requestID string, body commandBody) error {
	results, err := routes.controller.ApproveAll(event.Request.Context(), safeActor(body.Actor), safeReason(body.Reason))
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	decisions := make([]decisionDTO, 0, len(results))
	for _, result := range results {
		decisions = append(decisions, decisionForAPI(result.Decision))
	}
	status, _ := routes.controller.Status(event.Request.Context())
	return event.JSON(http.StatusOK, approveAllResponse{RequestID: requestID, Results: decisions, Status: status})
}

type acceptNextBody struct {
	Count int    `json:"count"`
	Actor string `json:"actor"`
}

func (routes *controlRoutes) acceptNext(event *core.RequestEvent, requestID string, body acceptNextBody) error {
	if body.Count < 1 || body.Count > 100 {
		return routes.respondError(event, http.StatusBadRequest, requestID, "count must be between 1 and 100")
	}
	status, err := routes.controller.AcceptNext(event.Request.Context(), body.Count, safeActor(body.Actor))
	if err != nil {
		return routes.controllerError(event, requestID, err)
	}
	return event.JSON(http.StatusOK, statusResponse{RequestID: requestID, Status: status})
}

// mutation keeps authentication, rate limits and strict body decoding in one
// order. Each command retains its typed body and response/error semantics.
func mutation[T any](routes *controlRoutes, action func(*core.RequestEvent, string, T) error) func(*core.RequestEvent) error {
	return func(event *core.RequestEvent) error {
		requestID := newRequestID()
		if !routes.authorizeMutation(event, requestID) {
			return nil
		}
		var body T
		if err := decodeControlBody(event, &body); err != nil {
			return routes.respondError(event, bodyStatus(err), requestID, err.Error())
		}
		return action(event, requestID, body)
	}
}

func (routes *controlRoutes) authorizeMutation(event *core.RequestEvent, requestID string) bool {
	if !routes.authorize(event, requestID) {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(event.Request.Header.Get("Content-Type")), "application/json") {
		_ = routes.respondError(event, http.StatusUnsupportedMediaType, requestID, "application/json is required")
		return false
	}
	if !routes.limiter.allow(clientAddress(event.Request), false) {
		_ = routes.respondError(event, http.StatusTooManyRequests, requestID, "control rate limit exceeded")
		return false
	}
	return true
}

func (routes *controlRoutes) authorize(event *core.RequestEvent, requestID string) bool {
	if !routes.allowOrigin(event) {
		_ = routes.respondError(event, http.StatusForbidden, requestID, "origin is not allowed")
		return false
	}
	authorization := event.Request.Header.Get("Authorization")
	provided := strings.TrimPrefix(authorization, "Bearer ")
	expectedHash, providedHash := sha256.Sum256(routes.config.Token), sha256.Sum256([]byte(provided))
	valid := len(routes.config.Token) > 0 && strings.HasPrefix(authorization, "Bearer ") && subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
	if !valid {
		if !routes.limiter.allow(clientAddress(event.Request), true) {
			_ = routes.respondError(event, http.StatusTooManyRequests, requestID, "authentication rate limit exceeded")
		} else {
			_ = routes.respondError(event, http.StatusUnauthorized, requestID, "valid bearer authorization is required")
		}
		return false
	}
	return true
}

func (routes *controlRoutes) allowOrigin(event *core.RequestEvent) bool {
	origin := strings.TrimSpace(event.Request.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if _, ok := routes.origins[origin]; !ok {
		return false
	}
	event.Response.Header().Set("Access-Control-Allow-Origin", origin)
	event.Response.Header().Set("Vary", "Origin")
	return true
}

func (limiter *routeLimiter) allow(address string, failure bool) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := time.Now()
	entry := limiter.entries[address]
	if entry.start.IsZero() || now.Sub(entry.start) >= time.Second {
		entry = routeLimiterEntry{start: now}
	}
	if failure {
		entry.failures++
	} else {
		entry.mutations++
	}
	limiter.entries[address] = entry
	if len(limiter.entries) > 1024 {
		for key, candidate := range limiter.entries {
			if now.Sub(candidate.start) > time.Minute {
				delete(limiter.entries, key)
			}
		}
	}
	if failure {
		return entry.failures <= 5
	}
	return entry.mutations <= 30
}

func decodeControlBody(event *core.RequestEvent, target any) error {
	event.Request.Body = http.MaxBytesReader(event.Response, event.Request.Body, maxControlBodyBytes)
	decoder := json.NewDecoder(event.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func bodyStatus(err error) int {
	if strings.Contains(err.Error(), "request body too large") {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func (routes *controlRoutes) controllerError(event *core.RequestEvent, requestID string, err error) error {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrDecisionNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrInvalidArmRequest):
		status = http.StatusConflict
	case errors.Is(err, ErrDisabled), errors.Is(err, ErrUnavailable):
		status = http.StatusServiceUnavailable
	}
	return routes.respondError(event, status, requestID, err.Error())
}

func (routes *controlRoutes) respondError(event *core.RequestEvent, status int, requestID, message string) error {
	return event.JSON(status, errorResponse{RequestID: requestID, Error: message})
}

func decisionsForAPI(decisions []Decision) []decisionDTO {
	result := make([]decisionDTO, 0, len(decisions))
	for _, decision := range decisions {
		result = append(result, decisionForAPI(decision))
	}
	return result
}

func decisionForAPI(decision Decision) decisionDTO {
	decidedAtMS := int64(0)
	if !decision.DecidedAt.IsZero() {
		decidedAtMS = decision.DecidedAt.UnixMilli()
	}
	return decisionDTO{
		ID: decision.ID, FlowKey: decision.FlowKey, SessionID: decision.SessionID,
		ClientIP: decision.ClientIP, RemoteIP: decision.RemoteIP, ClientPort: decision.ClientPort,
		RemotePort: decision.RemotePort, Protocol: decision.Protocol, Mode: decision.Mode, Direction: decision.Direction, PacketCount: decision.PacketCount,
		WireBytes: decision.WireBytes, PayloadBytes: decision.PayloadBytes,
		TCPFlags: decision.TCPFlags, QueuedAtMS: decision.QueuedAt.UnixMilli(), DeadlineMS: decision.Deadline.UnixMilli(),
		State: decision.State, Verdict: decision.Verdict, VerdictSource: decision.Source,
		Actor: decision.Actor, Reason: decision.Reason, DecidedAtMS: decidedAtMS, WaitMS: decision.WaitMS,
	}
}

func safeActor(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "operator"
	}
	if len(value) > 128 {
		return value[:128]
	}
	return value
}

func safeReason(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 500 {
		return value[:500]
	}
	return value
}

func clientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return request.RemoteAddr
}

func newRequestID() string {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("command-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
