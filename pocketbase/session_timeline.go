package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

const (
	defaultTimelinePageSize = 500
	maxTimelinePageSize     = 1000
	maxTimelineDetailSpan   = 15 * time.Minute
	maxTimelineFlowFilter   = 200
)

type sessionTimelineManifest struct {
	SessionID         string           `json:"sessionId"`
	Name              string           `json:"name"`
	StartedAt         string           `json:"startedAt"`
	EndedAt           *string          `json:"endedAt"`
	Active            bool             `json:"active"`
	ServerNow         string           `json:"serverNow"`
	Watermark         string           `json:"watermark"`
	Counts            map[string]int64 `json:"counts"`
	Coverage          timelineRange    `json:"coverage"`
	GateAuditComplete bool             `json:"gateAuditComplete"`
	GateAuditDrops    int              `json:"gateAuditDrops"`
}

type timelineRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type sessionTimelineWindow struct {
	Range                timelineRange    `json:"range"`
	LOD                  string           `json:"lod"`
	Watermark            string           `json:"watermark"`
	Flows                []map[string]any `json:"flows"`
	DNSQueries           []map[string]any `json:"dnsQueries"`
	Attributions         []map[string]any `json:"attributions"`
	ActivityEpisodes     []map[string]any `json:"activityEpisodes"`
	FlowAssociations     []map[string]any `json:"flowAssociations"`
	FlowActivityChunks   []map[string]any `json:"flowActivityChunks"`
	FlowActivityWindows  []map[string]any `json:"flowActivityWindows"`
	FlowActivityStatuses []map[string]any `json:"flowActivityStatuses"`
	Destinations         []map[string]any `json:"destinations"`
	Routes               []map[string]any `json:"routes"`
	GateEvents           []map[string]any `json:"gateEvents"`
	NextCursor           *string          `json:"nextCursor"`
}

type timelineCursor map[string]int

type activitySamplePayload struct {
	Version  int       `json:"version"`
	BucketMS int       `json:"bucket_ms"`
	ChunkMS  int       `json:"chunk_ms"`
	Samples  [][]int64 `json:"samples"`
}

func registerSessionTimelineRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	r.GET("/api/infrareveal/sessions/{id}/manifest", func(e *core.RequestEvent) error {
		manifest, err := buildSessionTimelineManifest(app, e.Request.PathValue("id"), time.Now().UTC())
		if err != nil {
			return e.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		return e.JSON(http.StatusOK, manifest)
	})

	r.GET("/api/infrareveal/sessions/{id}/window", func(e *core.RequestEvent) error {
		window, status, err := buildSessionTimelineWindow(app, e.Request.PathValue("id"), e.Request.URL.Query())
		if err != nil {
			return e.JSON(status, map[string]string{"error": err.Error()})
		}
		return e.JSON(http.StatusOK, window)
	})
}

func buildSessionTimelineManifest(app core.App, sessionID string, now time.Time) (sessionTimelineManifest, error) {
	record, err := app.FindRecordById("sessions", sessionID)
	if err != nil {
		return sessionTimelineManifest{}, fmt.Errorf("session not found")
	}

	started := record.GetDateTime("started_at").Time()
	if started.IsZero() {
		started = record.GetDateTime("created").Time()
	}
	active := record.GetBool("active")
	ended := record.GetDateTime("ended_at").Time()
	if !active && ended.IsZero() {
		ended = record.GetDateTime("updated").Time()
	}

	coverageFrom := started
	coverageTo := ended
	if active || coverageTo.IsZero() {
		coverageTo = now
	}
	if firstRecords, findErr := app.FindRecordsByFilter("flows", "session={:session}", "start", 1, 0, dbx.Params{"session": sessionID}); findErr == nil && len(firstRecords) > 0 {
		candidate := firstRecords[0].GetDateTime("start").Time()
		if !candidate.IsZero() && (coverageFrom.IsZero() || candidate.Before(coverageFrom)) {
			coverageFrom = candidate
		}
	}
	if lastRecords, findErr := app.FindRecordsByFilter("flows", "session={:session}", "-last_seen", 1, 0, dbx.Params{"session": sessionID}); findErr == nil && len(lastRecords) > 0 {
		candidate := lastRecords[0].GetDateTime("last_seen").Time()
		if !candidate.IsZero() && candidate.After(coverageTo) {
			coverageTo = candidate
		}
	}
	if coverageFrom.IsZero() {
		coverageFrom = now
	}
	if coverageTo.Before(coverageFrom) {
		coverageTo = coverageFrom
	}

	counts := map[string]int64{}
	for _, collection := range []string{
		"flows", "dns_queries", "flow_attributions", "activity_episodes",
		"flow_associations", "flow_activity_chunks", "flow_activity_windows", "routes",
		"gate_events",
	} {
		count, countErr := app.CountRecords(collection, dbx.HashExp{"session": sessionID})
		if countErr != nil {
			return sessionTimelineManifest{}, fmt.Errorf("count %s: %w", collection, countErr)
		}
		counts[collection] = count
	}

	manifest := sessionTimelineManifest{
		SessionID:         sessionID,
		Name:              record.GetString("name"),
		StartedAt:         started.UTC().Format(time.RFC3339Nano),
		Active:            active,
		ServerNow:         now.Format(time.RFC3339Nano),
		Watermark:         now.Format(time.RFC3339Nano),
		Counts:            counts,
		GateAuditComplete: record.GetBool("gate_audit_complete"),
		GateAuditDrops:    record.GetInt("gate_audit_drops"),
		Coverage: timelineRange{
			From: coverageFrom.UTC().Format(time.RFC3339Nano),
			To:   coverageTo.UTC().Format(time.RFC3339Nano),
		},
	}
	if !ended.IsZero() {
		value := ended.UTC().Format(time.RFC3339Nano)
		manifest.EndedAt = &value
	}
	return manifest, nil
}

func buildSessionTimelineWindow(app core.App, sessionID string, query map[string][]string) (sessionTimelineWindow, int, error) {
	if _, err := app.FindRecordById("sessions", sessionID); err != nil {
		return sessionTimelineWindow{}, http.StatusNotFound, fmt.Errorf("session not found")
	}
	from, err := parseTimelineTime(firstQueryValue(query, "from"))
	if err != nil {
		return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("invalid from: %w", err)
	}
	to, err := parseTimelineTime(firstQueryValue(query, "to"))
	if err != nil {
		return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("invalid to: %w", err)
	}
	if !to.After(from) {
		return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("to must be after from")
	}

	lod, lodMS, overview, err := parseTimelineLOD(firstQueryValue(query, "lod"))
	if err != nil {
		return sessionTimelineWindow{}, http.StatusBadRequest, err
	}
	if !overview && to.Sub(from) > maxTimelineDetailSpan {
		return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("detail windows are limited to %s", maxTimelineDetailSpan)
	}

	limit := defaultTimelinePageSize
	if value := firstQueryValue(query, "limit"); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed < 1 || parsed > maxTimelinePageSize {
			return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("limit must be between 1 and %d", maxTimelinePageSize)
		}
		limit = parsed
	}
	cursor, err := decodeTimelineCursor(firstQueryValue(query, "cursor"), overview)
	if err != nil {
		return sessionTimelineWindow{}, http.StatusBadRequest, err
	}
	requestedFlowIDs := parseFlowIDs(firstQueryValue(query, "flow"))
	if len(requestedFlowIDs) > maxTimelineFlowFilter {
		return sessionTimelineWindow{}, http.StatusBadRequest, fmt.Errorf("at most %d flow ids may be requested", maxTimelineFlowFilter)
	}

	params := dbx.Params{
		"from": formatPocketBaseTimelineDate(from),
		"to":   formatPocketBaseTimelineDate(to),
	}

	flowExpressions := []dbx.Expression{
		dbx.HashExp{"session": sessionID},
		dbx.NewExp("[[start]] < {:to} AND [[last_seen]] >= {:from}", params),
	}
	flowExpressions, err = appendStringSetExpression(flowExpressions, "id", requestedFlowIDs)
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}
	flows, flowMore, err := queryTimelinePage(app, "flows", flowExpressions, []string{"start", "id"}, limit, cursor["flows"])
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}
	episodes, episodeMore, err := queryTimelinePage(app, "activity_episodes", []dbx.Expression{
		dbx.HashExp{"session": sessionID},
		dbx.NewExp("[[start]] < {:to} AND [[last_seen]] >= {:from}", params),
	}, []string{"start", "id"}, limit, cursor["episodes"])
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}

	var dnsQueries []*core.Record
	var dnsMore bool
	var gateEvents []*core.Record
	var gateMore bool
	if !overview {
		dnsQueries, dnsMore, err = queryTimelinePage(app, "dns_queries", []dbx.Expression{
			dbx.HashExp{"session": sessionID},
			dbx.NewExp("[[timestamp]] >= {:lookback} AND [[timestamp]] < {:to}", dbx.Params{
				"lookback": formatPocketBaseTimelineDate(from.Add(-5 * time.Minute)),
				"to":       formatPocketBaseTimelineDate(to),
			}),
		}, []string{"timestamp", "id"}, limit, cursor["dns"])
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
		gateEvents, gateMore, err = queryTimelinePage(app, "gate_events", []dbx.Expression{
			dbx.HashExp{"session": sessionID},
			dbx.NewExp("[[queued_at]] >= {:from} AND [[queued_at]] < {:to}", params),
		}, []string{"queued_at", "id"}, limit, cursor["gates"])
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
	}

	var chunks []*core.Record
	var chunkMore bool
	var windows []*core.Record
	var windowMore bool
	if !overview {
		chunkExpressions := []dbx.Expression{
			dbx.HashExp{"session": sessionID},
			dbx.NewExp("[[chunk_start]] >= {:chunkOverlap} AND [[chunk_start]] < {:to}", dbx.Params{
				"chunkOverlap": formatPocketBaseTimelineDate(from.Add(-10 * time.Second)),
				"to":           formatPocketBaseTimelineDate(to),
			}),
		}
		chunkExpressions, err = appendStringSetExpression(chunkExpressions, "flow", requestedFlowIDs)
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
		chunks, chunkMore, err = queryTimelinePage(app, "flow_activity_chunks", chunkExpressions, []string{"chunk_start", "id"}, limit, cursor["chunks"])
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
		windows, windowMore, err = queryTimelinePage(app, "flow_activity_windows", []dbx.Expression{
			dbx.HashExp{"session": sessionID},
			dbx.NewExp("[[window_start]] >= {:windowOverlap} AND [[window_start]] < {:to}", dbx.Params{
				"windowOverlap": formatPocketBaseTimelineDate(from.Add(-time.Minute)),
				"to":            formatPocketBaseTimelineDate(to),
			}),
		}, []string{"window_start", "id"}, limit, cursor["windows"])
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
	}

	visibleFlowIDs := make([]string, 0, len(flows))
	destinationIPs := make([]string, 0, len(flows))
	seenIPs := map[string]bool{}
	for _, flow := range flows {
		visibleFlowIDs = append(visibleFlowIDs, flow.Id)
		ip := flow.GetString("destination_ip")
		if ip != "" && !seenIPs[ip] {
			seenIPs[ip] = true
			destinationIPs = append(destinationIPs, ip)
		}
	}
	attributions, err := queryRelatedRecords(app, "flow_attributions", "flow", visibleFlowIDs, "observed_at")
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}
	associations, err := queryRelatedRecords(app, "flow_associations", "flow", visibleFlowIDs, "observed_at")
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}
	destinations, err := queryRelatedRecords(app, "destinations", "ip", destinationIPs, "ip")
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}
	routes := []*core.Record{}
	if len(destinationIPs) > 0 {
		routeExpressions, expressionErr := appendStringSetExpression(
			[]dbx.Expression{dbx.HashExp{"session": sessionID}},
			"destination_ip",
			destinationIPs,
		)
		if expressionErr != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, expressionErr
		}
		routes, err = queryRecords(app, "routes", routeExpressions, "completed_at")
		if err != nil {
			return sessionTimelineWindow{}, http.StatusInternalServerError, err
		}
	}
	statuses, _, err := queryTimelinePage(app, "flow_activity_status", []dbx.Expression{
		dbx.HashExp{"session": sessionID},
	}, []string{"reported_at DESC"}, 1, 0)
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}

	advanceTimelineCursor(cursor, "flows", flowMore, limit)
	advanceTimelineCursor(cursor, "episodes", episodeMore, limit)
	if !overview {
		advanceTimelineCursor(cursor, "dns", dnsMore, limit)
		advanceTimelineCursor(cursor, "chunks", chunkMore, limit)
		advanceTimelineCursor(cursor, "windows", windowMore, limit)
		advanceTimelineCursor(cursor, "gates", gateMore, limit)
	}
	nextCursor, err := encodeTimelineCursor(cursor)
	if err != nil {
		return sessionTimelineWindow{}, http.StatusInternalServerError, err
	}

	return sessionTimelineWindow{
		Range: timelineRange{
			From: from.UTC().Format(time.RFC3339Nano),
			To:   to.UTC().Format(time.RFC3339Nano),
		},
		LOD:                  lod,
		Watermark:            time.Now().UTC().Format(time.RFC3339Nano),
		Flows:                exportRecords(flows),
		DNSQueries:           exportRecords(dnsQueries),
		Attributions:         exportRecords(attributions),
		ActivityEpisodes:     exportRecords(episodes),
		FlowAssociations:     exportRecords(associations),
		FlowActivityChunks:   exportActivityRecords(chunks, lodMS),
		FlowActivityWindows:  exportRecords(windows),
		FlowActivityStatuses: exportRecords(statuses),
		Destinations:         exportRecords(destinations),
		Routes:               exportRecords(routes),
		GateEvents:           exportRecords(gateEvents),
		NextCursor:           nextCursor,
	}, http.StatusOK, nil
}

func queryTimelinePage(app core.App, collection string, expressions []dbx.Expression, sortFields []string, limit, offset int) ([]*core.Record, bool, error) {
	if offset < 0 {
		return []*core.Record{}, false, nil
	}
	records, err := queryRecordsPage(app, collection, expressions, sortFields, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	more := len(records) > limit
	if more {
		records = records[:limit]
	}
	return records, more, nil
}

func queryRelatedRecords(app core.App, collection, field string, values []string, sortFields string) ([]*core.Record, error) {
	if len(values) == 0 {
		return []*core.Record{}, nil
	}
	expressions, err := appendStringSetExpression(nil, field, values)
	if err != nil {
		return nil, err
	}
	return queryRecords(app, collection, expressions, sortFields)
}

func queryRecords(app core.App, collection string, expressions []dbx.Expression, sortFields ...string) ([]*core.Record, error) {
	return queryRecordsPage(app, collection, expressions, sortFields, 0, 0)
}

func queryRecordsPage(app core.App, collection string, expressions []dbx.Expression, sortFields []string, limit, offset int) ([]*core.Record, error) {
	query := app.RecordQuery(collection)
	for _, expression := range expressions {
		query.AndWhere(expression)
	}
	if len(sortFields) > 0 {
		query.OrderBy(sortFields...)
	}
	if limit > 0 {
		query.Limit(int64(limit))
	}
	if offset > 0 {
		query.Offset(int64(offset))
	}

	records := []*core.Record{}
	if err := query.All(&records); err != nil {
		return nil, fmt.Errorf("query %s: %w", collection, err)
	}
	return records, nil
}

// appendStringSetExpression keeps set membership constant-sized by passing the
// values as one JSON parameter. Fields are internal schema constants, never
// request-provided identifiers; set values remain bound query parameters.
func appendStringSetExpression(expressions []dbx.Expression, field string, values []string) ([]dbx.Expression, error) {
	if len(values) == 0 {
		return expressions, nil
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode %s value set: %w", field, err)
	}
	return append(expressions, dbx.NewExp(
		fmt.Sprintf("[[%s]] IN (SELECT value FROM json_each({:valueSet}))", field),
		dbx.Params{"valueSet": string(payload)},
	)), nil
}

func exportRecords(records []*core.Record) []map[string]any {
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		result = append(result, record.PublicExport())
	}
	return result
}

func exportActivityRecords(records []*core.Record, targetBucketMS int) []map[string]any {
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		exported := record.PublicExport()
		if targetBucketMS > 0 {
			exported = aggregateActivityRecord(exported, targetBucketMS)
		}
		result = append(result, exported)
	}
	return result
}

func aggregateActivityRecord(record map[string]any, targetBucketMS int) map[string]any {
	raw, err := json.Marshal(record["samples"])
	if err != nil {
		return record
	}
	payload := activitySamplePayload{}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Version != 1 || payload.BucketMS <= 0 || targetBucketMS <= payload.BucketMS {
		return record
	}
	if payload.ChunkMS <= 0 || targetBucketMS > payload.ChunkMS {
		targetBucketMS = payload.ChunkMS
	}
	type totals [4]int64
	bins := map[int64]totals{}
	for _, sample := range payload.Samples {
		if len(sample) < 5 || sample[0] < 0 {
			continue
		}
		offset := (sample[0] / int64(targetBucketMS)) * int64(targetBucketMS)
		value := bins[offset]
		for index := 0; index < 4; index++ {
			if sample[index+1] > 0 {
				value[index] += sample[index+1]
			}
		}
		bins[offset] = value
	}
	offsets := make([]int64, 0, len(bins))
	for offset := range bins {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	aggregated := make([][]int64, 0, len(offsets))
	for _, offset := range offsets {
		value := bins[offset]
		aggregated = append(aggregated, []int64{offset, value[0], value[1], value[2], value[3]})
	}
	payload.BucketMS = targetBucketMS
	payload.Samples = aggregated
	record["bucket_ms"] = targetBucketMS
	record["samples"] = payload
	return record
}

func parseTimelineTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("value is required")
	}
	if milliseconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.UnixMilli(milliseconds).UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected epoch milliseconds or RFC3339")
	}
	return parsed.UTC(), nil
}

func parseTimelineLOD(value string) (string, int, bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "50ms", "raw":
		return "50ms", 50, false, nil
	case "500ms":
		return "500ms", 500, false, nil
	case "1s", "1000ms":
		return "1s", 1000, false, nil
	case "5s", "5000ms":
		return "5s", 5000, false, nil
	case "overview":
		return "overview", 0, true, nil
	default:
		return "", 0, false, fmt.Errorf("lod must be one of 50ms, 500ms, 1s, 5s, or overview")
	}
}

func parseFlowIDs(value string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		id := strings.TrimSpace(item)
		if id != "" && !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}

func decodeTimelineCursor(value string, overview bool) (timelineCursor, error) {
	cursor := timelineCursor{"flows": 0, "episodes": 0, "dns": 0, "chunks": 0, "windows": 0, "gates": 0}
	if overview {
		cursor["dns"] = -1
		cursor["chunks"] = -1
		cursor["windows"] = -1
		cursor["gates"] = -1
	}
	if value == "" {
		return cursor, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(raw, &cursor) != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	for _, key := range []string{"flows", "episodes", "dns", "chunks", "windows", "gates"} {
		if _, ok := cursor[key]; !ok || cursor[key] < -1 {
			return nil, fmt.Errorf("invalid cursor")
		}
	}
	return cursor, nil
}

func encodeTimelineCursor(cursor timelineCursor) (*string, error) {
	for _, value := range cursor {
		if value >= 0 {
			raw, err := json.Marshal(cursor)
			if err != nil {
				return nil, err
			}
			encoded := base64.RawURLEncoding.EncodeToString(raw)
			return &encoded, nil
		}
	}
	return nil, nil
}

func advanceTimelineCursor(cursor timelineCursor, key string, more bool, limit int) {
	if cursor[key] < 0 {
		return
	}
	if more {
		cursor[key] += limit
	} else {
		cursor[key] = -1
	}
}

func firstQueryValue(values map[string][]string, key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return values[key][0]
}

func formatPocketBaseTimelineDate(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04:05.000Z")
}
