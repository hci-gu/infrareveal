package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"myapp/debugtrace"
	"myapp/labgate"
	"myapp/lib"
	_ "myapp/migrations"
	"myapp/observer"
)

// Global pointer tracking active session
var active_session_id *string

// We'll keep a global map to track which hostnames we've seen for the current session
var sessionHostnames sync.Map // key=string (hostname), value=bool
var observationClearMu sync.Mutex
var conntrackSampler *observer.ConntrackSampler

func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// no port part
		return hostPort
	}
	return host
}

// generateDebugData creates synthetic network traffic data for testing
func generateDebugData(app *pocketbase.PocketBase, geoipDB *geoip2.Reader) {
	// Common domains to simulate traffic to
	domains := []string{
		"google.com",
		"facebook.com",
		"amazon.com",
		"netflix.com",
		"github.com",
	}

	// Create a new debug session
	collection, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		log.Printf("Failed to find sessions collection: %v", err)
		return
	}

	sessionRecord := core.NewRecord(collection)
	sessionRecord.Set("active", true)
	sessionRecord.Set("name", "Debug Session")

	if err := app.Save(sessionRecord); err != nil {
		log.Printf("Failed to create debug session: %v", err)
		return
	}

	// Simulate traffic for each domain
	for _, domain := range domains {
		// Create packet record
		recordID, err := lib.CreatePacketRecord(sessionRecord.Id, "192.168.1.100", domain, app, geoipDB)
		if err != nil {
			log.Printf("Failed to create packet record for %s: %v", domain, err)
			continue
		}

		// Run traceroute
		if err := lib.RunTraceroute(sessionRecord.Id, app, geoipDB, domain); err != nil {
			log.Printf("Traceroute error for %s: %v", domain, err)
		}

		// Simulate packet data
		aggregator := lib.NewPacketAggregator(recordID, app)

		// Simulate some traffic over time
		for i := 0; i < 5; i++ {
			aggregator.Add("in", int64(1000+rand.Intn(5000)))
			aggregator.Add("out", int64(500+rand.Intn(2000)))
			aggregator.Flush()
			time.Sleep(time.Second)
		}

		// Close the packet record
		if err := lib.ClosePacketRecord(recordID, app); err != nil {
			log.Printf("Failed to close packet record: %v", err)
		}

		// Add some delay between domains
		time.Sleep(time.Second * 2)
	}

	// Deactivate the debug session
	sessionRecord.Set("active", false)
	if err := app.Save(sessionRecord); err != nil {
		log.Printf("Failed to deactivate debug session: %v", err)
	}
}

func main() {
	app := pocketbase.New()
	ctx, cancelObservers := context.WithCancel(context.Background())
	defer cancelObservers()
	traceConfig := debugtrace.ConfigFromEnv()
	traceConfig.LogEffective()
	traceHub, traceSink := debugtrace.NewRuntime(context.Background(), traceConfig)
	if traceHub != nil {
		defer traceHub.Close()
	}
	gateConfig := labgate.ConfigFromEnv()
	gateConfig.LogEffective()
	var gateAudit labgate.AuditSink = labgate.NopAuditSink{}
	var gateAuditWriter *labgate.AuditWriter
	if gateConfig.Enabled {
		gateAuditWriter = labgate.NewAuditWriter(app, 512)
		gateAudit = gateAuditWriter
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = gateAuditWriter.Close(closeCtx)
		}()
	}
	clientSubnetText := envOrDefault("LAB_GATE_CLIENT_SUBNET", "10.0.0.0/24")
	clientSubnet, subnetErr := netip.ParsePrefix(clientSubnetText)
	if subnetErr != nil {
		log.Fatalf("invalid LAB_GATE_CLIENT_SUBNET: %v", subnetErr)
	}
	var controlToken []byte
	if gateConfig.ControlTokenFile != "" {
		loadedToken, tokenErr := labgate.LoadControlToken(gateConfig.ControlTokenFile)
		if tokenErr != nil {
			log.Printf("lab gate controls unavailable: %v", tokenErr)
		} else {
			controlToken = loadedToken
		}
	}
	gateController, err := newLabGateRuntime(
		context.Background(), gateConfig, traceSink,
		envOrDefault("AP_IFACE", "wlan0"), envOrDefault("INTERNET_IFACE", "eth0"),
		clientSubnetText, gateAudit,
	)
	if err != nil {
		log.Fatalf("invalid lab gate configuration: %v", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = gateController.Close(closeCtx)
	}()

	geoipDB, _ := geoip2.Open("./geoip/city.mmdb")
	if geoipDB != nil {
		defer geoipDB.Close()
	}

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		registerSessionTimelineRoutes(se.Router, app)
		debugtrace.RegisterRoutes(se.Router, app, traceHub)
		labgate.RegisterControlRoutes(se.Router, app, gateController, labgate.ControlRouteConfig{
			Token: controlToken, AllowedOrigins: gateConfig.AllowedOrigins, ClientSubnet: clientSubnet,
		})
		se.Router.POST("/api/infrareveal/clear-observations", func(e *core.RequestEvent) error {
			result, err := clearObservationCollections(app)
			if err != nil {
				return e.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			clearSessionHostnames()
			return e.JSON(http.StatusOK, result)
		})
		se.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))

		if err := ensureDefaultActiveSession(app); err != nil {
			log.Printf("failed to ensure active gateway session: %v", err)
		}

		dnsmasqLogPath := envOrDefault("DNSMASQ_LOG_PATH", "/var/log/dnsmasq.log")
		conntrackPath := envOrDefault("CONNTRACK_PATH", "/proc/net/nf_conntrack")
		clientPrefix := envOrDefault("CLIENT_IP_PREFIX", "10.0.0.")
		gatewayIP := envOrDefault("GATEWAY_IP", "10.0.0.1")
		apInterface := envOrDefault("AP_IFACE", "wlan0")
		observationScope := observer.NewObservationScope(clientPrefix, gatewayIP)

		observer.StartDNSMasqIngestor(ctx, app, dnsmasqLogPath, currentSessionID, traceSink)
		conntrackSampler = observer.StartConntrackSampler(ctx, app, conntrackPath, observationScope, currentSessionID, traceSink)
		observer.StartPacketActivityObserver(
			ctx,
			app,
			observationScope,
			currentSessionID,
			observer.PacketActivityConfigFromEnv(apInterface),
			traceSink,
		)
		observer.StartFlowCorrelator(ctx, app, observationScope, currentSessionID, traceSink)
		observer.StartDestinationEnricher(ctx, app, geoipDB, observationScope, currentSessionID, traceSink)

		return se.Next()
	})

	app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := gateController.Close(closeCtx); err != nil {
			log.Printf("lab gate shutdown: %v", err)
		}
		cancel()
		if gateAuditWriter != nil {
			auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := gateAuditWriter.Close(auditCtx); err != nil {
				log.Printf("lab gate audit shutdown: %v", err)
			}
			auditCancel()
		}
		cancelObservers()
		traceHub.Close()
		return e.Next()
	})

	app.OnRecordCreate("sessions").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetDateTime("started_at").IsZero() {
			e.Record.Set("started_at", time.Now().UTC().Format(time.RFC3339Nano))
		}
		if e.Record.GetBool("active") {
			e.Record.Set("ended_at", "")
		}
		e.Record.Set("gate_audit_complete", true)
		e.Record.Set("gate_audit_drops", 0)
		return e.Next()
	})

	app.OnRecordUpdate("sessions").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetBool("active") {
			e.Record.Set("ended_at", "")
			e.Record.Set("gate_audit_complete", true)
			e.Record.Set("gate_audit_drops", 0)
		} else if e.Record.GetDateTime("ended_at").IsZero() {
			statusCtx, statusCancel := context.WithTimeout(context.Background(), 2*time.Second)
			status, statusErr := gateController.Status(statusCtx)
			if statusErr == nil && status.Armed && status.SessionID == e.Record.Id {
				if _, disarmErr := gateController.Disarm(statusCtx); disarmErr != nil {
					log.Printf("lab gate session-end disarm: %v", disarmErr)
				}
			}
			statusCancel()
			if gateAuditWriter != nil {
				auditCtx, auditCancel := context.WithTimeout(context.Background(), 3*time.Second)
				if flushErr := gateAuditWriter.Flush(auditCtx); flushErr != nil {
					log.Printf("lab gate audit flush for session %s: %v", e.Record.Id, flushErr)
				}
				drops := gateAuditWriter.DroppedForSession(e.Record.Id)
				e.Record.Set("gate_audit_complete", drops == 0)
				e.Record.Set("gate_audit_drops", drops)
				auditCancel()
			}
			e.Record.Set("ended_at", time.Now().UTC().Format(time.RFC3339Nano))
		}
		return e.Next()
	})

	// Watch session creation/updates
	app.OnRecordAfterCreateSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
		id := e.Record.GetString("id")
		if e.Record.GetBool("active") {
			active_session_id = &id
			// Clear map of seen hostnames on new session
			clearSessionHostnames()
		}
		return e.Next()
	})

	app.OnRecordAfterUpdateSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
		if !e.Record.GetBool("active") {
			active_session_id = nil
		} else {
			id := e.Record.GetString("id")
			active_session_id = &id
			clearSessionHostnames()
		}
		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func currentSessionID() string {
	if active_session_id == nil {
		return ""
	}
	return *active_session_id
}

func ensureDefaultActiveSession(app *pocketbase.PocketBase) error {
	record, err := app.FindFirstRecordByFilter("sessions", "active=true")
	if err == nil {
		id := record.Id
		active_session_id = &id
		return nil
	}
	if !strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
		return err
	}

	collection, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		return err
	}
	record = core.NewRecord(collection)
	record.Set("name", "Gateway Session")
	record.Set("active", true)
	if err := app.Save(record); err != nil {
		return err
	}
	id := record.Id
	active_session_id = &id
	return nil
}

// clearSessionHostnames empties the global map when a new session starts
func clearSessionHostnames() {
	sessionHostnames.Range(func(key, value any) bool {
		sessionHostnames.Delete(key)
		return true
	})
}

type clearObservationsResult struct {
	Deleted map[string]int `json:"deleted"`
	Skipped []string       `json:"skipped"`
}

func clearObservationCollections(app *pocketbase.PocketBase) (clearObservationsResult, error) {
	observationClearMu.Lock()
	defer observationClearMu.Unlock()

	previousActiveSessionID := active_session_id
	active_session_id = nil
	defer func() {
		active_session_id = previousActiveSessionID
	}()
	if conntrackSampler != nil {
		if err := conntrackSampler.SuppressCurrentFlows(); err != nil {
			return clearObservationsResult{}, fmt.Errorf("snapshot active conntrack flows before clearing: %w", err)
		}
	}

	result := clearObservationsResult{
		Deleted: map[string]int{},
		Skipped: []string{},
	}
	skipped := map[string]bool{}
	collections := []string{
		"gate_events",
		"flow_activity_chunks",
		"flow_activity_windows",
		"flow_activity_status",
		"flow_associations",
		"activity_episodes",
		"flow_attributions",
		"routes",
		"traceroutes",
		"packets",
		"flows",
		"dns_queries",
		"destinations",
		"clients",
	}

	var lastErr error
	for pass := 0; pass < 8; pass++ {
		deletedThisPass := 0
		lastErr = nil

		for _, name := range collections {
			if _, err := app.FindCollectionByNameOrId(name); err != nil {
				if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
					if !skipped[name] {
						result.Skipped = append(result.Skipped, name)
						skipped[name] = true
					}
					continue
				}
				return result, err
			}

			records, err := app.FindAllRecords(name)
			if err != nil {
				return result, err
			}

			for _, record := range records {
				if err := app.Delete(record); err != nil {
					lastErr = err
					continue
				}
				result.Deleted[name]++
				deletedThisPass++
			}
		}

		if deletedThisPass == 0 {
			if lastErr != nil {
				return result, fmt.Errorf("clear observations stalled because records are still referenced: %w", lastErr)
			}
			return result, nil
		}
	}

	if lastErr != nil {
		return result, fmt.Errorf("clear observations did not finish after retries: %w", lastErr)
	}

	return result, nil
}

func isExpectedProxyClose(err error) bool {
	if err == nil || err == io.EOF {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection")
}

func logUnexpectedCopyError(direction string, err error) {
	if !isExpectedProxyClose(err) {
		log.Printf("Error in %s: %s", direction, err)
	}
}

func handleConnection(clientConn net.Conn, app *pocketbase.PocketBase, geoipDB *geoip2.Reader) {
	defer clientConn.Close()

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Print(err)
		return
	}

	// Peek first bytes to decide if connection is TLS
	peekBuf := make([]byte, 5)
	n, err := clientConn.Read(peekBuf)
	if err != nil {
		log.Print(err)
		return
	}
	// Reset deadline
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Print(err)
		return
	}

	peekedReader := io.MultiReader(bytes.NewReader(peekBuf[:n]), clientConn)

	// Check for TLS
	if lib.IsTLSHandshake(peekBuf) {
		clientHello, clientReader, err := lib.PeekClientHello(peekedReader)
		if err != nil {
			log.Print(err)
			return
		}

		log.Printf("TLS traffic for ServerName: %s", clientHello.ServerName)

		backendConn, err := net.DialTimeout("tcp", net.JoinHostPort(clientHello.ServerName, "443"), 5*time.Second)
		if err != nil {
			log.Print(err)
			return
		}
		defer backendConn.Close()

		pipeTraffic(clientConn, backendConn, clientReader, app, geoipDB, clientHello.ServerName)
	} else {
		// Handle plaintext (e.g., HTTP)
		log.Print("Non-TLS traffic detected")
		buf := new(bytes.Buffer)
		teeReader := io.TeeReader(peekedReader, buf)

		req, err := http.ReadRequest(bufio.NewReader(teeReader))
		if err != nil {
			log.Printf("Failed to parse HTTP request: %s", err)
			return
		}

		hostname := req.Host
		if _, _, err := net.SplitHostPort(hostname); err != nil {
			hostname = net.JoinHostPort(hostname, "80")
		}

		backendConn, err := net.DialTimeout("tcp", hostname, 5*time.Second)
		if err != nil {
			log.Printf("Failed to connect to backend: %s", err)
			return
		}
		defer backendConn.Close()

		fullRequestReader := io.MultiReader(bytes.NewReader(buf.Bytes()), clientConn)
		pipeTraffic(clientConn, backendConn, fullRequestReader, app, geoipDB, hostname)
	}
}

func pipeTraffic(clientConn net.Conn, backendConn net.Conn, clientReader io.Reader, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, hostname string) {
	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		log.Print(err)
		return
	}

	var aggregator *lib.PacketAggregator
	recordIDCh := make(chan string, 1)

	if active_session_id != nil {
		sessionID := *active_session_id
		hn := stripPort(hostname)
		aggregator = lib.NewPacketAggregator("", app)

		go func() {
			recordID, err := lib.CreatePacketRecord(sessionID, clientIP, hn, app, geoipDB)
			if err != nil {
				log.Printf("Failed to create packet record: %s", err)
				recordIDCh <- ""
				return
			}
			if recordID == "" {
				recordIDCh <- ""
				return
			}

			aggregator.SetRecordID(recordID)
			aggregator.Flush()
			recordIDCh <- recordID

			// If this is a new hostname in the current session, run traceroute & geolocate in background.
			if _, loaded := sessionHostnames.LoadOrStore(hn, true); !loaded {
				go func() {
					if err := lib.RunTraceroute(sessionID, app, geoipDB, hn); err != nil {
						log.Printf("Traceroute error for host %s: %v", hn, err)
					}
				}()
			}
		}()
	} else {
		recordIDCh <- ""
	}

	var flushTicker *time.Ticker
	done := make(chan struct{})
	if aggregator != nil {
		flushTicker = time.NewTicker(1 * time.Second)
		go func() {
			for {
				select {
				case <-flushTicker.C:
					aggregator.Flush()
				case <-done:
					return
				}
			}
		}()
	}

	copyTraffic := func(dst io.Writer, src io.Reader, direction string) error {
		if aggregator != nil {
			return lib.CopyAndUpdatePacket(dst, src, direction, aggregator)
		}
		_, err := io.Copy(dst, src)
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Flow: client -> backend
	go func() {
		defer wg.Done()
		if err := copyTraffic(backendConn, clientReader, "out"); err != nil {
			logUnexpectedCopyError("client->backend", err)
		}
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Flow: backend -> client
	go func() {
		defer wg.Done()
		if err := copyTraffic(clientConn, backendConn, "in"); err != nil {
			logUnexpectedCopyError("backend->client", err)
		}
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()

	if aggregator != nil {
		close(done)
		flushTicker.Stop()

		// Final flush
		aggregator.Flush()

		select {
		case recordID := <-recordIDCh:
			aggregator.Flush()
			if recordID == "" {
				return
			}
			if err := lib.ClosePacketRecord(recordID, app); err != nil {
				log.Printf("Failed to update packet record: %s", err)
			}
		case <-time.After(2 * time.Second):
			log.Printf("Packet record creation still pending for host %s", stripPort(hostname))
		}
	}
}
