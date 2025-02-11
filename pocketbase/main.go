package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

// Hop represents a single hop in the traceroute output
type Hop struct {
	TTL     int       // Hop number
	Address string    // IP or Hostname
	Timings []float64 // Latency timings in milliseconds

	// NEW: Add fields to store geolocation data
	Latitude  float64
	Longitude float64
	City      string
	Country   string
}

// RunTraceroute executes the traceroute command and returns parsed hops
func RunTraceroute(hostname string) ([]Hop, error) {
	var cmd *exec.Cmd

	// Select command based on OS
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tracert", hostname) // Windows
	} else {
		cmd = exec.Command("traceroute", hostname) // macOS/Linux
	}

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run traceroute: %v", err)
	}

	// Parse the output and extract hops
	hops := parseTracerouteOutput(string(output))
	return hops, nil
}

// parseTracerouteOutput extracts hop details and converts timings to floats
func parseTracerouteOutput(output string) []Hop {
	lines := strings.Split(output, "\n")
	hops := []Hop{}

	// Regex pattern to match typical lines, e.g.:
	//   "1  192.168.1.1  1.2 ms  2.3 ms  3.1 ms"
	re := regexp.MustCompile(`^\s*(\d+)\s+([\d\.a-zA-Z\-\*]+)\s+(.*)$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			ttl := parseInt(matches[1])         // Hop number
			address := matches[2]               // IP or Hostname
			timings := parseTimings(matches[3]) // Convert timings to float slice

			hops = append(hops, Hop{
				TTL:     ttl,
				Address: address,
				Timings: timings,
			})
		}
	}

	return hops
}

// parseInt converts a string to an integer
func parseInt(str string) int {
	num, _ := strconv.Atoi(str)
	return num
}

// parseTimings extracts multiple timings from a string and converts them to float64
func parseTimings(timingStr string) []float64 {
	timingStr = strings.ReplaceAll(timingStr, " ms", "") // Remove "ms" suffix
	parts := strings.Fields(timingStr)                   // Split by whitespace
	var timings []float64

	for _, part := range parts {
		if num, err := strconv.ParseFloat(part, 64); err == nil {
			timings = append(timings, num)
		}
	}

	return timings
}

// NEW: geolocateHops populates the latitude/longitude/city/country for each hop.
// It tries to parse the hop's Address as an IP; if that fails, it attempts a DNS lookup.
// You can refine the logic to skip lines like "* * *" if that is typical in your traceroute output.
func geolocateHops(hops []Hop, geoipDB *geoip2.Reader) {
	for i := range hops {
		rawAddr := hops[i].Address
		// traceroute might sometimes produce lines like "* * *", or domain names, or IP addresses.

		// Skip placeholders like "* * *"
		if strings.Contains(rawAddr, "*") {
			continue
		}

		ip := net.ParseIP(rawAddr)
		// If not a direct IP, attempt a DNS lookup
		if ip == nil {
			addrs, err := net.LookupIP(rawAddr)
			if err != nil || len(addrs) == 0 {
				continue
			}
			ip = addrs[0]
		}
		// Now attempt the geolocation
		if ip == nil {
			continue
		}

		cityRecord, err := geoipDB.City(ip)
		if err != nil {
			continue
		}

		hops[i].Latitude = cityRecord.Location.Latitude
		hops[i].Longitude = cityRecord.Location.Longitude
		hops[i].City = cityRecord.City.Names["en"]
		hops[i].Country = cityRecord.Country.Names["en"]
	}
}

// createTracerouteRecord is a helper to store traceroute results in PocketBase.
func createTracerouteRecord(sessionID, domain string, hops []Hop, app *pocketbase.PocketBase) error {
	// If you have a "traceroutes" collection, do something like this:
	collection, err := app.FindCollectionByNameOrId("traceroutes")
	if err != nil {
		log.Printf("createTracerouteRecord: collection error: %s", err)
		return err
	}

	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("domain", domain)

	// Convert each Hop struct to a map so we can store it in PB. For example:
	var hopData []map[string]interface{}
	for _, h := range hops {
		hopData = append(hopData, map[string]interface{}{
			"ttl":       h.TTL,
			"address":   h.Address,
			"timings":   h.Timings,
			"latitude":  h.Latitude,
			"longitude": h.Longitude,
			"city":      h.City,
			"country":   h.Country,
		})
	}
	record.Set("hops", hopData)

	err = app.Save(record)
	if err != nil {
		log.Printf("createTracerouteRecord: save error: %s", err)
		return err
	}

	return nil
}

// Global pointer tracking active session
var active_session_id *string

// We'll keep a global map to track which hostnames we've seen for the current session
var sessionHostnames sync.Map // key=string (hostname), value=bool

func main() {
	app := pocketbase.New()

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		se.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))
		return se.Next()
	})

	geoipDB, _ := geoip2.Open("./geoip/city.mmdb")
	defer geoipDB.Close()

	// Watch session creation/updates
	go func() {
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
	}()

	// Start listening for traffic on :1337
	go func() {
		l, err := net.Listen("tcp", ":1337")
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Print(err)
				continue
			}
			go handleConnection(conn, app, geoipDB)
		}
	}()

	// Wait for SIGINT or SIGTERM
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
}

// clearSessionHostnames empties the global map when a new session starts
func clearSessionHostnames() {
	sessionHostnames.Range(func(key, value any) bool {
		sessionHostnames.Delete(key)
		return true
	})
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()
	if hello == nil {
		return nil, err
	}
	return hello, nil
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
	if isTLSHandshake(peekBuf) {
		clientHello, clientReader, err := peekClientHello(peekedReader)
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

func isTLSHandshake(data []byte) bool {
	// TLS handshake typically starts with 0x16
	return len(data) > 0 && data[0] == 0x16
}

func pipeTraffic(clientConn net.Conn, backendConn net.Conn, clientReader io.Reader, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, hostname string) {
	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		log.Print(err)
		return
	}

	// Create the packet record for this flow
	recordID, err := createPacketRecord(clientIP, stripPort(hostname), app, geoipDB)
	if err != nil {
		log.Printf("Failed to create packet record: %s", err)
	}

	// If this is a new hostname in the current session, run traceroute & geolocate in background.
	if active_session_id != nil && recordID != "" {
		hn := stripPort(hostname)
		if _, loaded := sessionHostnames.LoadOrStore(hn, true); !loaded {
			go func(sid, h string) {
				// Perform traceroute
				hops, err := RunTraceroute(h)
				if err != nil {
					log.Printf("Traceroute error for host %s: %v", h, err)
					return
				}
				// Geolocate each hop
				geolocateHops(hops, geoipDB)

				// Store results in PB
				if err := createTracerouteRecord(sid, h, hops, app); err != nil {
					log.Printf("Failed to store traceroute for %s: %v", h, err)
				}
			}(*active_session_id, hn)
		}
	}

	// Create an aggregator for recording in/out bytes
	aggregator := NewAggregator(recordID, app)

	// Flush aggregator once per second
	flushTicker := time.NewTicker(1 * time.Second)
	done := make(chan struct{})
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

	var wg sync.WaitGroup
	wg.Add(2)

	// Flow: client -> backend
	go func() {
		err := copyAndUpdate(backendConn, clientReader, "out", aggregator)
		if err != nil {
			log.Printf("Error in client->backend: %s", err)
		}
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	// Flow: backend -> client
	go func() {
		err := copyAndUpdate(clientConn, backendConn, "in", aggregator)
		if err != nil {
			log.Printf("Error in backend->client: %s", err)
		}
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()
	close(done)
	flushTicker.Stop()

	// Final flush
	aggregator.Flush()

	// Mark the packet record as inactive
	if recordID != "" {
		if err := closePacketRecord(recordID, app); err != nil {
			log.Printf("Failed to update packet record: %s", err)
		}
	}
}

// createPacketRecord is your existing function that logs a new 'packets' record
func createPacketRecord(clientIP string, hostname string, app *pocketbase.PocketBase, geoipDB *geoip2.Reader) (string, error) {
	if active_session_id == nil {
		return "", nil
	}

	hostIPs, lookupErr := net.LookupIP(hostname)
	if lookupErr != nil {
		log.Printf("lookup error: %s", lookupErr)
		return "", lookupErr
	}

	var hostIP net.IP
	for _, ip := range hostIPs {
		if ip.To4() != nil {
			hostIP = ip
			break
		}
	}

	if hostIP == nil {
		log.Printf("no IPv4 address found for host: %s", hostname)
		return "", nil
	}

	geoRecord, geoErr := geoipDB.City(hostIP)
	if geoErr != nil {
		log.Printf("geoip error: %s", geoErr)
		return "", geoErr
	}

	collection, err := app.FindCollectionByNameOrId("packets")
	if err != nil {
		log.Printf("collection error: %s", err)
		return "", err
	}

	record := core.NewRecord(collection)
	record.Set("session", *active_session_id)
	record.Set("active", true)
	record.Set("client_ip", clientIP)
	record.Set("host", hostname)
	record.Set("lat", geoRecord.Location.Latitude)
	record.Set("lon", geoRecord.Location.Longitude)
	record.Set("data", []interface{}{})
	record.Set("city", geoRecord.City.Names["en"])
	record.Set("country", geoRecord.Country.Names["en"])

	err = app.Save(record)
	if err != nil {
		log.Printf("save error: %s", err)
		return "", err
	}

	return record.Id, nil
}

type Aggregator struct {
	mu       sync.Mutex
	inCount  int64
	outCount int64
	entries  []interface{}
	recordID string
	app      *pocketbase.PocketBase
}

func NewAggregator(recordID string, app *pocketbase.PocketBase) *Aggregator {
	return &Aggregator{
		inCount:  0,
		outCount: 0,
		entries:  make([]interface{}, 0),
		recordID: recordID,
		app:      app,
	}
}

func (a *Aggregator) Add(direction string, n int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if direction == "in" {
		a.inCount += n
	} else if direction == "out" {
		a.outCount += n
	}
}

func (a *Aggregator) Flush() {
	now := time.Now().Format(time.RFC3339)
	a.mu.Lock()
	if a.inCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "in",
			"bytes": a.inCount,
		}
		a.entries = append(a.entries, entry)
		a.inCount = 0
	}
	if a.outCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "out",
			"bytes": a.outCount,
		}
		a.entries = append(a.entries, entry)
		a.outCount = 0
	}
	currentEntries := make([]interface{}, len(a.entries))
	copy(currentEntries, a.entries)
	a.mu.Unlock()

	// Update the record with the aggregator data
	if err := updatePacketRecordDataWithAccumulator(a.recordID, currentEntries, a.app); err != nil {
		log.Printf("Failed to update aggregator for record %s: %s", a.recordID, err)
	}
}

func updatePacketRecordDataWithAccumulator(recordID string, entries []interface{}, app *pocketbase.PocketBase) error {
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("updatePacketRecordDataWithAccumulator: could not find record %s: %s", recordID, err)
		return err
	}
	record.Set("data", entries)
	if err := app.Save(record); err != nil {
		log.Printf("updatePacketRecordDataWithAccumulator: save error: %s", err)
		return err
	}
	return nil
}

func closePacketRecord(recordID string, app *pocketbase.PocketBase) error {
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("closePacketRecord: could not find record %s: %s", recordID, err)
		return err
	}
	record.Set("active", false)
	err = app.Save(record)
	if err != nil {
		log.Printf("closePacketRecord: save error: %s", err)
		return err
	}
	return nil
}

// copyAndUpdate transfers data and updates the aggregator in/out counters.
func copyAndUpdate(dst io.Writer, src io.Reader, direction string, aggregator *Aggregator) error {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			if written > 0 {
				aggregator.Add(direction, int64(written))
			}
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// stripPort strips a port if present (e.g. "example.com:443" -> "example.com")
func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// no port part
		return hostPort
	}
	return host
}
