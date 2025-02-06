package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

var active_session_id *string

func main() {
	app := pocketbase.New()

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		se.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))
		return se.Next()
	})

	geoipDB, _ := geoip2.Open("./geoip/city.mmdb")
	defer geoipDB.Close()

	go func() {
		app.OnRecordAfterCreateSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
			id := e.Record.Get("id").(string)
			if e.Record.Get("active") == true {
				active_session_id = &id
			}
			return e.Next()
		})

		app.OnRecordAfterUpdateSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
			// if record.ended is set, then we need to update the session_id
			if e.Record.Get("active") == false {
				active_session_id = nil
			}
			if e.Record.Get("active") == true {
				id := e.Record.Get("id").(string)
				active_session_id = &id
			}
			return e.Next()
		})

		if err := app.Start(); err != nil {
			log.Fatal(err)
		}
	}()

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

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
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

// Flush is called once per second to finalize the current bucket.
// It creates one entry per direction (if there is any data), appends those entries
// to the aggregator’s entries slice, resets the counters, and then updates PocketBase.
func (a *Aggregator) Flush() {
	now := time.Now().Format(time.RFC3339)
	a.mu.Lock()
	// If we have any inbound bytes, create an "in" entry.
	if a.inCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "in",
			"bytes": a.inCount,
		}
		a.entries = append(a.entries, entry)
		a.inCount = 0
	}
	// Similarly for outbound.
	if a.outCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "out",
			"bytes": a.outCount,
		}
		a.entries = append(a.entries, entry)
		a.outCount = 0
	}
	// Make a copy of the entries to use for updating the record.
	currentEntries := make([]interface{}, len(a.entries))
	copy(currentEntries, a.entries)
	a.mu.Unlock()

	// Update the PocketBase record with the full accumulator.
	if err := updatePacketRecordDataWithAccumulator(a.recordID, currentEntries, a.app); err != nil {
		log.Printf("Failed to update aggregator for record %s: %s", a.recordID, err)
	}
}

// updatePacketRecordDataWithAccumulator writes the entire shared accumulator to the record.
func updatePacketRecordDataWithAccumulator(recordID string, entries []interface{}, app *pocketbase.PocketBase) error {
	// Fetch the record.
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("updatePacketRecordDataWithAccumulator: could not find record %s: %s", recordID, err)
		return err
	}
	// Replace the "data" field with the full entries array.
	record.Set("data", entries)
	// Save the record.
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

func handleConnection(clientConn net.Conn, app *pocketbase.PocketBase, geoipDB *geoip2.Reader) {
	defer clientConn.Close()

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Print(err)
		return
	}

	// Peek the first bytes to decide whether the connection is TLS
	peekBuf := make([]byte, 5)
	n, err := clientConn.Read(peekBuf)
	if err != nil {
		log.Print(err)
		return
	}

	// Reset the deadline after peeking
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Print(err)
		return
	}

	peekedReader := io.MultiReader(bytes.NewReader(peekBuf[:n]), clientConn)

	// Check if the traffic looks like TLS
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
		// Handle plaintext (non-TLS) traffic, e.g., HTTP
		log.Print("Non-TLS traffic detected")
		buf := new(bytes.Buffer)
		teeReader := io.TeeReader(peekedReader, buf)

		// Read the HTTP request to extract the Host header
		req, err := http.ReadRequest(bufio.NewReader(teeReader))
		if err != nil {
			log.Printf("Failed to parse HTTP request: %s", err)
			return
		}

		// Extract the hostname from the Host header
		hostname := req.Host
		if _, _, err := net.SplitHostPort(hostname); err != nil {
			hostname = net.JoinHostPort(hostname, "80")
		}

		// Connect to the backend server
		backendConn, err := net.DialTimeout("tcp", hostname, 5*time.Second)
		if err != nil {
			log.Printf("Failed to connect to backend: %s", err)
			return
		}
		defer backendConn.Close()

		// Reassemble the full client data stream:
		// first, the bytes already read into the buffer, then the rest of the connection.
		fullRequestReader := io.MultiReader(bytes.NewReader(buf.Bytes()), clientConn)
		pipeTraffic(clientConn, backendConn, fullRequestReader, app, geoipDB, hostname)
	}
}

func isTLSHandshake(data []byte) bool {
	// Check for TLS handshake (starts with 0x16 for ClientHello)
	return len(data) > 0 && data[0] == 0x16
}

func pipeTraffic(clientConn net.Conn, backendConn net.Conn, clientReader io.Reader, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, hostname string) {
	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		log.Print(err)
		return
	}

	// Create the packet record.
	recordID, err := createPacketRecord(clientIP, hostname, app, geoipDB)
	if err != nil {
		log.Printf("Failed to create packet record: %s", err)
	}

	// Create a shared aggregator.
	aggregator := NewAggregator(recordID, app)

	// Start a ticker that flushes the aggregator once per second.
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

	// Flow: client -> backend ("out" direction).
	go func() {
		err := copyAndUpdate(backendConn, clientReader, "out", aggregator)
		if err != nil {
			log.Printf("Error in client->backend: %s", err)
		}
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	// Flow: backend -> client ("in" direction).
	go func() {
		err := copyAndUpdate(clientConn, backendConn, "in", aggregator)
		if err != nil {
			log.Printf("Error in backend->client: %s", err)
		}
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()
	close(done)
	flushTicker.Stop()

	// Final flush to capture any remaining bytes.
	aggregator.Flush()

	// Close the packet record.
	if recordID != "" {
		if err := closePacketRecord(recordID, app); err != nil {
			log.Printf("Failed to update packet record: %s", err)
		}
	}
}

// copyAndUpdate now simply transfers data and adds to the aggregator.
func copyAndUpdate(dst io.Writer, src io.Reader, direction string, aggregator *Aggregator) error {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			if written > 0 {
				// Add the written bytes to the aggregator.
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
