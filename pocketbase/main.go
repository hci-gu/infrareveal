package main

import (
	"bufio"
	"bytes"
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

	"myapp/lib"
)

// Global pointer tracking active session
var active_session_id *string

// We'll keep a global map to track which hostnames we've seen for the current session
var sessionHostnames sync.Map // key=string (hostname), value=bool

func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// no port part
		return hostPort
	}
	return host
}

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

	// Create the packet record for this flow
	if active_session_id != nil {
		recordID, err := lib.CreatePacketRecord(*active_session_id, clientIP, stripPort(hostname), app, geoipDB)
		if err != nil {
			log.Printf("Failed to create packet record: %s", err)
		}

		// If this is a new hostname in the current session, run traceroute & geolocate in background.
		if active_session_id != nil && recordID != "" {
			hn := stripPort(hostname)
			if _, loaded := sessionHostnames.LoadOrStore(hn, true); !loaded {
				go func(sid, h string) {
					// Perform traceroute
					err := lib.RunTraceroute(*active_session_id, app, geoipDB, h)
					if err != nil {
						log.Printf("Traceroute error for host %s: %v", h, err)
						return
					}
				}(*active_session_id, hn)
			}
		}

		// Create an aggregator for recording in/out bytes
		aggregator := lib.NewPacketAggregator(recordID, app)

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
			err := lib.CopyAndUpdatePacket(backendConn, clientReader, "out", aggregator)
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
			err := lib.CopyAndUpdatePacket(clientConn, backendConn, "in", aggregator)
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
			if err := lib.ClosePacketRecord(recordID, app); err != nil {
				log.Printf("Failed to update packet record: %s", err)
			}
		}
	}
}
