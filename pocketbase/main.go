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
			active_session_id = &id
			return e.Next()
		})

		app.OnRecordAfterUpdateSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
			// if record.ended is set, then we need to update the session_id
			if e.Record.Get("ended") != nil {
				active_session_id = nil
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
	// 1. If there's no active session, we can skip creating a packet record
	if active_session_id == nil {
		return "", nil
	}

	// 2. Look up IP address from hostname
	hostIPs, lookupErr := net.LookupIP(hostname)
	if lookupErr != nil {
		log.Printf("lookup error: %s", lookupErr)
		return "", lookupErr
	}

	// 3. Pick the first IPv4 address if available
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

	// 4. GeoIP lookup
	geoRecord, geoErr := geoipDB.City(hostIP)
	if geoErr != nil {
		log.Printf("geoip error: %s", geoErr)
		return "", geoErr
	}

	// 5. Create a new packet record
	collection, err := app.FindCollectionByNameOrId("packets")
	if err != nil {
		log.Printf("collection error: %s", err)
		return "", err
	}
	record := core.NewRecord(collection)

	// 6. Populate fields (but do NOT include bytes or direction yet)
	record.Set("session", *active_session_id)
	record.Set("active", true)
	record.Set("client_ip", clientIP)
	record.Set("host", hostname)
	record.Set("lat", geoRecord.Location.Latitude)
	record.Set("lon", geoRecord.Location.Longitude)
	record.Set("incoming_bytes", 0)
	record.Set("outgoing_bytes", 0)
	record.Set("city", geoRecord.City.Names["en"])
	record.Set("country", geoRecord.Country.Names["en"])

	// 7. Save the record
	err = app.Save(record)
	if err != nil {
		log.Printf("save error: %s", err)
		return "", err
	}

	// 8. Return the newly created record's ID
	return record.Id, nil
}

func updatePacketRecordBytes(recordID string, incomingBytes, outgoingBytes int64, app *pocketbase.PocketBase) error {
	// 1. Find the record to update
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("updatePacketRecordBytes: could not find record %s: %s", recordID, err)
		return err
	}

	record.Set("incoming_bytes", record.Get("incoming_bytes").(int64)+incomingBytes)
	record.Set("outgoing_bytes", record.Get("outgoing_bytes").(int64)+outgoingBytes)

	// 4. Save
	err = app.Save(record)
	if err != nil {
		log.Printf("updatePacketRecordBytes: save error: %s", err)
		return err
	}

	return nil
}

func closePacketRecord(recordID string, app *pocketbase.PocketBase) error {
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("updatePacketRecordBytes: could not find record %s: %s", recordID, err)
		return err
	}

	record.Set("active", false)

	err = app.Save(record)
	if err != nil {
		log.Printf("updatePacketRecordBytes: save error: %s", err)
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

		pipeTraffic(clientConn, backendConn, peekedReader, app, geoipDB, hostname)
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

	// --- 1. Create the packet record first (without byte counts) ---
	recordID, err := createPacketRecord(clientIP, hostname, app, geoipDB)
	if err != nil {
		log.Printf("Failed to create packet record: %s", err)
	}

	// If recordID is empty (meaning no active session), we won't update anything later
	// but we still continue piping the traffic for normal proxy behavior.

	// --- 2. Pipe data, capturing byte counts ---
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client -> backend with realtime update of incoming_bytes
	go func() {
		err := copyAndUpdate(backendConn, clientReader, recordID, app, true)
		if err != nil {
			log.Printf("Error in client->backend: %s", err)
		}
		// half-close the connection: no more writes to backend
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	// Copy backend -> client with realtime update of outgoing_bytes
	go func() {
		err := copyAndUpdate(clientConn, backendConn, recordID, app, false)
		if err != nil {
			log.Printf("Error in backend->client: %s", err)
		}
		// half-close the connection: no more writes to client
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()

	// --- 3. Close the packet record ---
	if recordID != "" {
		err = closePacketRecord(recordID, app)
		if err != nil {
			log.Printf("Failed to update packet record: %s", err)
		}
	}
}

// copyAndUpdate reads from src and writes to dst in chunks.
// For each chunk it calls updatePacketRecordBytes to update the byte count.
// If incoming is true, then the bytes count will be added as incoming_bytes;
// otherwise, as outgoing_bytes.
func copyAndUpdate(dst io.Writer, src io.Reader, recordID string, app *pocketbase.PocketBase, incoming bool) error {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			if written > 0 && recordID != "" {
				// update the record for this chunk
				if incoming {
					if updateErr := updatePacketRecordBytes(recordID, int64(written), 0, app); updateErr != nil {
						log.Printf("Failed to update incoming bytes: %s", updateErr)
					}
				} else {
					if updateErr := updatePacketRecordBytes(recordID, 0, int64(written), app); updateErr != nil {
						log.Printf("Failed to update outgoing bytes: %s", updateErr)
					}
				}
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
