package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
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

func savePacket(hostname string, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, incomingBytes int, outgoingBytes int) error {
	// ignore if there is no active session
	if active_session_id == nil {
		return nil
	}

	trafficDirection := ""
	if outgoingBytes > incomingBytes {
		trafficDirection = "outgoing"
	} else {
		trafficDirection = "incoming"
	}

	hostIPs, lookupErr := net.LookupIP(hostname)
	if lookupErr != nil {
		log.Printf("lookup error: %s", lookupErr)
		return nil
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
		return nil
	}

	log.Printf("savePacket %s, hostIP: %s", hostname, hostIP)

	geoRecord, geoErr := geoipDB.City(hostIP)
	if geoErr != nil {
		log.Printf("geoip error: %s", geoErr)
		return nil
	}

	collection, err := app.FindCollectionByNameOrId("packets")
	if err != nil {
		log.Printf("collection error: %s", err)
		return err
	}
	record := core.NewRecord(collection)
	record.Set("session", active_session_id)
	record.Set("host", hostname)
	record.Set("direction", trafficDirection)
	record.Set("incoming_bytes", incomingBytes)
	record.Set("outgoing_bytes", outgoingBytes)
	record.Set("lat", geoRecord.Location.Latitude)
	record.Set("lon", geoRecord.Location.Longitude)
	record.Set("city", geoRecord.City.Names["en"])
	record.Set("country", geoRecord.Country.Names["en"])

	err = app.Save(record)
	if err != nil {
		log.Printf("save error: %s", err)
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
		// get hostname for packet
		hostname, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		backendConn, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, "80"), 5*time.Second)
		if err != nil {
			log.Print(err)
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
	var wg sync.WaitGroup
	wg.Add(2)

	// Track data flow
	outgoingBytes := int64(0)
	incomingBytes := int64(0)

	// Copy client -> backend (incoming data)
	go func() {
		n, _ := io.Copy(backendConn, clientReader)
		outgoingBytes += n
		log.Printf("Client -> Server: %d bytes", n)
		backendConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	// Copy backend -> client (outgoing data)
	go func() {
		n, _ := io.Copy(clientConn, backendConn)
		incomingBytes += n
		log.Printf("Server -> Client: %d bytes", n)
		clientConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	wg.Wait()

	savePacket(hostname, app, geoipDB, incomingBytes, outgoingBytes)

	// log.Printf("Total data: Client -> Server: %d bytes, Server -> Client: %d bytes", clientToServerBytes, serverToClientBytes)
}
