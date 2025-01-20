package main

import (
	"fmt"
	"infra-reveal/parser"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	soOriginalDst = 80 // SO_ORIGINAL_DST
	solIP         = 0  // SOL_IP
)

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

func ntohs(n uint16) uint16 {
	return (n<<8)&0xff00 | n>>8
}

func main() {
	listener, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Cannot listen on :1337: %v", err)
	}
	defer listener.Close()

	log.Println("Transparent proxy listening on :1337...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	log.Printf("New connection from %s", clientConn.RemoteAddr())

	// Get the original destination
	origAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("getOriginalDst error: %v", err)
		return
	}
	log.Printf("Original destination: %s", origAddr)

	// Peek initial bytes for SNI parsing
	peek := make([]byte, 512)
	n, err := clientConn.Read(peek)
	if err != nil {
		log.Printf("Error reading initial bytes: %v", err)
		return
	}

	// Extract SNI
	clientHello, clientReader, err := parser.PeekClientHello(clientConn)
	if err != nil {
		log.Print(err)
		return
	}

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Print(err)
		return
	}

	log.Print(clientHello.ServerName)

	// Dial the original destination
	serverConn, err := net.Dial("tcp", origAddr.String())
	if err != nil {
		log.Printf("Failed to connect to %s: %v", origAddr, err)
		return
	}
	defer serverConn.Close()

	// Write the peeked bytes to the server
	if _, err := serverConn.Write(peek[:n]); err != nil {
		log.Printf("Error writing peeked bytes to server: %v", err)
		return
	}

	backendConn, err := net.DialTimeout("tcp", net.JoinHostPort(clientHello.ServerName, "443"), 5*time.Second)
	if err != nil {
		log.Print(err)
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(clientConn, backendConn)
		clientConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		io.Copy(backendConn, clientReader)
		backendConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	wg.Wait()
}

func getOriginalDst(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}

	f, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("tcpConn.File: %w", err)
	}
	defer f.Close()

	fd := f.Fd()

	var addr RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))

	_, _, e1 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solIP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if e1 != 0 {
		return nil, fmt.Errorf("getsockopt(SO_ORIGINAL_DST) error: %v", e1)
	}

	port := ntohs(addr.Port)
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}
