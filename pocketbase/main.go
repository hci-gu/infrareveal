package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
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

	// Peek initial bytes
	peek := make([]byte, 5)
	n, err := clientConn.Read(peek)
	if err != nil {
		log.Printf("Error reading initial bytes: %v", err)
		return
	}
	if n < 5 {
		log.Println("Not enough bytes to determine protocol")
		return
	}

	// Check for TLS or HTTP
	isTLS := (peek[0] == 0x16)
	var hostname string
	if isTLS {
		hostname = parseTLSClientHello(bufio.NewReader(io.MultiReader(bytes.NewReader(peek), clientConn)))
		if hostname == "" {
			hostname = "UNKNOWN_SNI"
		}
		log.Printf("[TLS] SNI: %s => %s", hostname, origAddr)
	} else {
		hostname = parseHTTPHost(bufio.NewReader(io.MultiReader(bytes.NewReader(peek), clientConn)))
		if hostname == "" {
			hostname = "UNKNOWN_HOST"
		}
		log.Printf("[HTTP] Host: %s => %s", hostname, origAddr)
	}

	// Dial the original destination
	serverConn, err := net.Dial("tcp", origAddr.String())
	if err != nil {
		log.Printf("Failed to connect to %s: %v", origAddr, err)
		return
	}
	defer serverConn.Close()
	log.Printf("Connected to %s", origAddr)

	// Write the peeked bytes to the server
	_, err = serverConn.Write(peek[:n])
	if err != nil {
		log.Printf("Error writing peeked bytes to server: %v", err)
		return
	}

	// Proxy data between client and server
	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverConn, clientConn) // client -> server
		done <- err
		serverConn.Close()
	}()
	go func() {
		_, err := io.Copy(clientConn, serverConn) // server -> client
		done <- err
		clientConn.Close()
	}()

	err1 := <-done
	err2 := <-done
	if err1 != nil {
		log.Printf("Error proxying client -> server: %v", err1)
	}
	if err2 != nil {
		log.Printf("Error proxying server -> client: %v", err2)
	}
	log.Println("Connection closed")
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

func parseHTTPHost(r *bufio.Reader) string {
	_, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	for {
		header, err := r.ReadString('\n')
		if err != nil || header == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(header), "host:") {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseTLSClientHello(r *bufio.Reader) string {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 {
		return ""
	}

	data := make([]byte, recLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return ""
	}
	idx := 4 + 2 + 32
	idx += int(data[idx]) + 1
	csLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2 + csLen + int(data[idx])
	idx += 2
	for idx+4 < len(data) {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		if extType == 0x00 && extLen >= 5 {
			nameLen := int(binary.BigEndian.Uint16(data[idx+7 : idx+9]))
			return string(data[idx+9 : idx+9+nameLen])
		}
		idx += 4 + extLen
	}
	return ""
}
