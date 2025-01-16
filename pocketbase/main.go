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
	if _, err := serverConn.Write(peek[:n]); err != nil {
		log.Printf("Error writing peeked bytes to server: %v", err)
		return
	}

	// Proxy data between client and server
	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverConn, clientConn) // client -> server
		if err != nil {
			log.Printf("Error copying client to server: %v", err)
		}
		done <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, serverConn) // server -> client
		if err != nil {
			log.Printf("Error copying server to client: %v", err)
		}
		done <- err
	}()

	// Wait for both directions to finish
	err1 := <-done
	err2 := <-done
	if err1 != nil {
		log.Printf("Proxy error (client -> server): %v", err1)
	}
	if err2 != nil {
		log.Printf("Proxy error (server -> client): %v", err2)
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
	// Read the TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		log.Printf("Failed to read TLS header: %v", err)
		return ""
	}

	// Extract the record length
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 || recLen > 16384 { // Validate reasonable ClientHello lengths
		log.Printf("Invalid ClientHello length: %d", recLen)
		return ""
	}

	// Read the full ClientHello message
	data := make([]byte, recLen)
	if _, err := io.ReadFull(r, data); err != nil {
		log.Printf("Failed to read ClientHello data: %v", err)
		return ""
	}

	// Parse ClientHello fields
	idx := 4 // Skip handshake type (1 byte) and length (3 bytes)
	if idx+2+32 > len(data) {
		log.Printf("ClientHello too short for session ID and random")
		return ""
	}

	// Skip session ID
	idx += 2 + 32
	sessLen := int(data[idx])
	idx++
	if idx+sessLen > len(data) {
		log.Printf("Session ID length exceeds message bounds")
		return ""
	}
	idx += sessLen

	// Skip cipher suites
	if idx+2 > len(data) {
		log.Printf("ClientHello too short for cipher suites length")
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2
	if idx+csLen > len(data) {
		log.Printf("Cipher suites length exceeds message bounds")
		return ""
	}
	idx += csLen

	// Skip compression methods
	if idx+1 > len(data) {
		log.Printf("ClientHello too short for compression methods")
		return ""
	}
	compLen := int(data[idx])
	idx++
	if idx+compLen > len(data) {
		log.Printf("Compression methods length exceeds message bounds")
		return ""
	}
	idx += compLen

	// Read extensions
	if idx+2 > len(data) {
		log.Printf("ClientHello too short for extensions length")
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2
	if idx+extLen > len(data) {
		log.Printf("Extensions length exceeds message bounds")
		return ""
	}

	// Parse extensions
	end := idx + extLen
	for idx+4 <= end {
		// Read extension type and length
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extDataLen := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		idx += 4

		if idx+extDataLen > end {
			log.Printf("Extension length exceeds message bounds: type=%x len=%d", extType, extDataLen)
			return ""
		}

		// SNI extension (type 0x00)
		if extType == 0x00 {
			sniData := data[idx : idx+extDataLen]
			if len(sniData) < 5 {
				log.Printf("SNI extension too short")
				return ""
			}
			if sniData[2] == 0 { // Name type = host_name
				nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
				if 5+nameLen <= len(sniData) {
					return string(sniData[5 : 5+nameLen])
				}
				log.Printf("SNI host_name length exceeds bounds")
				return ""
			}
		}

		idx += extDataLen
	}

	log.Printf("No SNI found in ClientHello")
	return ""
}
