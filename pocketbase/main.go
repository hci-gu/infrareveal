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

// soOriginalDst is the socket option used to get the original destination.
// On Linux, it's 80 for IPv4. (Defined in <linux/netfilter_ipv4.h>)
const soOriginalDst = 80 // 0x50

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	defer ln.Close()

	log.Println("Transparent proxy listening on :1337 (requires iptables REDIRECT)")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(clientConn)
	}
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 1) Retrieve original destination (IP+port) via SO_ORIGINAL_DST
	origAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("Could not get original DST: %v", err)
		return
	}
	// e.g. "93.184.216.34:443"
	// If you only forwarded ports 80 & 443, you already know the port. But let's keep it dynamic.

	// 2) Sniff the first few bytes to decide if it's TLS (0x16) or plain HTTP
	peekBuf := make([]byte, 5)
	n, err := io.ReadFull(clientConn, peekBuf)
	if err != nil {
		log.Printf("Error reading initial bytes: %v", err)
		return
	}
	if n < 5 {
		return
	}

	// Re-inject these bytes so the full stream can flow to the destination
	combinedReader := io.MultiReader(bytes.NewReader(peekBuf), clientConn)
	bufReader := bufio.NewReader(combinedReader)

	isTLS := (peekBuf[0] == 0x16)

	var hostname string
	if isTLS {
		hostname = parseTLSClientHello(bufReader)
		if hostname == "" {
			hostname = "UNKNOWN_SNI"
		}
		log.Printf("[TLS] SNI: %s => %s", hostname, origAddr.String())
	} else {
		// parse HTTP host header
		hostname = parseHTTPHost(bufReader)
		if hostname == "" {
			hostname = "UNKNOWN_HOST"
		}
		log.Printf("[HTTP] Host: %s => %s", hostname, origAddr.String())
	}

	// 3) Dial the original destination
	serverConn, err := net.Dial("tcp", origAddr.String())
	if err != nil {
		log.Printf("Dial %s failed: %v", origAddr.String(), err)
		return
	}
	defer serverConn.Close()

	// 4) Bidirectional copy: client <-> server
	//    We do this in two goroutines so traffic flows both ways.
	go func() {
		_, _ = io.Copy(serverConn, bufReader) // client -> server
		serverConn.Close()
	}()
	_, _ = io.Copy(clientConn, serverConn) // server -> client
}

// getOriginalDst uses SO_ORIGINAL_DST to get the original IP:port
// that the client was trying to reach before iptables REDIRECT.
func getOriginalDst(clientConn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}

	// Get underlying file descriptor
	f, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("tcpConn.File(): %w", err)
	}
	defer f.Close()

	fd := int(f.Fd())

	// Prepare storage for sockaddr_in
	// struct sockaddr_in (IPv4) = 16 bytes
	var addr syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))

	// Call getsockopt(SOL_IP, SO_ORIGINAL_DST)
	err = syscall.Getsockopt(fd, syscall.SOL_IP, soOriginalDst, (*byte)(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %w", err)
	}

	// Convert to Go's IP+Port
	port := (uint16(addr.Port[0]) << 8) + uint16(addr.Port[1])
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

// parseHTTPHost tries to read an HTTP request and find the Host header.
// We only look at the first request line + headers until the blank line.
// If it's actually HTTPS data, we'll likely fail quickly or see gibberish.
func parseHTTPHost(r *bufio.Reader) string {
	// Example request line: "GET / HTTP/1.1"
	line, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	// We'll read more headers until blank line
	var host string
	for {
		hdrLine, err := r.ReadString('\n')
		if err != nil {
			break
		}
		hdrLine = strings.TrimSpace(hdrLine)
		if hdrLine == "" {
			// blank line => end of headers
			break
		}
		if strings.HasPrefix(strings.ToLower(hdrLine), "host:") {
			parts := strings.SplitN(hdrLine, ":", 2)
			if len(parts) == 2 {
				host = strings.TrimSpace(parts[1])
			}
		}
	}
	// if the host included a port, remove it for logging
	host = strings.Split(host, ":")[0]
	return host
}

// parseTLSClientHello reads the first TLS record to extract SNI (server_name) if present.
// We do a minimal parse of the ClientHello handshake. This won't handle all TLS edge cases.
func parseTLSClientHello(r *bufio.Reader) string {
	// The first 5 bytes are the record header we already read in handleConn:
	//  - byte 0: record type (0x16 => handshake)
	//  - bytes 1..2: TLS version
	//  - bytes 3..4: record length
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 { // too short to be a valid ClientHello
		return ""
	}

	payload := make([]byte, recLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return ""
	}

	// parse handshake
	// payload[0] = handshake type (0x01 for ClientHello)
	if payload[0] != 0x01 {
		return ""
	}

	// skip 4 bytes: handshakeType(1) + length(3)
	idx := 4

	// skip client version(2) + random(32)
	idx += 2 + 32

	// session ID
	if idx >= len(payload) {
		return ""
	}
	sessionIDLen := int(payload[idx])
	idx++
	idx += sessionIDLen
	if idx >= len(payload) {
		return ""
	}

	// cipher suites
	if idx+2 > len(payload) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[idx : idx+2]))
	idx += 2 + cipherSuitesLen
	if idx >= len(payload) {
		return ""
	}

	// compression methods
	if idx >= len(payload) {
		return ""
	}
	compMethodsLen := int(payload[idx])
	idx++
	idx += compMethodsLen
	if idx >= len(payload) {
		return ""
	}

	// extensions length
	if idx+2 > len(payload) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[idx : idx+2]))
	idx += 2
	if idx+extensionsLen > len(payload) {
		return ""
	}

	end := idx + extensionsLen
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(payload[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(payload[idx+2 : idx+4]))
		idx += 4
		if idx+extLen > end {
			return ""
		}
		if extType == 0x00 { // SNI extension
			// SNI format: 2 bytes list length, 1 byte name type, 2 bytes name len, name bytes
			sniData := payload[idx : idx+extLen]
			if len(sniData) < 5 {
				return ""
			}
			// sniData[2] => nameType (0 => host_name)
			if sniData[2] == 0 {
				nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
				if 5+nameLen <= len(sniData) {
					return string(sniData[5 : 5+nameLen])
				}
			}
		}
		idx += extLen
	}
	return ""
}
