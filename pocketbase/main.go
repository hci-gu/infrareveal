package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	// Listen on TCP port 1337
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Failed to listen on port 1337: %v\n", err)
	}
	defer ln.Close()

	log.Println("Proxy listening on :1337 ...")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v\n", err)
			continue
		}
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// We’ll peek at the first bytes to decide whether this is likely TLS or plain HTTP.
	// The TLS handshake starts with 0x16 as the first byte (record type),
	// and typically 0x03 (TLS version) at bytes [1], [2] or so.
	// We only need a small buffer to make this decision.
	peekBuf := make([]byte, 5)
	n, err := io.ReadAtLeast(clientConn, peekBuf, 5)
	if err != nil {
		log.Printf("Error reading first bytes: %v", err)
		return
	}

	// Put those bytes into a buffered reader so we can "unread" them.
	// This way, the rest of the flow can read them again as needed.
	bufReader := bufio.NewReaderSize(clientConn, 4096)
	_ = bufReader.UnreadByte() // We have to push bytes back in reverse order
	for i := n - 2; i >= 0; i-- {
		_ = bufReader.UnreadByte()
	}

	var hostname string
	isTLS := (peekBuf[0] == 0x16)

	if isTLS {
		// Attempt to parse SNI from the ClientHello
		hostname = parseSNI(bufReader)
		if hostname == "" {
			hostname = "UNKNOWN_SNI"
		}
		log.Printf("[HTTPS] Client requested SNI: %s", hostname)
	} else {
		// Attempt to parse Host header from an HTTP request
		hostname = parseHTTPHost(bufReader)
		if hostname == "" {
			hostname = "UNKNOWN_HOST"
		}
		log.Printf("[HTTP] Client requested Host: %s", hostname)
	}

	// ---------------------------------------------------------------------
	// In a typical forwarding proxy scenario, you’d connect onward based on
	// the hostname:port gleaned from either SNI or Host. For demonstration,
	// we’ll just assume port 80 for HTTP, 443 for TLS. Or you can do more
	// advanced logic here (e.g., original destination from iptables, etc.).
	// ---------------------------------------------------------------------
	var remotePort = "80"
	if isTLS {
		remotePort = "443"
	}

	remoteAddr := net.JoinHostPort(hostname, remotePort)
	serverConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Could not connect to %s: %v", remoteAddr, err)
		return
	}
	defer serverConn.Close()

	// Now just pipe data between clientConn <-> serverConn
	go io.Copy(serverConn, bufReader)
	io.Copy(clientConn, serverConn)
}

// parseHTTPHost reads the first HTTP request line and/or headers to find the Host header.
func parseHTTPHost(r *bufio.Reader) string {
	// Read one line (e.g., "GET / HTTP/1.1")
	line, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	// If it starts with CONNECT, it might be a proxy style request: "CONNECT example.com:443 HTTP/1.1"
	if strings.HasPrefix(line, "CONNECT ") {
		fields := strings.Split(line, " ")
		if len(fields) >= 2 {
			hostPort := fields[1]
			// Could parse out "example.com" or "example.com:443"
			return strings.Split(hostPort, ":")[0]
		}
		return ""
	}

	// Otherwise, read headers until blank line
	var host string
	for {
		hdrLine, err := r.ReadString('\n')
		if err != nil {
			return host
		}
		hdrLine = strings.TrimSpace(hdrLine)
		if hdrLine == "" {
			// end of headers
			break
		}
		// e.g. "Host: example.com"
		if strings.HasPrefix(strings.ToLower(hdrLine), "host:") {
			parts := strings.SplitN(hdrLine, ":", 2)
			if len(parts) == 2 {
				host = strings.TrimSpace(parts[1])
			}
		}
	}
	// If there's a port in the host, remove it
	host = strings.Split(host, ":")[0]
	return host
}

// parseSNI does a minimal parse of the TLS ClientHello to extract the SNI (server_name).
// This does not handle all possible TLS handshake variants but works for most standard clients.
func parseSNI(r *bufio.Reader) string {
	// We already read 5 bytes (TLS record header) in handleConnection:
	//   type (1 byte) = 0x16
	//   version (2 bytes)
	//   length (2 bytes)
	//
	// But let's read them again from the buffered Reader (they should match):
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}

	// The record length is the last two bytes
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 { // minimal ClientHello length
		return ""
	}

	// Read the handshake messages (ClientHello etc.)
	data := make([]byte, recLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return ""
	}

	// data[0] = handshake type (0x01 for ClientHello)
	// data[1..3] = 3-byte length of the handshake
	// data[4..5] = client version
	// data[6..37] = random
	// next comes session id length + session id
	idx := 0
	if data[idx] != 0x01 {
		// not a ClientHello
		return ""
	}
	idx += 4 // skip msg-type(1) + length(3)

	// skip client version(2) + random(32)
	idx += 2 + 32

	// session id
	if idx >= len(data) {
		return ""
	}
	sessionIDLen := int(data[idx])
	idx++
	idx += sessionIDLen
	if idx >= len(data) {
		return ""
	}

	// cipher suites
	if idx+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2 + cipherSuitesLen
	if idx >= len(data) {
		return ""
	}

	// compression methods
	compMethodsLen := int(data[idx])
	idx++
	idx += compMethodsLen
	if idx > len(data) {
		return ""
	}

	// extensions length
	if idx+2 > len(data) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2
	if idx+extensionsLen > len(data) {
		return ""
	}

	// parse extensions
	end := idx + extensionsLen
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		idx += 4
		if idx+extLen > end {
			return ""
		}
		if extType == 0x00 { // SNI extension
			// SNI extension format:
			// 2 bytes for list length
			// then name type (1 byte), name length (2 bytes), name bytes
			sniData := data[idx : idx+extLen]
			// sniData[0..1] = SNI list length
			if len(sniData) < 5 {
				return ""
			}
			serverNameType := sniData[2] // should be 0 for DNS hostname
			if serverNameType == 0 {
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
