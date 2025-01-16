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
	"unsafe"

	"golang.org/x/sys/unix"
)

// soOriginalDst is the sockopt to get the original destination (SO_ORIGINAL_DST).
// Defined in <linux/netfilter_ipv4.h> as 80 (0x50).
const soOriginalDst = 80

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Failed to listen on :1337: %v", err)
	}
	defer ln.Close()

	log.Println("Transparent proxy listening on :1337...")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleClient(clientConn)
	}
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	// 1) Retrieve the original destination IP:port
	origAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("getOriginalDst error: %v", err)
		return
	}

	// 2) Peek first 5 bytes to see if TLS handshake (0x16) or HTTP
	peek := make([]byte, 5)
	n, err := io.ReadFull(clientConn, peek)
	if err != nil {
		log.Printf("Read initial bytes error: %v", err)
		return
	}
	if n < 5 {
		return
	}

	// Re-inject those bytes via MultiReader so we don't lose them
	combined := io.MultiReader(bytes.NewReader(peek), clientConn)
	buf := bufio.NewReader(combined)

	isTLS := (peek[0] == 0x16)

	// 3) Log either SNI (if TLS) or Host (if HTTP)
	var hostname string
	if isTLS {
		hostname = parseTLSClientHello(buf)
		if hostname == "" {
			hostname = "UNKNOWN_SNI"
		}
		log.Printf("[TLS] SNI: %s => %s", hostname, origAddr)
	} else {
		hostname = parseHTTPHost(buf)
		if hostname == "" {
			hostname = "UNKNOWN_HOST"
		}
		log.Printf("[HTTP] Host: %s => %s", hostname, origAddr)
	}

	// 4) Dial the real/original destination
	serverConn, err := net.Dial("tcp", origAddr.String())
	if err != nil {
		log.Printf("Dial %s failed: %v", origAddr, err)
		return
	}
	defer serverConn.Close()

	// 5) Forward data in both directions
	go func() {
		_, _ = io.Copy(serverConn, buf) // client -> server
		serverConn.Close()
	}()
	_, _ = io.Copy(clientConn, serverConn) // server -> client
}

// getOriginalDst manually calls getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST)
// and decodes the returned RawSockaddrInet4 to get the IP+port.
func getOriginalDst(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}
	f, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("tcpConn.File(): %w", err)
	}
	defer f.Close()

	fd := int(f.Fd())

	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))

	// Use IPPROTO_IP (== 0) for the "level" argument.
	// soOriginalDst (80) is the "optname".
	err = unix.Getsockopt(fd, unix.IPPROTO_IP, soOriginalDst, (*byte)(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %v", err)
	}

	// Port is in network byte order in addr.Port[0..1]
	port := (uint16(addr.Port[0]) << 8) + uint16(addr.Port[1])
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

// parseHTTPHost reads the first HTTP request line + headers to find the Host header.
func parseHTTPHost(r *bufio.Reader) string {
	// For example, "GET / HTTP/1.1\r\n"
	line, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimSpace(line)

	// Keep reading headers until blank line
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
	// Remove any :port if present
	host = strings.Split(host, ":")[0]
	return host
}

// parseTLSClientHello does a minimal parse of the TLS ClientHello handshake
// to extract the SNI (server_name) if present. This won't handle all edge cases.
func parseTLSClientHello(r *bufio.Reader) string {
	// We already read 5 bytes (record header), read them again for the handshake portion:
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 {
		return ""
	}

	payload := make([]byte, recLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return ""
	}

	// payload[0] => handshake type (0x01 = ClientHello)
	if payload[0] != 0x01 {
		return ""
	}
	idx := 4 // skip handshake type(1)+length(3)

	// skip client version(2) + random(32)
	idx += 2 + 32
	if idx >= len(payload) {
		return ""
	}
	// sessionID
	sessionLen := int(payload[idx])
	idx++
	idx += sessionLen
	if idx >= len(payload) {
		return ""
	}

	// cipher suites
	if idx+2 > len(payload) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(payload[idx : idx+2]))
	idx += 2 + csLen
	if idx >= len(payload) {
		return ""
	}

	// compression methods
	if idx >= len(payload) {
		return ""
	}
	compLen := int(payload[idx])
	idx++
	idx += compLen
	if idx >= len(payload) {
		return ""
	}

	// extensions
	if idx+2 > len(payload) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(payload[idx : idx+2]))
	idx += 2
	if idx+extLen > len(payload) {
		return ""
	}

	end := idx + extLen
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(payload[idx : idx+2])
		length := int(binary.BigEndian.Uint16(payload[idx+2 : idx+4]))
		idx += 4
		if idx+length > end {
			return ""
		}
		// SNI extension => extType == 0
		if extType == 0x00 {
			// Format: 2 bytes SNI list length, 1 byte name_type, 2 bytes name_len, name...
			sniData := payload[idx : idx+length]
			if len(sniData) < 5 {
				return ""
			}
			if sniData[2] == 0 { // host_name
				nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
				if 5+nameLen <= len(sniData) {
					return string(sniData[5 : 5+nameLen])
				}
			}
		}
		idx += length
	}
	return ""
}
