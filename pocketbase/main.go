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

// soOriginalDst is the option code for SO_ORIGINAL_DST on Linux (0x50 = 80).
// This is defined in <linux/netfilter_ipv4.h>.
const soOriginalDst = 80

// solIP is the SOL_IP constant in Linux, which is 0 for IPv4.
const solIP = 0

// RawSockaddrInet4 here is our own copy, matching the Linux struct:
//
//	struct sockaddr_in {
//	    __u16  sin_family;
//	    __be16 sin_port;
//	    struct in_addr sin_addr;
//	    ...
//	}
type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// ntohs swaps a 16-bit integer from network byte order to host byte order.
func ntohs(n uint16) uint16 {
	return (n<<8)&0xff00 | n>>8
}

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Cannot listen on :1337: %v", err)
	}
	defer ln.Close()

	log.Println("Transparent proxy listening on :1337 ... (run as root, iptables redirect in place)")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	origAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("getOriginalDst error: %v", err)
		return
	}

	// Peek the first few bytes
	peek := make([]byte, 5)
	n, err := clientConn.Read(peek)
	if err != nil {
		log.Printf("Error reading initial bytes: %v", err)
		return
	}
	if n < 5 {
		return
	}

	// Check for protocol type
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
		log.Printf("Dial %s failed: %v", origAddr.String(), err)
		return
	}
	defer serverConn.Close()

	// Write the peeked bytes to the server
	if _, err := serverConn.Write(peek[:n]); err != nil {
		log.Printf("Error writing peeked bytes to server: %v", err)
		return
	}

	// Proxy data in both directions
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		if err != nil {
			log.Printf("Error copying from client to server: %v", err)
		}
		serverConn.Close()
	}()
	_, err = io.Copy(clientConn, serverConn)
	if err != nil {
		log.Printf("Error copying from server to client: %v", err)
	}
}

// getOriginalDst uses a raw getsockopt(SO_ORIGINAL_DST) syscall
// to retrieve the real (pre-REDIRECT) IPv4 address + port.
func getOriginalDst(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}

	// Get the file descriptor
	f, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("tcpConn.File: %w", err)
	}
	defer f.Close()

	fd := f.Fd()

	// Prepare a buffer for RawSockaddrInet4
	var addr RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))

	// Use the lower-level Syscall6 for getsockopt,
	// since some platforms don't have syscall.Getsockopt defined.
	r0, _, e1 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solIP),         // IPPROTO_IP = 0
		uintptr(soOriginalDst), // 80
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if int(r0) != 0 {
		// If r0 != 0, this indicates an error code.
		if e1 != 0 {
			return nil, fmt.Errorf("getsockopt(SO_ORIGINAL_DST) syscall error: %v", e1)
		}
		return nil, fmt.Errorf("getsockopt(SO_ORIGINAL_DST) failed (unknown error)")
	}

	// Now parse the RawSockaddrInet4
	port := ntohs(addr.Port)
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

// parseHTTPHost tries to read the first line + headers from an HTTP request.
// Looks for a "Host:" header. Returns "" if not found or if there's an error.
func parseHTTPHost(r *bufio.Reader) string {
	// For example: "GET / HTTP/1.1\r\n"
	_, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	// Then read headers until blank line
	var host string
	for {
		hdrLine, err := r.ReadString('\n')
		if err != nil {
			// possible EOF
			break
		}
		hdrLine = strings.TrimSpace(hdrLine)
		if hdrLine == "" {
			// end of headers
			break
		}
		if strings.HasPrefix(strings.ToLower(hdrLine), "host:") {
			parts := strings.SplitN(hdrLine, ":", 2)
			if len(parts) == 2 {
				host = strings.TrimSpace(parts[1])
			}
		}
	}
	// Remove any :port part
	host = strings.Split(host, ":")[0]
	return host
}

// parseTLSClientHello does a minimal parse of a TLS ClientHello
// to extract the SNI (server_name). If it doesn't find any SNI, returns "".
func parseTLSClientHello(r *bufio.Reader) string {
	// We already read 5 bytes of the TLS record header (type, version, length).
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 42 { // too short to be a valid ClientHello
		return ""
	}

	data := make([]byte, recLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return ""
	}

	// data[0] => handshake type (0x01 = ClientHello)
	if data[0] != 0x01 {
		// not a ClientHello
		return ""
	}
	idx := 4 // skip handshakeType(1) + length(3)

	// skip client_version(2) + random(32)
	idx += 2 + 32
	if idx >= len(data) {
		return ""
	}

	// session_id
	sessLen := int(data[idx])
	idx++
	idx += sessLen
	if idx >= len(data) {
		return ""
	}

	// cipher_suites
	if idx+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2 + csLen
	if idx >= len(data) {
		return ""
	}

	// compression_methods
	if idx >= len(data) {
		return ""
	}
	compLen := int(data[idx])
	idx++
	idx += compLen
	if idx >= len(data) {
		return ""
	}

	// extensions
	if idx+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2
	if idx+extLen > len(data) {
		return ""
	}

	end := idx + extLen
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		length := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		idx += 4
		if idx+length > end {
			return ""
		}

		// SNI extension => 0x00
		if extType == 0x0000 {
			// SNI format: 2 bytes for list length, 1 byte name_type, 2 bytes name_len, name
			sniData := data[idx : idx+length]
			if len(sniData) < 5 {
				return ""
			}
			// sniData[2] == 0 => host_name
			if sniData[2] == 0 {
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
