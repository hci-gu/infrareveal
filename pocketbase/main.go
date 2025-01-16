package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalf("Failed to listen on :1337: %v", err)
	}
	defer ln.Close()
	log.Println("Minimal pass-through proxy listening on :1337...")

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

	// 1) Find the original destination (IP:port) via SO_ORIGINAL_DST
	origAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("getOriginalDst error: %v", err)
		return
	}

	// 2) Dial the original address
	serverConn, err := net.Dial("tcp", origAddr)
	if err != nil {
		log.Printf("Dial %s failed: %v", origAddr, err)
		return
	}
	defer serverConn.Close()

	// 3) Just blindly copy client->server and server->client, no inspection
	go func() {
		_, _ = io.Copy(serverConn, clientConn)
		serverConn.Close()
	}()
	_, _ = io.Copy(clientConn, serverConn)
}

// soOriginalDst = 80 (0x50) per <linux/netfilter_ipv4.h>
const soOriginalDst = 80

func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCPConn")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", fmt.Errorf("tcpConn.File: %w", err)
	}
	defer file.Close()

	fd := file.Fd()

	var addr syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))

	// IPPROTO_IP (==0), soOriginalDst (==80).
	r0, _, e1 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(0), // IPPROTO_IP = 0
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r0 != 0 {
		if e1 != 0 {
			return "", fmt.Errorf("getsockopt(SO_ORIGINAL_DST) syscall error: %v", e1)
		}
		return "", fmt.Errorf("getsockopt(SO_ORIGINAL_DST) failed (unknown error)")
	}

	port := ntohs(addr.Port)
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return fmt.Sprintf("%s:%d", ip, port), nil
}

// Helper function to convert from network byte order (big-endian) to host byte order
func ntohs(netport uint16) uint16 {
	return (netport << 8) | (netport >> 8)
}
