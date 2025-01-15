package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening on :1337")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)

	// Read first line: e.g. "CONNECT www.facebook.com:443 HTTP/1.1"
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading request line: %v", err)
		return
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "CONNECT ") {
		log.Printf("Not a CONNECT request: %s", line)
		return
	}

	// Example: "CONNECT www.facebook.com:443 HTTP/1.1"
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return
	}
	hostPort := parts[1] // "www.facebook.com:443"
	log.Printf("[CONNECT] %s", hostPort)

	// Read remaining headers until blank line
	for {
		hdr, err := reader.ReadString('\n')
		if err != nil {
			// Possibly no more data
			break
		}
		hdr = strings.TrimSpace(hdr)
		if hdr == "" {
			// blank line => end of headers
			break
		}
	}

	// Dial the target
	remote, err := net.Dial("tcp", hostPort)
	if err != nil {
		log.Printf("Unable to connect to %s: %v", hostPort, err)
		return
	}
	defer remote.Close()

	// Respond with 200
	fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\n")
	fmt.Fprintf(client, "Proxy-agent: MyProxy/0.1\r\n")
	fmt.Fprintf(client, "\r\n")

	// Relay bytes both ways
	go io.Copy(remote, reader) // client -> remote
	io.Copy(client, remote)    // remote -> client
}
