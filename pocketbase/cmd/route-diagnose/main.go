// route-diagnose compares probe profiles and captures only ICMP header summaries.
// It runs independently of PocketBase and never changes sessions or firewall rules.
package main

import (
	"context"
	"flag"
	"fmt"
	"myapp/routing"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	target := flag.String("target", "", "numeric destination IP to investigate")
	port := flag.Int("port", 443, "observed destination port")
	iface := flag.String("interface", "eth0", "uplink interface for returning ICMP headers")
	seconds := flag.Int("seconds", 45, "deadline for each paced comparison, 5–90 seconds")
	hops := flag.Int("hops", 20, "maximum TTL, 3–32")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := routing.Diagnose(ctx, *target, *port, *iface, time.Duration(*seconds)*time.Second, *hops, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
