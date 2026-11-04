// Package displaymode tracks temporary, self-selected display devices. Roles
// are local runtime state, never a permanent identity or an observation record.
package displaymode

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Grace = 3 * time.Minute
const RenewAfter = 20 * time.Second
const maxDisplays = 32

var ErrLease = errors.New("join the InfraReveal Wi-Fi before choosing display mode")
var ErrExpired = errors.New("display mode has ended; choose this device as a display again")

type Lease struct {
	MAC     string
	Expires time.Time
}

type Status struct {
	Token        string `json:"token"`
	ClientIP     string `json:"clientIp"`
	ExpiresMS    int64  `json:"expiresMs"`
	RenewAfterMS int64  `json:"renewAfterMs"`
	ValidForMS   int64  `json:"validForMs"`
}

type registration struct {
	Status
	mac          string
	leaseExpires time.Time
}

type Registry struct {
	mu      sync.RWMutex
	entries map[string]registration // IP -> current device and browser capability
	lease   func(string) (Lease, error)
	now     func() time.Time
}

func New(path string) *Registry {
	return &Registry{entries: map[string]registration{}, lease: func(ip string) (Lease, error) {
		return ReadLease(path, ip, time.Now())
	}, now: time.Now}
}

// ReadLease deliberately resolves the current lease when renewing a role or
// checking an IP-only source. Reusing an address must not inherit an exclusion.
func ReadLease(path, ip string, now time.Time) (Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		return Lease{}, ErrLease
	}
	defer f.Close()
	s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 3 || fields[2] != ip {
			continue
		}
		expires, err := strconv.ParseInt(fields[0], 10, 64)
		mac, macErr := net.ParseMAC(fields[1])
		if err != nil || macErr != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			return Lease{}, ErrLease
		}
		lease := Lease{MAC: mac.String()}
		if expires != 0 {
			lease.Expires = time.Unix(expires, 0)
			if !now.Before(lease.Expires) {
				return Lease{}, ErrLease
			}
		}
		return lease, nil
	}
	return Lease{}, ErrLease
}

func (r *Registry) Eligible(ip string) bool { _, err := r.lease(ip); return err == nil }

func (r *Registry) Start(ip string) (Status, error) {
	lease, err := r.lease(ip)
	if err != nil {
		return Status{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for key, entry := range r.entries {
		if entry.ExpiresMS <= now.UnixMilli() {
			delete(r.entries, key)
		}
	}
	// Multiple tabs on one device share a role. Stopping it invalidates every
	// tab's renewal token, rather than allowing a stale tab to re-enable it.
	entry, exists := r.entries[ip]
	if !exists || entry.mac != lease.MAC {
		if !exists && len(r.entries) >= maxDisplays {
			return Status{}, errors.New("too many active display devices")
		}
		var token [24]byte
		if _, err := rand.Read(token[:]); err != nil {
			return Status{}, err
		}
		entry = registration{Status: Status{Token: hex.EncodeToString(token[:]), ClientIP: ip}, mac: lease.MAC}
	}
	entry.ExpiresMS, entry.RenewAfterMS = now.Add(Grace).UnixMilli(), RenewAfter.Milliseconds()
	entry.leaseExpires = lease.Expires
	entry.ValidForMS = validity(now, lease)
	r.entries[ip] = entry
	return entry.Status, nil
}

func (r *Registry) Renew(ip, token string) (Status, error) {
	lease, err := r.lease(ip)
	if err != nil {
		return Status{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for previousIP, entry := range r.entries {
		if token == "" || entry.Token != token {
			continue
		}
		if entry.mac != lease.MAC || entry.ExpiresMS <= r.now().UnixMilli() {
			return Status{}, ErrExpired
		}
		// DHCP can change the address during a reconnect. The capability and
		// current lease must still identify the same Wi-Fi device.
		delete(r.entries, previousIP)
		entry.ClientIP, entry.ExpiresMS = ip, r.now().Add(Grace).UnixMilli()
		entry.leaseExpires = lease.Expires
		entry.ValidForMS = validity(r.now(), lease)
		r.entries[ip] = entry
		return entry.Status, nil
	}
	return Status{}, ErrExpired
}

func validity(now time.Time, lease Lease) int64 {
	duration := Grace
	if !lease.Expires.IsZero() && lease.Expires.Sub(now) < duration {
		duration = lease.Expires.Sub(now)
	}
	return max(1, duration.Milliseconds())
}

func (r *Registry) Stop(ip, token string) {
	lease, _ := r.lease(ip)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if token != "" && entry.Token == token && (entry.ClientIP == ip || entry.mac == lease.MAC) {
			delete(r.entries, key)
		}
	}
}

// Excluded is called before aggregation, DNS attribution, tracing and gating.
// Packet sources supply the Ethernet MAC, making the hot path memory-only.
// IP-only sources resolve the current lease, never trusting an old IP binding.
func (r *Registry) Excluded(ip, mac string) bool {
	r.mu.RLock()
	entry, ok := r.entries[ip]
	r.mu.RUnlock()
	now := r.now()
	if !ok || entry.ExpiresMS <= now.UnixMilli() || (!entry.leaseExpires.IsZero() && !now.Before(entry.leaseExpires)) {
		return false
	}
	if mac == "" {
		lease, err := r.lease(ip)
		if err != nil {
			return false
		}
		mac = lease.MAC
	}
	return strings.EqualFold(entry.mac, mac)
}
