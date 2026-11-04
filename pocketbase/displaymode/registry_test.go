package displaymode

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoleRenewsExpiresStopsAndNeverFollowsAReusedIP(t *testing.T) {
	now := time.Now()
	leases := map[string]Lease{"10.0.0.50": {MAC: "02:00:00:00:00:01", Expires: now.Add(time.Hour)}}
	r := &Registry{entries: map[string]registration{}, now: func() time.Time { return now }, lease: func(ip string) (Lease, error) {
		if l, ok := leases[ip]; ok {
			return l, nil
		}
		return Lease{}, ErrLease
	}}
	role, err := r.Start("10.0.0.50")
	if err != nil || role.Token == "" || role.ValidForMS != Grace.Milliseconds() {
		t.Fatal(role, err)
	}
	if !r.Excluded("10.0.0.50", "") || !r.Excluded("10.0.0.50", leases["10.0.0.50"].MAC) || r.Excluded("10.0.0.51", "") {
		t.Fatal("wrong initial exclusion")
	}
	if r.Excluded("10.0.0.50", "02:00:00:00:00:02") {
		t.Fatal("new device inherited exclusion")
	}
	// A new DHCP owner must also be visible to IP-only DNS/conntrack sources.
	old := leases["10.0.0.50"]
	leases["10.0.0.50"] = Lease{MAC: "02:00:00:00:00:02", Expires: now.Add(time.Hour)}
	if r.Excluded("10.0.0.50", "") {
		t.Fatal("reused IP inherited DNS exclusion")
	}
	if _, err := r.Renew("10.0.0.50", role.Token); err != ErrExpired {
		t.Fatal("different device renewed role", err)
	}
	// A real reconnect may change the original device's address.
	leases["10.0.0.51"] = old
	if _, err := r.Renew("10.0.0.51", role.Token); err != nil {
		t.Fatal(err)
	}
	if r.Excluded("10.0.0.50", old.MAC) || !r.Excluded("10.0.0.51", old.MAC) {
		t.Fatal("reconnect left stale binding")
	}
	now = now.Add(Grace - time.Second)
	if _, err := r.Renew("10.0.0.51", role.Token); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if !r.Excluded("10.0.0.51", old.MAC) {
		t.Fatal("renewal failed")
	}
	second, _ := r.Start("10.0.0.51")
	if second.Token != role.Token {
		t.Fatal("tabs must share a device role")
	}
	r.Stop("10.0.0.51", role.Token)
	if r.Excluded("10.0.0.51", old.MAC) {
		t.Fatal("stop did not release")
	}
	if _, err := r.Renew("10.0.0.51", second.Token); err != ErrExpired {
		t.Fatal("stale tab resurrected role")
	}
	role, _ = r.Start("10.0.0.51")
	now = now.Add(Grace)
	if r.Excluded("10.0.0.51", old.MAC) {
		t.Fatal("role did not expire")
	}
	if _, err := r.Renew("10.0.0.51", role.Token); err != ErrExpired {
		t.Fatal("expired token resurrected role")
	}
	role, _ = r.Start("10.0.0.51")
	leases["10.0.0.52"] = old
	r.Stop("10.0.0.52", role.Token) // address changed before the next heartbeat
	if r.Excluded("10.0.0.51", old.MAC) {
		t.Fatal("stop after DHCP move left an old exclusion")
	}
}

func TestDHCPLeaseValidationAndRoleLeaseExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases")
	now := time.Now()
	write := func(line string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf("%d 02:00:00:00:00:01 10.0.0.50 laptop *\n", now.Add(time.Minute).Unix()))
	r := New(path)
	role, err := r.Start("10.0.0.50")
	if err != nil || role.ValidForMS > 60_000 {
		t.Fatal(role, err)
	}
	if _, err := r.Start("10.0.0.51"); err != ErrLease {
		t.Fatal("unknown IP accepted")
	}
	for _, line := range []string{"bad lease\n", "1 02:00:00:00:00:01 10.0.0.50 laptop *\n", "0 00:00:00:00:00:00 10.0.0.50 laptop *\n"} {
		write(line)
		if r.Excluded("10.0.0.50", "") {
			t.Fatal("missing or invalid lease remained excluded", line)
		}
	}
	write("0 02:00:00:00:00:01 10.0.0.50 laptop *\n")
	if !r.Eligible("10.0.0.50") {
		t.Fatal("infinite DHCP lease rejected")
	}
}
