package routing

import (
	"fmt"
	"testing"
	"time"
)

func TestEphemeralRouteAllowanceRenewsWithoutBypassingNetworkLimit(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	rec, _ := app.FindRecordById("sessions", session)
	rec.Set("ephemeral", true)
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}
	c := ConfigFromEnv()
	c.MaxTargets = 2
	c.MaxAttempts = 2
	c.HourlyAttempts = 2
	now := time.Now().UTC()
	// A reconstructed repository each hour models restarts during three days.
	for hour := 0; hour < 72; hour++ {
		repo := repository{app: app}
		at := now.Add(time.Duration(hour) * time.Hour)
		for i := 0; i < 3; i++ {
			a, err := repo.reserve(session, "network", target{fmt.Sprintf("8.1.%d.%d", hour, i+1), "tcp", 443}, c, false, at.Add(time.Duration(i)*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if i < 2 && a.Reason != "" {
				t.Fatalf("hour %d: %s", hour, a.Reason)
			}
			if i == 2 && a.Reason != "hourly_budget" {
				t.Fatalf("hour %d bypassed network cap: %s", hour, a.Reason)
			}
		}
		_, b, err := loadSessionBudgetAt(app, session, at.Add(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if b.Attempts != 2 || len(b.Targets) != 2 {
			t.Fatalf("unbounded ledger: %+v", b)
		}
	}
}

func TestEphemeralStorageUsesRetainedEvidence(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	rec, _ := app.FindRecordById("sessions", session)
	rec.Set("ephemeral", true)
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	repo := repository{app: app}
	tgt := target{"9.9.9.9", "tcp", 443}
	c := ConfigFromEnv()
	a, err := repo.reserve(session, "network", tgt, c, false, now)
	if err != nil || a.Reason != "" {
		t.Fatal(a, err)
	}
	_, err = repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{}, useful(now, a.Attempt), "reached", "probe", now)
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := loadSessionBudgetAt(app, session, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if before.Snapshots != 1 || before.Bytes <= 0 || before.Attempts != 0 {
		t.Fatalf("renewal lost retained storage accounting: %+v", before)
	}
	_, err = app.DB().NewQuery("DELETE FROM routes").Execute()
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := loadSessionBudgetAt(app, session, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if after.Snapshots != 0 || after.Bytes >= before.Bytes {
		t.Fatal("pruning did not release storage allowance")
	}
}
