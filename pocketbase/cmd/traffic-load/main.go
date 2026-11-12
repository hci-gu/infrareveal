// traffic-load creates an isolated, reproducible database and optionally serves
// it through the production API while generating synthetic capture events.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/gateway"
	_ "myapp/migrations"
	"myapp/observer"
)

func main() {
	profile := flag.String("cpuprofile", "", "write a 30-second CPU profile after ten-second warmup")
	dir := flag.String("dir", "", "required EMPTY isolated database directory")
	clients := flag.Int("clients", 30, "synthetic clients (1-200)")
	bindings := flag.Int("bindings", 50, "destinations per client (1-200)")
	minutes := flag.Int("minutes", 5, "recorded history minutes (1-30)")
	bins := flag.Int("bins", 5, "occupied 50ms bins per five-second chunk (1-100)")
	duration := flag.Duration("duration", 0, "live load duration, e.g. 90m; zero seeds a recording")
	pps := flag.Int("pps", 2000, "synthetic packets/second during live load")
	listen := flag.String("http", "127.0.0.1:8092", "isolated HTTP listener")
	reuse := flag.Bool("reuse", false, "serve a previously generated workload.json fixture")
	serve := flag.Bool("serve", false, "serve the fixture using the product API")
	flag.Parse()
	if *dir == "" || *clients < 1 || *clients > 200 || *bindings < 1 || *bindings > 200 || *minutes < 1 || *minutes > 30 || *bins < 1 || *bins > 100 || *pps < 1 || *pps > 100000 || *duration < 0 {
		log.Fatal("invalid load configuration")
	}
	path, err := filepath.Abs(*dir)
	must(err)
	entries, err := os.ReadDir(path)
	if err == nil && len(entries) > 0 && !*reuse {
		log.Fatal("load fixture requires an empty directory; existing data is never changed")
	}
	if *reuse {
		if _, err := os.Stat(filepath.Join(path, "workload.json")); err != nil {
			log.Fatal("reuse requires a generated load fixture")
		}
	}
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: path, HideStartBanner: true})
	must(app.Bootstrap())
	must(app.RunAppMigrations())
	if *reuse {
		app.OnServe().BindFunc(func(e *core.ServeEvent) error { gateway.RegisterSessionTimelineRoutes(e.Router, app); return e.Next() })
		app.RootCmd.SetArgs([]string{"serve", "--http", *listen})
		must(app.Start())
		return
	}
	start := time.Now().Add(-time.Duration(*minutes)*time.Minute).UnixMilli() / 5000 * 5000
	end := start + int64(*minutes)*60000
	live := *duration > 0
	if live {
		start = time.Now().UnixMilli() / 5000 * 5000
		end = 0
	}
	session := data.Session{ID: data.ID("traffic-load"), Name: fmt.Sprintf("Load fixture · %d clients · %d bindings", *clients, *bindings), StartedMS: start, EndedMS: end, RetainedFromMS: start, Revision: 1, Policy: observer.DefaultPolicy(), Active: live, Ephemeral: live, RetentionMinutes: *minutes, Capture: data.CaptureHealth{Epoch: "load", Quality: "complete", ConfirmedMS: end}}
	_, err = data.Write(app, "sessions", session)
	must(err)
	var sent, received, chunks int64
	if !live {
		for binding := 0; binding < *bindings; binding++ {
			lat, lon := float64(35+binding%25), float64(-120+(binding*17)%260)
			dest := data.Destination{ID: data.ID("load-destination", fmt.Sprint(binding)), IP: fmt.Sprintf("203.0.113.%d", binding+1), Version: "fixture", Country: "Illustrative", City: fmt.Sprintf("Location %d", binding%25), Lat: &lat, Lon: &lon, Precision: "city"}
			if binding%19 == 0 {
				dest.Lat, dest.Lon = nil, nil
				dest.Precision = "unknown"
			}
			_, err = data.Write(app, "destinations", dest)
			must(err)
		}
		// Bounded write transactions keep fixture creation useful on the actual Pi.
		for at := start; at < end; at += 5000 {
			err = app.RunInTransaction(func(tx core.App) error {
				for client := 0; client < *clients; client++ {
					for binding := 0; binding < *bindings; binding++ {
						id := fmt.Sprintf("%d-%d-%d", client, binding, at)
						samples := make([]data.Sample, *bins)
						for i := range samples {
							s, r := int64(100+binding), int64(1000+client*10+binding)
							samples[i] = data.Sample{int64(i) * 5000 / int64(*bins) / 50 * 50, s, r, s - 40, r - 40, 1, 1}
							sent += s
							received += r
						}
						encoded, _ := json.Marshal(samples)
						_, err := tx.DB().Insert("traffic_chunks", dbx.Params{"id": data.ID(id), "session": session.ID, "capture_epoch": "load", "client_id": fmt.Sprintf("client-%d", client), "client_ip": fmt.Sprintf("10.254.0.%d", client+10), "service_key": fmt.Sprintf("service-%d.test", binding), "service_label": fmt.Sprintf("Service %d", binding), "destination_id": data.ID("load-destination", fmt.Sprint(binding)), "destination_ip": fmt.Sprintf("203.0.113.%d", binding+1), "protocol": "tcp", "destination_port": 443, "start_ms": at, "bucket_ms": 50, "chunk_ms": 5000, "sealed": true, "samples": string(encoded), "evidence": `{"source":"synthetic","confidence":"medium"}`}).Execute()
						if err != nil {
							return err
						}
						chunks++
					}
				}
				return nil
			})
			must(err)
		}
		_, err = data.Write(app, "capture_intervals", data.CaptureInterval{ID: data.ID("load-coverage"), Session: session.ID, CaptureEpoch: "load", StartMS: start, EndMS: end, Quality: "complete"})
		must(err)
	}
	report := map[string]any{"session": session.ID, "clients": *clients, "bindings": *bindings, "series": *clients * *bindings, "minutes": *minutes, "bins_per_chunk": *bins, "chunks": chunks, "sent": sent, "received": received, "payloadSent": sent - 40*chunks*int64(*bins), "payloadReceived": received - 40*chunks*int64(*bins), "packetsSent": chunks * int64(*bins), "packetsReceived": chunks * int64(*bins), "start_ms": start, "end_ms": end, "live": live, "pps": *pps}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	must(os.WriteFile(filepath.Join(path, "workload.json"), encoded, 0600))
	fmt.Println(string(encoded))
	if !*serve && !live {
		must(app.ResetBootstrapState())
		return
	}
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		gateway.RegisterSessionTimelineRoutes(e.Router, app)
		if live {
			checkpoints, err := data.StartCheckpoints(app)
			if err != nil {
				return err
			}
			app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := checkpoints.Close(ctx); err != nil {
					return err
				}
				return e.Next()
			})
			if *profile != "" {
				go func() {
					time.Sleep(10 * time.Second)
					f, err := os.Create(*profile)
					if err != nil {
						log.Print(err)
						return
					}
					defer f.Close()
					if err := pprof.StartCPUProfile(f); err != nil {
						log.Print(err)
						return
					}
					time.Sleep(30 * time.Second)
					pprof.StopCPUProfile()
				}()
			}
			meter := &observer.TrafficLoadMeter{}
			runtime := observer.NewTrafficLoad(app, session.ID, time.Now().Add(*duration), *clients, *bindings, *pps, meter)
			runtime.Start()
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				if err := runtime.Wait(ctx); err != nil {
					return
				}
				cancel()
				if err := app.RunInTransaction(func(tx core.App) error {
					record, err := tx.FindRecordById("sessions", session.ID)
					if err != nil {
						return err
					}
					current, err := data.Decode[data.Session](record)
					if err != nil {
						return err
					}
					_, err = tx.DB().NewQuery("UPDATE sessions SET active=0,ended_ms={:end},revision=revision+1 WHERE id={:id}").Bind(dbx.Params{"end": current.Capture.ConfirmedMS, "id": session.ID}).Execute()
					return err
				}); err != nil {
					log.Print(err)
				}
			}()
			go func() {
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				writeStats := func() {
					encoded, err := json.Marshal(meter.Snapshot())
					if err == nil {
						err = os.WriteFile(filepath.Join(path, "source-stats.json.tmp"), encoded, 0600)
					}
					if err == nil {
						err = os.Rename(filepath.Join(path, "source-stats.json.tmp"), filepath.Join(path, "source-stats.json"))
					}
					if err != nil {
						log.Print(err)
					}
				}
				defer writeStats()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						writeStats()
						if meter.EndedMS.Load() > 0 {
							return
						}
					}
				}
			}()
			app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
				cancel()
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer closeCancel()
				if err := runtime.Close(closeCtx); err != nil {
					return err
				}
				return e.Next()
			})
			go func() {
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case now := <-ticker.C:
						cutoff := max(start, now.Add(-time.Duration(*minutes)*time.Minute).UnixMilli()/50*50)
						if cutoff <= start {
							continue
						}
						err := app.RunInTransaction(func(tx core.App) error {
							if err := observer.PruneSession(tx, session.ID, cutoff); err != nil {
								return err
							}
							_, err := tx.DB().NewQuery("UPDATE sessions SET retained_from_ms={:cut},revision=revision+1 WHERE id={:id}").Bind(dbx.Params{"cut": cutoff, "id": session.ID}).Execute()
							return err
						})
						if err != nil {
							log.Printf("load retention: %v", err)
						}
					}
				}
			}()
		}
		return e.Next()
	})
	app.RootCmd.SetArgs([]string{"serve", "--http", *listen})
	must(app.Start())
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
