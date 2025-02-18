package lib

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// createPacketRecord is your existing function that logs a new 'packets' record
func CreatePacketRecord(sessionID string, clientIP string, hostname string, app *pocketbase.PocketBase, geoipDB *geoip2.Reader) (string, error) {
	hostIPs, lookupErr := net.LookupIP(hostname)
	if lookupErr != nil {
		log.Printf("lookup error: %s", lookupErr)
		return "", lookupErr
	}

	var hostIP net.IP
	for _, ip := range hostIPs {
		if ip.To4() != nil {
			hostIP = ip
			break
		}
	}

	if hostIP == nil {
		log.Printf("no IPv4 address found for host: %s", hostname)
		return "", nil
	}

	geoRecord, geoErr := geoipDB.City(hostIP)
	if geoErr != nil {
		log.Printf("geoip error: %s", geoErr)
		return "", geoErr
	}

	collection, err := app.FindCollectionByNameOrId("packets")
	if err != nil {
		log.Printf("collection error: %s", err)
		return "", err
	}

	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("ip", hostIP.String())
	record.Set("client_ip", clientIP)
	record.Set("host", hostname)
	record.Set("lat", geoRecord.Location.Latitude)
	record.Set("lon", geoRecord.Location.Longitude)
	record.Set("data", []interface{}{})
	record.Set("city", geoRecord.City.Names["en"])
	record.Set("country", geoRecord.Country.Names["en"])

	err = app.Save(record)
	if err != nil {
		log.Printf("save error: %s", err)
		return "", err
	}

	return record.Id, nil
}

type PacketAggregator struct {
	mu       sync.Mutex
	inCount  int64
	outCount int64
	entries  []interface{}
	recordID string
	app      *pocketbase.PocketBase
}

func NewPacketAggregator(recordID string, app *pocketbase.PocketBase) *PacketAggregator {
	return &PacketAggregator{
		inCount:  0,
		outCount: 0,
		entries:  make([]interface{}, 0),
		recordID: recordID,
		app:      app,
	}
}

func (a *PacketAggregator) Add(direction string, n int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if direction == "in" {
		a.inCount += n
	} else if direction == "out" {
		a.outCount += n
	}
}

func (a *PacketAggregator) Flush() {
	now := time.Now().Format(time.RFC3339)
	a.mu.Lock()
	if a.inCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "in",
			"bytes": a.inCount,
		}
		a.entries = append(a.entries, entry)
		a.inCount = 0
	}
	if a.outCount > 0 {
		entry := map[string]interface{}{
			"ts":    now,
			"dir":   "out",
			"bytes": a.outCount,
		}
		a.entries = append(a.entries, entry)
		a.outCount = 0
	}
	currentEntries := make([]interface{}, len(a.entries))
	copy(currentEntries, a.entries)
	a.mu.Unlock()

	// Update the record with the aggregator data
	if err := updatePacketRecordDataWithAccumulator(a.recordID, currentEntries, a.app); err != nil {
		log.Printf("Failed to update aggregator for record %s: %s", a.recordID, err)
	}
}

func updatePacketRecordDataWithAccumulator(recordID string, entries []interface{}, app *pocketbase.PocketBase) error {
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("updatePacketRecordDataWithAccumulator: could not find record %s: %s", recordID, err)
		return err
	}
	record.Set("data", entries)
	if err := app.Save(record); err != nil {
		log.Printf("updatePacketRecordDataWithAccumulator: save error: %s", err)
		return err
	}
	return nil
}

func ClosePacketRecord(recordID string, app *pocketbase.PocketBase) error {
	record, err := app.FindRecordById("packets", recordID)
	if err != nil {
		log.Printf("closePacketRecord: could not find record %s: %s", recordID, err)
		return err
	}
	record.Set("closed", time.Now().Format(time.RFC3339))
	err = app.Save(record)
	if err != nil {
		log.Printf("closePacketRecord: save error: %s", err)
		return err
	}
	return nil
}

// copyAndUpdate transfers data and updates the aggregator in/out counters.
func CopyAndUpdatePacket(dst io.Writer, src io.Reader, direction string, aggregator *PacketAggregator) error {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			if written > 0 {
				aggregator.Add(direction, int64(written))
			}
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
