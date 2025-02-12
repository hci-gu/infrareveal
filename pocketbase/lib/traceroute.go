package lib

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"

	iata "github.com/echa/code/iata"
)

// Hop represents a single hop in the traceroute output
type Hop struct {
	TTL       int       // Hop number
	Address   string    // IP or Hostname
	Timings   []float64 // Latency timings in milliseconds
	Latitude  float64
	Longitude float64
	City      string
	Country   string
}

func reverseDNS(ip string) (string, error) {
	addrs, err := net.LookupAddr(ip)
	if err != nil || len(addrs) == 0 {
		return "", err
	}

	return strings.TrimSuffix(addrs[0], "."), nil
}

func parseIATA(hostname string) *iata.Airport {
	// Convert to lowercase for easier searching
	// (the echa/code package expects uppercase codes, so we'll re-upcase as we go).
	lowerHost := strings.ToLower(hostname)

	// Split on '.' or '-' or any other delimiters to isolate tokens
	tokens := strings.FieldsFunc(lowerHost, func(r rune) bool {
		return r == '.' || r == '-'
	})

	for _, t := range tokens {
		// We only check tokens that are 3 letters for IATA
		if len(t) != 3 {
			continue
		}
		// Convert token to uppercase before parsing in echa/code
		tokenUpper := strings.ToUpper(t)

		// Use ParseAirportCode to parse the token as an IATA code
		code := iata.ParseAirportCode(tokenUpper)
		if !code.IsValid() {
			continue
		}

		// We have a valid IATA code. Look up the Airport object.
		airport := code.Airport() // iata.Airport

		return &airport
	}

	return nil
}

// RunTraceroute executes the traceroute command and returns parsed hops
func RunTraceroute(sessionID string, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, hostname string) error {
	var cmd *exec.Cmd

	cmd = exec.Command("traceroute", hostname)

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run traceroute: %v", err)
	}

	// Parse the output and extract hops
	hops := parseTracerouteOutput(string(output))

	cleanedHops := cleanHops(hops)

	for i := range cleanedHops {
		hostname, err := reverseDNS(cleanedHops[i].Address)
		if err == nil {
			cleanedHops[i].Address = hostname
		}
	}

	geolocateHops(cleanedHops, geoipDB)

	for i := range cleanedHops {
		// if lat/lon are not set, try to parse IATA code
		if cleanedHops[i].Latitude == 0 && cleanedHops[i].Longitude == 0 {
			airport := parseIATA(cleanedHops[i].Address)
			if airport != nil {
				cleanedHops[i].Latitude = airport.Lat
				cleanedHops[i].Longitude = airport.Lon
				cleanedHops[i].Country = airport.Country.String()
			}
		}
	}

	// Store results in PB
	if err := createTracerouteRecord(sessionID, hostname, cleanedHops, app); err != nil {
		log.Printf("Failed to store traceroute for %s: %v", hostname, err)
	}

	return nil
}

// parseTracerouteOutput extracts hop details and converts timings to floats
func parseTracerouteOutput(output string) []Hop {
	lines := strings.Split(output, "\n")
	hops := []Hop{}

	// Regex pattern to match typical lines, e.g.:
	//   "1  192.168.1.1  1.2 ms  2.3 ms  3.1 ms"
	re := regexp.MustCompile(`^\s*(\d+)\s+([\d\.a-zA-Z\-\*]+)\s+(.*)$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			ttl := parseInt(matches[1])         // Hop number
			address := matches[2]               // IP or Hostname
			timings := parseTimings(matches[3]) // Convert timings to float slice

			hops = append(hops, Hop{
				TTL:     ttl,
				Address: address,
				Timings: timings,
			})
		}
	}

	return hops
}

// parseInt converts a string to an integer
func parseInt(str string) int {
	num, _ := strconv.Atoi(str)
	return num
}

// parseTimings extracts multiple timings from a string and converts them to float64
func parseTimings(timingStr string) []float64 {
	timingStr = strings.ReplaceAll(timingStr, " ms", "") // Remove "ms" suffix
	parts := strings.Fields(timingStr)                   // Split by whitespace
	var timings []float64

	for _, part := range parts {
		if num, err := strconv.ParseFloat(part, 64); err == nil {
			timings = append(timings, num)
		}
	}

	return timings
}

// geolocateHops populates the latitude/longitude/city/country for each hop
func geolocateHops(hops []Hop, geoipDB *geoip2.Reader) {
	for i := range hops {
		rawAddr := hops[i].Address

		// Skip placeholders like "* * *"
		if strings.Contains(rawAddr, "*") {
			continue
		}

		ip := net.ParseIP(rawAddr)
		// If not a direct IP, attempt DNS lookup
		if ip == nil {
			addrs, err := net.LookupIP(rawAddr)
			if err != nil || len(addrs) == 0 {
				continue
			}
			ip = addrs[0]
		}
		if ip == nil {
			continue
		}

		cityRecord, err := geoipDB.City(ip)
		if err != nil {
			continue
		}

		hops[i].Latitude = cityRecord.Location.Latitude
		hops[i].Longitude = cityRecord.Location.Longitude
		hops[i].City = cityRecord.City.Names["en"]
		hops[i].Country = cityRecord.Country.Names["en"]
	}
}

// cleanHops removes duplicates and hops with address "*"
func cleanHops(hops []Hop) []Hop {
	cleaned := make([]Hop, 0, len(hops))
	var lastAddr string

	for _, hop := range hops {
		if hop.Address == "*" {
			continue
		}
		if hop.Address == lastAddr {
			continue
		}
		cleaned = append(cleaned, hop)
		lastAddr = hop.Address
	}

	return cleaned
}

// createTracerouteRecord stores traceroute results in PocketBase
func createTracerouteRecord(sessionID, domain string, hops []Hop, app *pocketbase.PocketBase) error {
	collection, err := app.FindCollectionByNameOrId("traceroutes")
	if err != nil {
		log.Printf("createTracerouteRecord: collection error: %s", err)
		return err
	}

	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("domain", domain)

	var hopData []map[string]interface{}
	for _, h := range hops {
		hopData = append(hopData, map[string]interface{}{
			"ttl":       h.TTL,
			"address":   h.Address,
			"timings":   h.Timings,
			"latitude":  h.Latitude,
			"longitude": h.Longitude,
			"city":      h.City,
			"country":   h.Country,
		})
	}
	record.Set("hops", hopData)

	err = app.Save(record)
	if err != nil {
		log.Printf("createTracerouteRecord: save error: %s", err)
		return err
	}

	return nil
}
