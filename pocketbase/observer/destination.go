package observer

import (
	"encoding/json"
	"github.com/oschwald/geoip2-golang"
	"myapp/data"
	"net"
	"time"
)

// A destination is a versioned snapshot. Capture only performs local lookups;
// resolver latency can never hold up the packet queue. Unknown geography stays
// explicitly unknown, even though PocketBase numeric fields default to zero.
func destinationSnapshot(db *geoip2.Reader, ip string, now time.Time) data.Destination {
	d := data.Destination{IP: ip, Precision: "unknown"}
	if db != nil {
		if city, err := db.City(net.ParseIP(ip)); err == nil {
			d.Country = city.Country.Names["en"]
			d.CountryCode = city.Country.IsoCode
			d.City = city.City.Names["en"]
			if d.CountryCode != "" {
				d.Precision = "country"
			}
			if d.City != "" && city.Location.AccuracyRadius > 0 {
				d.Precision = "city"
				d.Lat = &city.Location.Latitude
				d.Lon = &city.Location.Longitude
				d.AccuracyKM = int(city.Location.AccuracyRadius)
			}
		}
	}
	b, _ := json.Marshal(d)
	d.Version = data.ID(string(b))
	d.ID = data.ID(ip, d.Version)
	d.ObservedMS = now.UnixMilli()
	return d
}
