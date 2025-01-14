package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
)

func SetSocketOptions(network string, address string, c syscall.RawConn) error {
	var fn = func(s uintptr) {
		var setErr error
		var getErr error
		// syscall.SOL
		setErr = syscall.SetsockoptInt(int(s), 0x0, 0x13, 1)
		if setErr != nil {
			log.Fatal(setErr)
		}

		val, getErr := syscall.GetsockoptInt(int(s), 0x0, 0x13)
		if getErr != nil {
			log.Fatal(getErr)
		}
		log.Printf("value of IP_TRANSPARENT option is: %d", int(val))
	}
	if err := c.Control(fn); err != nil {
		return err
	}

	return nil

}

// func TransparentHttpProxy(w http.ResponseWriter, r *http.Request) {
// 	log.Print("request")
// 	director := func(target *http.Request) {
// 		target.URL.Scheme = "http"
// 		target.URL.Path = r.URL.Path
// 		target.Header.Set("Pass-Via-Go-Proxy", "1")
// 		log.Print(target.URL.Host)
// 		/*
// 			Line below of this comment this is the quite tricky part of the configuration,
// 			necessary to make transparent proxy working.

// 			From http.LocalAddrContextKey we can get address:port destination of client requst.
// 			In fact address:port values from http.LocalAddrContextKey,
// 			are the values from socket dynamicly created by tproxy.
// 			This will be used to create a connection between the proxy and the destination,
// 			to which the client request will be pass.
// 		*/
// 		target.URL.Host = fmt.Sprint(r.Context().Value(http.LocalAddrContextKey))
// 	}
// 	proxy := &httputil.ReverseProxy{Director: director}
// 	proxy.ServeHTTP(w, r)

// }

func main() {
	app := pocketbase.New()

	// // serves static files from the provided public dir (if exists)
	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS("./pb_public"), false))
		return nil
	})

	go func() {
		if err := app.Start(); err != nil {
			log.Fatal(err)
		}
	}()

	geoipDB, _ := geoip2.Open("./geoip/city.mmdb")
	defer geoipDB.Close()

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 1337,
		},
		// OnRequest: func(session *gomitmproxy.Session) (request *http.Request, response *http.Response) {
		// 	req := session.Request()

		// 	log.Printf("onRequest: %s %s", req.Method, req.URL.String())

		// 	trace := &httptrace.ClientTrace{
		// 		GotConn: func(connInfo httptrace.GotConnInfo) {
		// 			log.Printf("resolved to: %s", connInfo.Conn.RemoteAddr())
		// 		},
		// 	}

		// 	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), nil
		// },
		OnResponse: func(session *gomitmproxy.Session) *http.Response {
			req := session.Request()
			res := session.Response()

			log.Printf("onResponse: %s %s, %s, %s", req.Method, req.URL.String(), req.RemoteAddr, req.Host)

			// strip just hostname
			host := strings.Split(req.Host, ":")[0]

			hostIP, lookupErr := net.LookupIP(host)
			if lookupErr != nil {
				log.Printf("lookup error: %s", lookupErr)
				return nil
			}

			if len(hostIP) == 0 {
				log.Print("no IP found for host")
				return nil
			}

			log.Printf("IP: %s", hostIP)
			geoRecord, _ := geoipDB.City(hostIP[len(hostIP)-1])
			log.Printf("location: %f", geoRecord.Location.Latitude)

			collection, _ := app.Dao().FindCollectionByNameOrId("packet")
			record := models.NewRecord(collection)
			record.Set("host", req.Host)
			record.Set("method", req.Method)
			record.Set("protocol", req.Proto)
			record.Set("accept", res.Header.Get("Accept"))
			record.Set("contentType", res.Header.Get("Content-Type"))
			record.Set("lat", geoRecord.Location.Latitude)
			record.Set("lon", geoRecord.Location.Longitude)
			record.Set("city", geoRecord.City.Names["en"])
			record.Set("country", geoRecord.Country.Names["en"])
			region := ""
			if len(geoRecord.Subdivisions) > 0 {
				region = geoRecord.Subdivisions[0].Names["en"]
			}
			record.Set("region", region)

			app.Dao().SaveRecord(record)

			return nil
		},
	})

	go func() {

		proxyErr := proxy.Start()
		if proxyErr != nil {
			log.Fatal(proxyErr)
		}

	}()

	// go func() {
	// 	// proxyErr := proxy.Start()
	// 	// if proxyErr != nil {
	// 	// 	log.Fatal(proxyErr)
	// 	// }
	// 	http.HandleFunc("/*", TransparentHttpProxy)

	// 	// here we are creating custom listener with transparent socket, possible with Go 1.11+
	// 	lc := net.ListenConfig{}
	// 	listener, _ := lc.Listen(context.Background(), "tcp", ":8888")

	// 	log.Printf("Starting http proxy")
	// 	log.Fatal(http.Serve(listener, nil))
	// }()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
}
