package observer

import (
	"fmt"
	"myapp/data"
	"myapp/netmeta"
	"sort"
	"time"
)

const maxConnections = 8192

type connection struct {
	id, clientID                 string
	tuple                        netmeta.FlowTuple
	started, last, ctAt, ctBytes int64
	sent, received               int64
	established, closed          bool
	evidence                     data.Attribution
	service, label               string
}
type contribution struct {
	flow    string
	chunk   data.TrafficChunk
	samples map[int64]data.Sample
}

// aggregate owns the bounded correction tail. Contributions never leave memory;
// only their sum by product dimensions is persisted.
type aggregate struct {
	session, epoch string
	policy         data.Policy
	limit          int
	flows          map[string]*connection
	clients        map[string]string
	parts          map[string]*contribution
	dns            dnsCache
	generation     int64
	frozenBefore   int64
	dropped        int64
	lossAt         int64
	pending        map[string]CommittedTraffic
}

type CommittedTraffic struct {
	Session, NetworkEpoch, IP, Protocol string
	Port                                int
	Bytes                               int64
	At                                  time.Time
}

func newAggregate(session, epoch string, policy data.Policy, limit int) *aggregate {
	return &aggregate{session: session, epoch: epoch, policy: policy, limit: limit, flows: map[string]*connection{}, clients: map[string]string{}, parts: map[string]*contribution{}, pending: map[string]CommittedTraffic{}}
}

func (a *aggregate) client(ip, mac string) string {
	previous, known := a.clients[ip]
	if mac == "" {
		mac = previous
	}
	if known && previous != mac {
		a.dns.forgetClient(ip)
		for _, f := range a.flows {
			if f.tuple.ClientIP.String() == ip {
				f.closed = true
			}
		}
	}
	if len(a.clients) >= 1024 && !known { // Keep identity bounded; an unknown lease cannot borrow another client.
		a.dns.forgetClient(ip)
		return data.ID(a.session, a.epoch, ip)
	}
	a.clients[ip] = mac
	if mac == "" {
		return data.ID(a.session, a.epoch, ip)
	}
	return data.ID(a.session, ip, mac)
}

func (a *aggregate) packet(e PacketActivityEvent, network string, destination data.Destination) {
	tuple := e.Tuple
	if !tuple.ClientIP.IsValid() {
		var ok bool
		tuple, ok = tupleFromKey(e.FlowKey)
		if !ok {
			return
		}
	}
	now := e.ObservedAt.UnixMilli()
	// Source packets and heartbeats are ordered. A backwards wall-clock jump
	// must not introduce new bins into the sealed prefix already projected.
	if now < a.frozenBefore {
		a.dropped++
		a.lossAt = max(a.lossAt, a.frozenBefore)
		return
	}
	key := tuple.Key()
	client := a.client(tuple.ClientIP.String(), e.ClientMAC)
	f := a.flows[key]
	syn := tuple.Protocol == "tcp" && e.TCPFlags&0x12 == 0x02
	if f != nil && (f.clientID != client || f.closed || (syn && f.established) || now-f.last > 120000 || (tuple.Protocol == "udp" && now-f.last > 30000)) {
		delete(a.flows, key)
		f = nil
	}
	if f == nil {
		if len(a.flows) >= maxConnections {
			var oldest *connection
			var oldkey string
			for k, v := range a.flows {
				if oldest == nil || v.last < oldest.last {
					oldest = v
					oldkey = k
				}
			}
			// Evidence evicted from the identity cache is not trustworthy for reuse.
			a.dns.forgetClient(oldest.tuple.ClientIP.String())
			delete(a.flows, oldkey)
		}
		f = &connection{id: data.NewID(), clientID: client, tuple: tuple, started: now, last: now}
		a.flows[key] = f
	}
	f.last = max(f.last, now)
	f.established = f.established || (!syn && e.TCPFlags&0x10 != 0)
	f.service, f.label, f.evidence = a.dns.resolve(a.session, tuple, f.started, now, a.policy, f.evidence)
	start := now / a.policy.ChunkMS * a.policy.ChunkMS
	partKey := f.id + "|" + network + "|" + destination.ID + "|" + fmt.Sprint(start) + "|" + f.service
	p := a.parts[partKey]
	if p == nil {
		if len(a.parts) >= a.limit {
			a.dropped++
			a.lossAt = max(a.lossAt, now)
			return
		}
		p = &contribution{flow: f.id, chunk: data.TrafficChunk{Session: a.session, CaptureEpoch: a.epoch, ClientID: client, ClientIP: tuple.ClientIP.String(), ServiceKey: f.service, ServiceLabel: f.label, DestinationID: destination.ID, DestinationIP: tuple.RemoteIP.String(), Protocol: tuple.Protocol, DestinationPort: int(tuple.RemotePort), NetworkEpoch: network, StartMS: start, BucketMS: a.policy.BucketMS, ChunkMS: a.policy.ChunkMS, Evidence: f.evidence}, samples: map[int64]data.Sample{}}
		a.parts[partKey] = p
	}
	offset := (now - start) / a.policy.BucketMS * a.policy.BucketMS
	sample := p.samples[offset]
	sample[0] = offset
	direction := 1
	if e.Direction == RemoteToClient {
		direction = 2
	}
	sample[direction] += int64(e.WireBytes)
	if direction == 1 {
		f.sent += int64(e.WireBytes)
	} else {
		f.received += int64(e.WireBytes)
	}
	sample[direction+2] += int64(e.PayloadBytes)
	sample[direction+4]++
	p.samples[offset] = sample
	binding := network + "|" + tuple.RemoteIP.String() + "|" + tuple.Protocol + "|" + fmt.Sprint(tuple.RemotePort)
	delta := a.pending[binding]
	delta.Session = a.session
	delta.NetworkEpoch = network
	delta.IP = tuple.RemoteIP.String()
	delta.Protocol = tuple.Protocol
	delta.Port = int(tuple.RemotePort)
	delta.Bytes += int64(e.WireBytes)
	delta.At = e.ObservedAt
	a.pending[binding] = delta
	if e.TCPFlags&0x05 != 0 {
		f.closed = true
	}
}

func (a *aggregate) conntrack(samples []FlowSample, at int64) {
	seen := map[string]bool{}
	for _, s := range samples {
		key := s.Key()
		f := a.flows[key]
		if f == nil {
			continue
		}
		seen[key] = true
		total := s.BytesOut + s.BytesIn
		if f.ctAt > 0 && total < f.ctBytes {
			f.closed = true
		}
		f.ctAt = at
		f.ctBytes = total
		if s.State == "TIME_WAIT" || s.State == "CLOSE" {
			f.closed = true
		}
	}
	for key, f := range a.flows {
		if f.ctAt > 0 && !seen[key] {
			f.closed = true
		}
		if at-f.last > 120000 {
			delete(a.flows, key)
		}
	}
}

// Corrections move sample contributions, never copies. Old bins retain the
// evidence they had when the correction horizon elapsed.
func (a *aggregate) correct(now int64) {
	active := map[string]*connection{}
	for _, f := range a.flows {
		f.service, f.label, f.evidence = a.dns.resolve(a.session, f.tuple, f.started, now, a.policy, f.evidence)
		active[f.id] = f
	}
	additions := map[string]*contribution{}
	for _, p := range a.parts {
		f := active[p.flow]
		if f == nil || (f.service == p.chunk.ServiceKey && f.evidence == p.chunk.Evidence) {
			continue
		}
		key := p.flow + "|" + p.chunk.NetworkEpoch + "|" + p.chunk.DestinationID + "|" + fmt.Sprint(p.chunk.StartMS) + "|" + f.service
		target := a.parts[key]
		if target == p {
			p.chunk.Evidence = f.evidence
			continue
		}
		if target == nil {
			target = additions[key]
		}
		if target == nil {
			if len(a.parts)+len(additions) >= 3*a.limit {
				continue
			} // Reserve correction space beyond the packet intake cap.
			c := p.chunk
			c.ServiceKey = f.service
			c.ServiceLabel = f.label
			c.Evidence = f.evidence
			target = &contribution{flow: p.flow, chunk: c, samples: map[int64]data.Sample{}}
			additions[key] = target
		}
		for offset, s := range p.samples {
			if p.chunk.StartMS+offset < now-a.policy.CorrectionMS {
				continue
			}
			t := target.samples[offset]
			t[0] = offset
			for i := 1; i < len(s); i++ {
				t[i] += s[i]
			}
			target.samples[offset] = t
			delete(p.samples, offset)
		}
	}
	for k, p := range a.parts {
		if len(p.samples) == 0 {
			delete(a.parts, k)
		}
	}
	for k, p := range additions {
		if len(p.samples) > 0 {
			a.parts[k] = p
		}
	}
}

func chunkID(c data.TrafficChunk) string {
	return data.ID(c.Session, c.CaptureEpoch, c.ClientID, c.ServiceKey, c.DestinationID, c.Protocol, fmt.Sprint(c.DestinationPort), c.NetworkEpoch, fmt.Sprint(c.StartMS))
}
func (a *aggregate) snapshot(now int64) []data.TrafficChunk {
	a.correct(now)
	a.generation++
	groups := map[string]*contribution{}
	for _, p := range a.parts {
		id := chunkID(p.chunk)
		g := groups[id]
		if g == nil {
			c := p.chunk
			c.ID = id
			c.Generation = a.generation
			c.Sealed = c.StartMS+c.ChunkMS <= now-a.policy.CorrectionMS
			g = &contribution{chunk: c, samples: map[int64]data.Sample{}}
			groups[id] = g
		}
		if g.chunk.Evidence != p.chunk.Evidence {
			if g.chunk.Evidence.Confidence != p.chunk.Evidence.Confidence {
				g.chunk.Evidence.Confidence = "mixed"
			}
			if g.chunk.Evidence.Hostname != p.chunk.Evidence.Hostname {
				g.chunk.Evidence.Hostname = ""
			}
			g.chunk.Evidence.ObservedMS = max(g.chunk.Evidence.ObservedMS, p.chunk.Evidence.ObservedMS)
			g.chunk.Evidence.Ambiguous = g.chunk.Evidence.Ambiguous || p.chunk.Evidence.Ambiguous
			g.chunk.Evidence.Source = "combined"
		}
		for offset, s := range p.samples {
			t := g.samples[offset]
			t[0] = offset
			for i := 1; i < len(s); i++ {
				t[i] += s[i]
			}
			g.samples[offset] = t
		}
	}
	chunks := make([]data.TrafficChunk, 0, len(groups))
	for _, g := range groups {
		for _, s := range g.samples {
			g.chunk.Samples = append(g.chunk.Samples, s)
		}
		sort.Slice(g.chunk.Samples, func(i, j int) bool { return g.chunk.Samples[i][0] < g.chunk.Samples[j][0] })
		chunks = append(chunks, g.chunk)
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].ID < chunks[j].ID })
	return chunks
}
func (a *aggregate) committed(now, floor int64) {
	a.frozenBefore = max(a.frozenBefore, (now-a.policy.CorrectionMS)/a.policy.ChunkMS*a.policy.ChunkMS, floor)
	for key, p := range a.parts {
		if p.chunk.StartMS+p.chunk.ChunkMS <= now-a.policy.CorrectionMS || p.chunk.StartMS+p.chunk.ChunkMS <= floor {
			delete(a.parts, key)
		}
	}
	a.pending = map[string]CommittedTraffic{}
	a.dropped = 0
}
