package geo

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type ServiceLocation struct {
	ID        string                 `json:"id"`
	Service   string                 `json:"service"`
	Region    string                 `json:"region"`
	Country   string                 `json:"country"`
	Latitude  float64                `json:"latitude"`
	Longitude float64                `json:"longitude"`
	Altitude  float64                `json:"altitude_m"`
	Accuracy  float64                `json:"accuracy_m"`
	LastSeen  time.Time              `json:"last_seen"`
	LatencyMs float64                `json:"latency_ms"`
	Capacity  map[string]interface{} `json:"capacity,omitempty"`
	Meta      map[string]interface{} `json:"meta,omitempty"`
}

type GeoIPResolver interface {
	ResolveIP(ip string) (countryCode string, latitude, longitude float64, err error)
	Name() string
}

type ElevationProvider interface {
	GetElevation(lat, lon float64) (altitudeMeters float64, err error)
	Name() string
}

type LatencyEstimator interface {
	EstimateLatency(fromLat, fromLon float64, to ServiceLocation) (ms float64, err error)
	Name() string
}

type Subscriber func(event string, loc ServiceLocation)

type LocationManager struct {
	mu               sync.RWMutex
	locations        map[string]ServiceLocation
	subscribers      []Subscriber
	geoIP            GeoIPResolver
	elevation        ElevationProvider
	latencyEstimator LatencyEstimator
	staleThreshold   time.Duration
}

func NewLocationManager() *LocationManager {
	return &LocationManager{
		locations:      make(map[string]ServiceLocation),
		subscribers:    make([]Subscriber, 0),
		staleThreshold: 24 * time.Hour,
	}
}

func (lm *LocationManager) SetProviders(geoIP GeoIPResolver, elev ElevationProvider, latEst LatencyEstimator) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.geoIP = geoIP
	lm.elevation = elev
	lm.latencyEstimator = latEst
}

func (lm *LocationManager) Subscribe(s Subscriber) (unsubscribe func()) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.subscribers = append(lm.subscribers, s)
	idx := len(lm.subscribers) - 1
	return func() {
		lm.mu.Lock()
		defer lm.mu.Unlock()
		if idx >= 0 && idx < len(lm.subscribers) {
			lm.subscribers[idx] = nil
		}
	}
}

func (lm *LocationManager) notify(event string, loc ServiceLocation) {
	lm.mu.RLock()
	subs := append([]Subscriber(nil), lm.subscribers...)
	lm.mu.RUnlock()
	for _, s := range subs {
		if s == nil {
			continue
		}
		go func(sub Subscriber, l ServiceLocation) {
			defer func() { _ = recover() }()
			sub(event, l)
		}(s, loc)
	}
}

func (lm *LocationManager) Register(loc ServiceLocation) {
	lm.mu.Lock()
	if loc.LastSeen.IsZero() {
		loc.LastSeen = time.Now()
	}
	lm.locations[loc.ID] = loc
	lm.mu.Unlock()
	lm.notify("register", loc)

	if loc.Altitude == 0 && lm.elevation != nil {
		go func(id string, lat, lon float64) {
			if alt, err := lm.elevation.GetElevation(lat, lon); err == nil {
				lm.mu.Lock()
				if cur, ok := lm.locations[id]; ok {
					cur.Altitude = alt
					lm.locations[id] = cur
					lm.mu.Unlock()
					lm.notify("elevation_filled", cur)
					return
				}
				lm.mu.Unlock()
			}
		}(loc.ID, loc.Latitude, loc.Longitude)
	}
}

func (lm *LocationManager) Deregister(id string) {
	lm.mu.Lock()
	if loc, ok := lm.locations[id]; ok {
		delete(lm.locations, id)
		lm.mu.Unlock()
		lm.notify("deregister", loc)
		return
	}
	lm.mu.Unlock()
}

func (lm *LocationManager) Get(id string) (ServiceLocation, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	loc, ok := lm.locations[id]
	return loc, ok
}

func (lm *LocationManager) UpdateHeartbeat(id string, latencyMs float64, meta map[string]interface{}) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	loc, ok := lm.locations[id]
	if !ok {
		return errors.New("location not found")
	}
	loc.LastSeen = time.Now()
	if latencyMs >= 0 {
		loc.LatencyMs = latencyMs
	}
	if meta != nil {
		if loc.Meta == nil {
			loc.Meta = make(map[string]interface{})
		}
		for k, v := range meta {
			loc.Meta[k] = v
		}
	}
	lm.locations[id] = loc
	lm.notify("heartbeat", loc)
	return nil
}

func (lm *LocationManager) ListAll() []ServiceLocation {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	out := make([]ServiceLocation, 0, len(lm.locations))
	for _, v := range lm.locations {
		out = append(out, v)
	}
	return out
}

func (lm *LocationManager) GetByRegion(region string) []ServiceLocation {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	out := []ServiceLocation{}
	for _, loc := range lm.locations {
		if strings.EqualFold(loc.Region, region) {
			out = append(out, loc)
		}
	}
	return out
}

func (lm *LocationManager) FindNearest(lat, lon float64, n int) []ServiceLocation {
	all := lm.ListAll()
	type kv struct {
		loc  ServiceLocation
		dist float64
	}
	arr := make([]kv, 0, len(all))
	for _, loc := range all {
		d := HaversineMeters(lat, lon, loc.Latitude, loc.Longitude)
		arr = append(arr, kv{loc: loc, dist: d})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].dist < arr[j].dist })
	outN := make([]ServiceLocation, 0, minInt(n, len(arr)))
	for i := 0; i < minInt(n, len(arr)); i++ {
		outN = append(outN, arr[i].loc)
	}
	return outN
}

func (lm *LocationManager) FindWithinRadius(lat, lon float64, radiusMeters float64) []ServiceLocation {
	all := lm.ListAll()
	out := make([]ServiceLocation, 0)
	for _, loc := range all {
		d := HaversineMeters(lat, lon, loc.Latitude, loc.Longitude)
		if d <= radiusMeters {
			out = append(out, loc)
		}
	}
	return out
}

func (lm *LocationManager) GetClosestService(serviceName string, lat, lon float64) (ServiceLocation, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	bestD := math.MaxFloat64
	var best ServiceLocation
	found := false
	for _, loc := range lm.locations {
		if !strings.EqualFold(loc.Service, serviceName) {
			continue
		}
		d := HaversineMeters(lat, lon, loc.Latitude, loc.Longitude)
		if d < bestD {
			bestD = d
			best = loc
			found = true
		}
	}
	return best, found
}

func (lm *LocationManager) ResolveServiceRegion(serviceID string) (region, country string, lat, lon float64, ok bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	loc, found := lm.locations[serviceID]
	if !found {
		return "", "", 0, 0, false
	}
	return loc.Region, loc.Country, loc.Latitude, loc.Longitude, true
}

func (lm *LocationManager) EstimateLatencyBetweenServices(fromID, toID string) (float64, error) {
	lm.mu.RLock()
	from, fok := lm.locations[fromID]
	to, tok := lm.locations[toID]
	est := lm.latencyEstimator
	lm.mu.RUnlock()
	if !fok || !tok {
		return -1, errors.New("service(s) not found")
	}
	if est != nil {
		if v, err := est.EstimateLatency(from.Latitude, from.Longitude, to); err == nil {
			return v, nil
		}
	}
	// fallback: use stored latency if available
	if to.LatencyMs > 0 {
		return to.LatencyMs, nil
	}
	// approximate RTT ms by distance: one-way sec = dist / c_fiber (2e8 m/s)
	// approx RTT(ms) ~ 2 * dist_m / 2e5 = dist_m / 1e5
	dist := HaversineMeters(from.Latitude, from.Longitude, to.Latitude, to.Longitude)
	approx := dist / 1e5
	if approx < 0 {
		approx = 0
	}
	return approx, nil
}

func (lm *LocationManager) PruneStale(threshold time.Duration) int {
	if threshold <= 0 {
		threshold = lm.staleThreshold
	}
	cut := time.Now().Add(-threshold)
	lm.mu.Lock()
	defer lm.mu.Unlock()
	removed := 0
	for id, loc := range lm.locations {
		if loc.LastSeen.Before(cut) {
			delete(lm.locations, id)
			removed++
			go lm.notify("pruned", loc)
		}
	}
	return removed
}

func (lm *LocationManager) ExportJSON() ([]byte, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	list := make([]ServiceLocation, 0, len(lm.locations))
	for _, v := range lm.locations {
		list = append(list, v)
	}
	return json.MarshalIndent(list, "", "  ")
}

func (lm *LocationManager) LoadJSON(raw []byte) error {
	var arr []ServiceLocation
	if err := json.Unmarshal(raw, &arr); err != nil {
		return err
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for _, loc := range arr {
		if loc.LastSeen.IsZero() {
			loc.LastSeen = time.Now()
		}
		lm.locations[loc.ID] = loc
		go lm.notify("imported", loc)
	}
	return nil
}

func HaversineMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000.0
	toRad := func(deg float64) float64 { return deg * math.Pi / 180.0 }
	φ1 := toRad(lat1)
	φ2 := toRad(lat2)
	Δφ := toRad(lat2 - lat1)
	Δλ := toRad(lon2 - lon1)

	a := math.Sin(Δφ/2)*math.Sin(Δφ/2) +
		math.Cos(φ1)*math.Cos(φ2)*math.Sin(Δλ/2)*math.Sin(Δλ/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}