// internal/monitoring/service_monitor.go
// Service Health & Metrics Monitor — advanced institutional implementation
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Public types

type ServiceStatus string

const (
	StatusUp   ServiceStatus = "up"
	StatusDown ServiceStatus = "down"
	StatusWarn ServiceStatus = "warning"
)

// ServiceUsage: single point measurement
type ServiceUsage struct {
	ServiceName string        `json:"service_name"`
	CPU         float64       `json:"cpu_percent"`   // 0..100
	RAMMB       float64       `json:"ram_mb"`
	LatencyMS   float64       `json:"latency_ms"`
	ErrorRate   float64       `json:"error_rate"`    // 0..1
	Status      ServiceStatus `json:"status"`
	Timestamp   time.Time     `json:"timestamp"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// HealthSnapshot: compact summary returned by monitor
type HealthSnapshot struct {
	ServiceName string                 `json:"service_name"`
	HealthScore float64                `json:"health_score"` // 0..100, higher = healthier
	Status      ServiceStatus          `json:"status"`
	Latest      ServiceUsage           `json:"latest"`
	Anomaly     bool                   `json:"anomaly"`
	Reason      string                 `json:"reason,omitempty"`
	Trend      map[string]float64      `json:"trend,omitempty"` // simple trends e.g. cpu_delta, latency_delta
	Meta       map[string]interface{}  `json:"meta,omitempty"`
}

// AutoHealer: interface to connect to orchestrator or custom healing logic
type AutoHealer interface {
	Restart(ctx context.Context, service string) error
	Scale(ctx context.Context, service string, instances int) error
	Name() string
}

// TSDBWriter: interface to write metrics to time-series DB (optional)
type TSDBWriter interface {
	Write(ctx context.Context, svc string, usage ServiceUsage) error
	Name() string
}

// Subscriber: callback for events (anomaly/health change/suggestion)
type Subscriber func(event string, snapshot HealthSnapshot)

// internal rolling window stats (keeps last N samples)
type rollingWindow struct {
	sync.RWMutex
	size int
	buf  []ServiceUsage
	ptr  int
	full bool
}

func newRollingWindow(size int) *rollingWindow {
	if size <= 0 {
		size = 128
	}
	return &rollingWindow{
		size: size,
		buf:  make([]ServiceUsage, size),
		ptr:  0,
		full: false,
	}
}

func (r *rollingWindow) push(u ServiceUsage) {
	r.Lock()
	defer r.Unlock()
	r.buf[r.ptr] = u
	r.ptr++
	if r.ptr >= r.size {
		r.ptr = 0
		r.full = true
	}
}

func (r *rollingWindow) list() []ServiceUsage {
	r.RLock()
	defer r.RUnlock()
	var out []ServiceUsage
	if !r.full {
		out = append([]ServiceUsage(nil), r.buf[:r.ptr]...)
	} else {
		out = append([]ServiceUsage(nil), r.buf[r.ptr:]...)
		out = append(out, r.buf[:r.ptr]...)
	}
	return out
}

func (r *rollingWindow) latest() (ServiceUsage, bool) {
	r.RLock()
	defer r.RUnlock()
	if !r.full && r.ptr == 0 {
		return ServiceUsage{}, false
	}
	idx := r.ptr - 1
	if idx < 0 {
		idx = r.size - 1
	}
	return r.buf[idx], true
}

// PatternModel: light-weight learned pattern for a service (EWMA-based)
type PatternModel struct {
	CPU_EWMA     float64
	RAM_EWMA     float64
	Latency_EWMA float64
	Error_EWMA   float64
	alpha        float64 // smoothing factor
	seen         int
}

func newPatternModel(alpha float64) *PatternModel {
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.3
	}
	return &PatternModel{alpha: alpha}
}

func (p *PatternModel) observe(u ServiceUsage) {
	if p.seen == 0 {
		p.CPU_EWMA = u.CPU
		p.RAM_EWMA = u.RAMMB
		p.Latency_EWMA = u.LatencyMS
		p.Error_EWMA = u.ErrorRate
		p.seen = 1
		return
	}
	a := p.alpha
	p.CPU_EWMA = a*u.CPU + (1-a)*p.CPU_EWMA
	p.RAM_EWMA = a*u.RAMMB + (1-a)*p.RAM_EWMA
	p.Latency_EWMA = a*u.LatencyMS + (1-a)*p.Latency_EWMA
	p.Error_EWMA = a*u.ErrorRate + (1-a)*p.Error_EWMA
	p.seen++
}

func (p *PatternModel) predictNext() (cpu, ram, latency, errr float64) {
	return p.CPU_EWMA, p.RAM_EWMA, p.Latency_EWMA, p.Error_EWMA
}

// ServiceEntry: internal record per service
type serviceEntry struct {
	history    *rollingWindow
	model      *PatternModel
	lastScore  float64
	lastStatus ServiceStatus
	lastAnom   bool
	lastReason string
	config     ServiceConfig
	tsdb       TSDBWriter
}

// ServiceConfig: thresholds & behavior for a specific service
type ServiceConfig struct {
	HistorySize        int
	AnomalyZThreshold  float64 // z-score threshold for anomaly detection
	HealthWeightCPU    float64 // weights for healthscore
	HealthWeightRAM    float64
	HealthWeightLatency float64
	HealthWeightError  float64
	AutoHealEnabled    bool
	AutoHealOnAnomaly  bool
	AutoHealCooldown   time.Duration
	MaxStoredHistory   int
}

func defaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		HistorySize:         256,
		AnomalyZThreshold:   3.0,
		HealthWeightCPU:     0.3,
		HealthWeightRAM:     0.2,
		HealthWeightLatency: 0.3,
		HealthWeightError:   0.2,
		AutoHealEnabled:     false,
		AutoHealOnAnomaly:   false,
		AutoHealCooldown:    2 * time.Minute,
		MaxStoredHistory:    1000,
	}
}

// ServiceMonitor: main manager
type ServiceMonitor struct {
	mu           sync.RWMutex
	services     map[string]*serviceEntry
	subscribers  []Subscriber
	autoHealer   AutoHealer
	tsdbWriter   TSDBWriter
	globalConfig ServiceConfig
	// auto-heal bookkeeping
	lastAutoHeal map[string]time.Time
}

// NewServiceMonitor
func NewServiceMonitor() *ServiceMonitor {
	return &ServiceMonitor{
		services:     make(map[string]*serviceEntry),
		subscribers:  nil,
		globalConfig: defaultServiceConfig(),
		lastAutoHeal: make(map[string]time.Time),
	}
}

// RegisterAutoHealer
func (sm *ServiceMonitor) RegisterAutoHealer(h AutoHealer) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.autoHealer = h
}

// RegisterTSDBWriter
func (sm *ServiceMonitor) RegisterTSDBWriter(w TSDBWriter) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.tsdbWriter = w
}

// Subscribe
func (sm *ServiceMonitor) Subscribe(s Subscriber) (unsubscribe func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.subscribers = append(sm.subscribers, s)
	idx := len(sm.subscribers) - 1
	return func() {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		if idx >= 0 && idx < len(sm.subscribers) {
			sm.subscribers[idx] = nil
		}
	}
}

func (sm *ServiceMonitor) notifyAll(event string, snap HealthSnapshot) {
	sm.mu.RLock()
	subs := append([]Subscriber(nil), sm.subscribers...)
	sm.mu.RUnlock()
	for _, s := range subs {
		if s == nil {
			continue
		}
		go func(sub Subscriber, ev string, sh HealthSnapshot) {
			defer func() { _ = recover() }()
			sub(ev, sh)
		}(s, event, snap)
	}
}

// configure service (optional)
func (sm *ServiceMonitor) ConfigureService(service string, cfg ServiceConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	e, ok := sm.services[service]
	if !ok {
		e = &serviceEntry{
			history: newRollingWindow(cfg.HistorySize),
			model:   newPatternModel(0.25),
			config:  cfg,
		}
		sm.services[service] = e
		return
	}
	e.config = cfg
}

// ensureEntry returns or creates entry
func (sm *ServiceMonitor) ensureEntry(service string) *serviceEntry {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if e, ok := sm.services[service]; ok {
		return e
	}
	cfg := sm.globalConfig
	e := &serviceEntry{
		history: newRollingWindow(cfg.HistorySize),
		model:   newPatternModel(0.25),
		config:  cfg,
	}
	sm.services[service] = e
	return e
}

// Report: ingest new measurement; non-blocking notifications & optional TSDB write
func (sm *ServiceMonitor) Report(ctx context.Context, usage ServiceUsage) {
	usage.Timestamp = usage.Timestamp.UTC()
	e := sm.ensureEntry(usage.ServiceName)
	// push history & observe model
	e.history.push(usage)
	e.model.observe(usage)
	// write to tsdb asynchronously if configured
	if sm.tsdbWriter != nil {
		go func(w TSDBWriter, ctx context.Context, svc string, u ServiceUsage) {
			_ = w.Write(ctx, svc, u) // ignore error here (could log)
		}(sm.tsdbWriter, ctx, usage.ServiceName, usage)
	}
	// compute snapshot and anomaly
	snap := sm.evaluateSnapshot(usage.ServiceName)
	// notify subscribers
	sm.notifyAll("update", snap)
	// optionally auto-heal
	sm.maybeAutoHeal(ctx, usage.ServiceName, snap)
}

// evaluateSnapshot builds HealthSnapshot for a service
func (sm *ServiceMonitor) evaluateSnapshot(service string) HealthSnapshot {
	e := sm.ensureEntry(service)
	latest, ok := e.history.latest()
	if !ok {
		return HealthSnapshot{ServiceName: service, HealthScore: 0, Status: StatusDown}
	}
	// compute simple stats
	hist := e.history.list()
	n := len(hist)
	var cpuSum, ramSum, latSum, errSum float64
	for _, s := range hist {
		cpuSum += s.CPU
		ramSum += s.RAMMB
		latSum += s.LatencyMS
		errSum += s.ErrorRate
	}
	avgCPU := cpuSum / float64(n)
	avgRAM := ramSum / float64(n)
	avgLat := latSum / float64(n)
	avgErr := errSum / float64(n)

	// compute z-score for latest values (stddev)
	var cpuVar, ramVar, latVar, errVar float64
	for _, s := range hist {
		cpuVar += (s.CPU - avgCPU) * (s.CPU - avgCPU)
		ramVar += (s.RAMMB - avgRAM) * (s.RAMMB - avgRAM)
		latVar += (s.LatencyMS - avgLat) * (s.LatencyMS - avgLat)
		errVar += (s.ErrorRate - avgErr) * (s.ErrorRate - avgErr)
	}
	if n > 1 {
		cpuVar /= float64(n-1)
		ramVar /= float64(n-1)
		latVar /= float64(n-1)
		errVar /= float64(n-1)
	}
	cpuStd := math.Sqrt(cpuVar)
	ramStd := math.Sqrt(ramVar)
	latStd := math.Sqrt(latVar)
	errStd := math.Sqrt(errVar)

	zCPU := safeZscore(latest.CPU, avgCPU, cpuStd)
	zRAM := safeZscore(latest.RAMMB, avgRAM, ramStd)
	zLat := safeZscore(latest.LatencyMS, avgLat, latStd)
	zErr := safeZscore(latest.ErrorRate, avgErr, errStd)

	// anomaly detection
	anom := false
	reasons := []string{}
	th := e.config.AnomalyZThreshold
	if math.Abs(zCPU) >= th {
		anom = true
		reasons = append(reasons, fmt.Sprintf("cpu_z=%.2f", zCPU))
	}
	if math.Abs(zRAM) >= th {
		anom = true
		reasons = append(reasons, fmt.Sprintf("ram_z=%.2f", zRAM))
	}
	if math.Abs(zLat) >= th {
		anom = true
		reasons = append(reasons, fmt.Sprintf("lat_z=%.2f", zLat))
	}
	if math.Abs(zErr) >= th {
		anom = true
		reasons = append(reasons, fmt.Sprintf("err_z=%.2f", zErr))
	}
	// HealthScore (0..100): higher = healthier
	// normalize metrics into 0..1 worst score then map to 0..100
	cpuScore := metricToScore(latest.CPU/100.0, avgCPU/100.0)    // CPU% mapped
	ramScore := metricToScore(latest.RAMMB/(avgRAM+1.0), avgRAM/(avgRAM+1.0))
	latScore := metricToScore(latest.LatencyMS/(avgLat+1.0), avgLat/(avgLat+1.0))
	errScore := metricToScore(latest.ErrorRate, avgErr)

	wcpu := e.config.HealthWeightCPU
	wram := e.config.HealthWeightRAM
	wlat := e.config.HealthWeightLatency
	werr := e.config.HealthWeightError
	// fallback to defaults if weights not configured
	if wcpu+wram+wlat+werr == 0 {
		wcpu, wram, wlat, werr = 0.3, 0.2, 0.3, 0.2
	}
	raw := cpuScore*wcpu + ramScore*wram + latScore*wlat + errScore*werr
	healthScore := mathMax(0.0, mathMin(100.0, raw*100.0))

	status := StatusUp
	if latest.Status == StatusDown || healthScore < 35 {
		status = StatusDown
	} else if anom || healthScore < 70 {
		status = StatusWarn
	}

	trend := map[string]float64{
		"cpu_avg":    avgCPU,
		"cpu_latest": latest.CPU,
		"lat_avg":    avgLat,
		"lat_latest": latest.LatencyMS,
	}

	snap := HealthSnapshot{
		ServiceName: service,
		HealthScore: healthScore,
		Status:      status,
		Latest:      latest,
		Anomaly:     anom,
		Reason:      strings.Join(reasons, "; "),
		Trend:       trend,
		Meta:        map[string]interface{}{"samples": n},
	}

	// store last computed values
	e.lastScore = healthScore
	e.lastStatus = status
	e.lastAnom = anom
	e.lastReason = snap.Reason

	return snap
}

// safeZscore helper
func safeZscore(x, mean, std float64) float64 {
	if std <= 1e-9 {
		if math.Abs(x-mean) < 1e-9 {
			return 0.0
		}
		// large deviation when no variance
		return math.Copysign(6.0, x-mean)
	}
	return (x - mean) / std
}

// metricToScore: map metric ratio to 0..1 where 1 is healthy, 0 is unhealthy
// baselineRatio is typical/expected ratio, valueRatio is observed ratio
func metricToScore(valueRatio, baselineRatio float64) float64 {
	// if valueRatio <= baseline => full score
	if valueRatio <= baselineRatio {
		return 1.0
	}
	// degrade smoothly
	// score = 1 / (1 + k*(value/baseline -1))
	k := 2.0
	r := valueRatio / (baselineRatio + 1e-9)
	return 1.0 / (1.0 + k*(r-1.0))
}

// maybeAutoHeal: trigger auto-heal when configured and conditions met
func (sm *ServiceMonitor) maybeAutoHeal(ctx context.Context, service string, snap HealthSnapshot) {
	sm.mu.Lock()
	healer := sm.autoHealer
	last := sm.lastAutoHeal[service]
	sm.mu.Unlock()
	if healer == nil {
		return
	}
	// only heal if enabled in config
	e := sm.ensureEntry(service)
	if !e.config.AutoHealEnabled {
		return
	}
	// cooldown
	if time.Since(last) < e.config.AutoHealCooldown {
		return
	}
	// condition: severe anomaly or down state
	if snap.Status == StatusDown || (snap.Anomaly && e.config.AutoHealOnAnomaly) {
		// attempt restart first
		go func() {
			ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			_ = healer.Restart(ctx2, service) // error ignored here: could be logged
			sm.mu.Lock()
			sm.lastAutoHeal[service] = time.Now()
			sm.mu.Unlock()
			sm.notifyAll("auto_heal", snap)
		}()
	}
}

// GetStatus returns latest HealthSnapshot for a service
func (sm *ServiceMonitor) GetStatus(service string) (HealthSnapshot, error) {
	sm.mu.RLock()
	_, ok := sm.services[service]
	sm.mu.RUnlock()
	if !ok {
		return HealthSnapshot{}, errors.New("service not monitored")
	}
	snap := sm.evaluateSnapshot(service)
	return snap, nil
}

// ListServices returns names of monitored services
func (sm *ServiceMonitor) ListServices() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]string, 0, len(sm.services))
	for k := range sm.services {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Usages returns a copy of recent history for all services (careful with size)
func (sm *ServiceMonitor) Usages() map[string][]ServiceUsage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make(map[string][]ServiceUsage, len(sm.services))
	for k, e := range sm.services {
		out[k] = e.history.list()
	}
	return out
}

// PredictNext uses EWMA model to predict next usage values (very lightweight)
func (sm *ServiceMonitor) PredictNext(service string) (pred ServiceUsage, err error) {
	sm.mu.RLock()
	e, ok := sm.services[service]
	sm.mu.RUnlock()
	if !ok {
		return ServiceUsage{}, errors.New("service not monitored")
	}
	cpu, ram, lat, errr := e.model.predictNext()
	pred = ServiceUsage{
		ServiceName: service,
		CPU:         cpu,
		RAMMB:       ram,
		LatencyMS:   lat,
		ErrorRate:   errr,
		Timestamp:   time.Now(),
		Status:      StatusWarn,
	}
	return pred, nil
}

// CorrelateServices computes simple Pearson correlation between latency series of two services
func (sm *ServiceMonitor) CorrelateServices(a, b string) (corr float64, samples int, err error) {
	sm.mu.RLock()
	ea, oka := sm.services[a]
	eb, okb := sm.services[b]
	sm.mu.RUnlock()
	if !oka || !okb {
		return 0, 0, errors.New("service(s) not monitored")
	}
	ha := ea.history.list()
	hb := eb.history.list()
	n := minInt(len(ha), len(hb))
	if n < 5 {
		return 0, n, errors.New("not enough samples")
	}
	// align by latest n
	sumA, sumB := 0.0, 0.0
	for i := 0; i < n; i++ {
		sumA += ha[len(ha)-1-i].LatencyMS
		sumB += hb[len(hb)-1-i].LatencyMS
	}
	meanA := sumA / float64(n)
	meanB := sumB / float64(n)
	var cov, varA, varB float64
	for i := 0; i < n; i++ {
		x := ha[len(ha)-1-i].LatencyMS - meanA
		y := hb[len(hb)-1-i].LatencyMS - meanB
		cov += x * y
		varA += x * x
		varB += y * y
	}
	if varA <= 0 || varB <= 0 {
		return 0, n, errors.New("zero variance")
	}
	return cov / math.Sqrt(varA*varB), n, nil
}

// ExportStatusJSON: export snapshots for all services
func (sm *ServiceMonitor) ExportStatusJSON() ([]byte, error) {
	sm.mu.RLock()
	names := make([]string, 0, len(sm.services))
	for k := range sm.services {
		names = append(names, k)
	}
	sm.mu.RUnlock()
	out := make([]HealthSnapshot, 0, len(names))
	for _, n := range names {
		snap, err := sm.GetStatus(n)
		if err == nil {
			out = append(out, snap)
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

// Utility helpers

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mathMax(a, b float64) float64 {
	if a > b { return a }
	return b
}
func mathMin(a, b float64) float64 {
	if a < b { return a }
	return b
}

// mathMin/Max overloads for readability in healthscore clamp
func mathMinFloat(a, b float64) float64 {
	if a < b { return a }
	return b
}
func mathMaxFloat(a, b float64) float64 {
	if a > b { return a }
	return b
}

// map normalized metric -> score 0..1 with simple fallback avoiding NaNs
func metricToScoreSafe(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0.0
	}
	if v < 0 {
		return 0.0
	}
	if v > 1.0 {
		return 0.0
	}
	return 1.0 - v
}