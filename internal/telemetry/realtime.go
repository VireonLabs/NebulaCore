// internal/telemetry/realtime.go
// TelemetryManager: real-time metrics ingestion, ring-window store, sampling,
// persistent snapshots, anomaly configuration and detection, sinks (Prometheus/Otel stubs),
// and ExposeFunctions/ModuleMeta for AI Orchestrator integration.
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ModuleInfo for registry / discovery
type ModuleInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	Health       string   `json:"health"`
}

// ---- Types ----

type MetricType string

const (
	MetricCPUUsage MetricType = "cpu_usage"
	MetricMemUsage MetricType = "mem_usage"
	MetricNetBytes MetricType = "net_bytes"
	MetricIOPS     MetricType = "iops"
	MetricCustom   MetricType = "custom"
)

type MetricPoint struct {
	Timestamp time.Time         `json:"ts"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type AnomalyConfig struct {
	MinPoints        int     `json:"min_points"`
	StdMultiplier    float64 `json:"std_multiplier"`
	WindowSeconds    int     `json:"window_seconds"`
	DetectionEnabled bool    `json:"detection_enabled"`
	NotifyOnDetect   bool    `json:"notify_on_detect"`
}

// ringBuffer stores time-ordered points in a rotating slice
type ringBuffer struct {
	mu    sync.RWMutex
	data  []MetricPoint
	start int
	size  int
	cap   int
}

func newRingBuffer(cap int) *ringBuffer {
	if cap <= 0 {
		cap = 10000
	}
	return &ringBuffer{data: make([]MetricPoint, 0, cap), start: 0, size: 0, cap: cap}
}

func (r *ringBuffer) appendPoint(p MetricPoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.data) < r.cap {
		r.data = append(r.data, p)
		r.size = len(r.data)
		return
	}
	// overwrite oldest at start index
	r.data[r.start] = p
	r.start = (r.start + 1) % r.cap
	r.size = r.cap
}

func (r *ringBuffer) snapshotWindow(d time.Duration) []MetricPoint {
	cut := time.Now().Add(-d)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MetricPoint, 0, len(r.data))
	// iterate in logical order
	n := len(r.data)
	for i := 0; i < n; i++ {
		idx := (r.start + i) % n
		p := r.data[idx]
		if d <= 0 || p.Timestamp.After(cut) {
			out = append(out, p)
		}
	}
	return out
}

// ---- TelemetryManager ----

type TelemetryManager struct {
	mu            sync.RWMutex
	buffers       map[MetricType]*ringBuffer
	bufferCap     int
	maxRetain     time.Duration
	sinks         []func(mt MetricType, p MetricPoint)
	anomalyCfg    map[MetricType]AnomalyConfig
	anomalyCb     func(mt MetricType, p MetricPoint, meta map[string]any)
	sampleRate    map[MetricType]int  // samples per second (rate limiting)
	jitter        bool
	enableProm    bool
	ctxCancel     context.CancelFunc
	persistPath   string
	cleanupTicker *time.Ticker
	// internal sampler state
	lastSampleTS map[MetricType]time.Time
}

// NewTelemetryManager creates manager; maxRetain defines retention window; bufferCap number of points stored per metric.
func NewTelemetryManager(maxRetain time.Duration, bufferCap int, persistPath string) *TelemetryManager {
	if maxRetain <= 0 {
		maxRetain = 24 * time.Hour
	}
	if bufferCap <= 0 {
		bufferCap = 10000
	}
	ctx, cancel := context.WithCancel(context.Background())
	// seed randomness for jitter
	rand.Seed(time.Now().UnixNano())
	tm := &TelemetryManager{
		buffers:       map[MetricType]*ringBuffer{},
		bufferCap:     bufferCap,
		maxRetain:     maxRetain,
		sinks:         []func(mt MetricType, p MetricPoint){},
		anomalyCfg:    map[MetricType]AnomalyConfig{},
		sampleRate:    map[MetricType]int{},
		jitter:        true,
		enableProm:    false,
		ctxCancel:     cancel,
		persistPath:   persistPath,
		cleanupTicker: time.NewTicker(1 * time.Minute),
		lastSampleTS:  map[MetricType]time.Time{},
	}
	go tm.cleanupLoop(ctx)
	return tm
}

// Stop stops background tasks
func (tm *TelemetryManager) Stop() {
	tm.ctxCancel()
	if tm.cleanupTicker != nil {
		tm.cleanupTicker.Stop()
	}
}

// SetPersistPath sets directory for periodic snapshots (must be writable)
func (tm *TelemetryManager) SetPersistPath(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	tm.mu.Lock()
	tm.persistPath = path
	tm.mu.Unlock()
	return nil
}

// ensureBuffer lazily creates ring buffer
func (tm *TelemetryManager) ensureBuffer(mt MetricType) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.buffers[mt]; !ok {
		tm.buffers[mt] = newRingBuffer(tm.bufferCap)
	}
}

// Record ingests a metric point (rate-limited, non-blocking)
func (tm *TelemetryManager) Record(mt MetricType, value float64, labels map[string]string) {
	tm.ensureBuffer(mt)

	// sampling / rate-limit (thread-safe access to lastSampleTS)
	if r := tm.getSampleRate(mt); r > 0 {
		now := time.Now()
		minInterval := time.Duration(int64(time.Second) / int64(r))
		if tm.jitter && minInterval > 0 {
			j := rand.Int63n(int64(minInterval / 10))
			minInterval += time.Duration(j)
		}
		tm.mu.Lock()
		last := tm.lastSampleTS[mt]
		if !last.IsZero() && now.Sub(last) < minInterval {
			// drop sample to respect rate
			tm.mu.Unlock()
			return
		}
		tm.lastSampleTS[mt] = now
		tm.mu.Unlock()
	}

	pt := MetricPoint{Timestamp: time.Now(), Value: value, Labels: labels}
	tm.buffers[mt].appendPoint(pt)

	// emit to sinks asynchronously
	tm.mu.RLock()
	sinks := append([]func(mt MetricType, p MetricPoint){}, tm.sinks...)
	tm.mu.RUnlock()
	for _, s := range sinks {
		go s(mt, pt)
	}

	// run lightweight anomaly detection (async)
	go tm.detectAnomaly(mt, pt)
}

// getSampleRate returns configured sample rate, default 0 (no limit)
func (tm *TelemetryManager) getSampleRate(mt MetricType) int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if v, ok := tm.sampleRate[mt]; ok {
		return v
	}
	return 0
}

// GetRecent returns points since 'since' time
func (tm *TelemetryManager) GetRecent(mt MetricType, since time.Time) []MetricPoint {
	tm.mu.RLock()
	rb, ok := tm.buffers[mt]
	tm.mu.RUnlock()
	if !ok {
		return nil
	}
	if since.IsZero() {
		// return all retained
		return rb.snapshotWindow(tm.maxRetain)
	}
	// snapshot and filter
	points := rb.snapshotWindow(tm.maxRetain)
	out := make([]MetricPoint, 0, len(points))
	for _, p := range points {
		if p.Timestamp.After(since) {
			out = append(out, p)
		}
	}
	return out
}

// Snapshot returns a JSON-safe snapshot of recent metrics (windowSeconds=0 => full retention)
func (tm *TelemetryManager) Snapshot(windowSeconds int) (map[MetricType][]MetricPoint, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	win := time.Duration(windowSeconds) * time.Second
	if windowSeconds <= 0 {
		win = tm.maxRetain
	}
	out := map[MetricType][]MetricPoint{}
	for mt, rb := range tm.buffers {
		out[mt] = rb.snapshotWindow(win)
	}
	return out, nil
}

// SaveSnapshot persists a snapshot to disk (atomic write)
func (tm *TelemetryManager) SaveSnapshot(path string, windowSeconds int) error {
	snap, err := tm.Snapshot(windowSeconds)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o750)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadSnapshot loads previously saved snapshot (merges into buffers)
func (tm *TelemetryManager) LoadSnapshot(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap map[MetricType][]MetricPoint
	if err := json.Unmarshal(b, &snap); err != nil {
		return err
	}
	for mt, pts := range snap {
		tm.ensureBuffer(mt)
		for _, p := range pts {
			tm.buffers[mt].appendPoint(p)
		}
	}
	return nil
}

// RegisterSink registers external sink (Prometheus push, Kafka, etc.)
func (tm *TelemetryManager) RegisterSink(s func(mt MetricType, p MetricPoint)) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.sinks = append(tm.sinks, s)
}

// SetAnomalyConfig sets anomaly config for a metric
func (tm *TelemetryManager) SetAnomalyConfig(mt MetricType, cfg AnomalyConfig) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.anomalyCfg[mt] = cfg
}

// SetAnomalyCallback registers callback (e.g., to self-healing) invoked on anomaly detection.
func (tm *TelemetryManager) SetAnomalyCallback(cb func(mt MetricType, p MetricPoint, meta map[string]any)) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.anomalyCb = cb
}

// EnablePrometheus toggles prometheus bridge stub
func (tm *TelemetryManager) EnablePrometheus(enabled bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.enableProm = enabled
}

// Gather returns a JSON snapshot representation suitable for scraping if no exporter exists.
func (tm *TelemetryManager) Gather() ([]byte, error) {
	snap, err := tm.Snapshot(0)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(snap, "", "  ")
}

// SetSampling configures sample rate and jitter
func (tm *TelemetryManager) SetSampling(mt MetricType, samplesPerSecond int, jitter bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.sampleRate[mt] = samplesPerSecond
	tm.jitter = jitter
}

// detectAnomaly runs a quick z-score heuristic over recent window according to config
func (tm *TelemetryManager) detectAnomaly(mt MetricType, p MetricPoint) {
	tm.mu.RLock()
	cfg, ok := tm.anomalyCfg[mt]
	cb := tm.anomalyCb
	tm.mu.RUnlock()
	if !ok || !cfg.DetectionEnabled || cb == nil {
		return
	}
	// calculate mean/std for window
	window := time.Duration(cfg.WindowSeconds) * time.Second
	if cfg.WindowSeconds <= 0 {
		window = 300 * time.Second
	}
	points := tm.GetRecent(mt, time.Now().Add(-window))
	if len(points) < cfg.MinPoints {
		return
	}
	// mean/std
	sum := 0.0
	for _, pt := range points {
		sum += pt.Value
	}
	mean := sum / float64(len(points))
	variance := 0.0
	for _, pt := range points {
		d := pt.Value - mean
		variance += d * d
	}
	std := math.Sqrt(variance / float64(len(points)))
	threshold := mean + cfg.StdMultiplier*std
	if std == 0 {
		// check absolute spike
		if p.Value > mean*1.5 {
			cb(mt, p, map[string]any{"reason": "spike_absolute"})
		}
		return
	}
	if p.Value > threshold {
		cb(mt, p, map[string]any{"reason": "zscore", "mean": mean, "std": std, "threshold": threshold})
	}
}

// cleanupLoop periodically trims buffers and optionally persists snapshot
func (tm *TelemetryManager) cleanupLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.cleanupTicker.C:
			// persist lightweight snapshot occasionally
			tm.mu.RLock()
			pp := tm.persistPath
			tm.mu.RUnlock()
			if pp != "" {
				path := filepath.Join(pp, fmt.Sprintf("telemetry_snapshot_%d.json", time.Now().Unix()))
				_ = tm.SaveSnapshot(path, 60*5) // 5 minutes
			}
		}
	}
}

// ---- Utilities / Expose ----

func (tm *TelemetryManager) ModuleMeta() ModuleInfo {
	return ModuleInfo{
		Name:         "telemetry",
		Version:      "v1.1",
		Capabilities: []string{"record", "snapshot", "anomaly_detection", "prometheus_bridge", "sampling"},
		Health:       "ok",
	}
}

// ExposeFunctions returns map of callable functions for orchestrator / model
func (tm *TelemetryManager) ExposeFunctions() map[string]any {
	return map[string]any{
		"record_metric":     tm.Record,
		"get_recent":        tm.GetRecent,
		"snapshot":          tm.Snapshot,
		"save_snapshot":     tm.SaveSnapshot,
		"load_snapshot":     tm.LoadSnapshot,
		"set_anomaly_cfg":   tm.SetAnomalyConfig,
		"set_anom_cb":       tm.SetAnomalyCallback,
		"register_sink":     tm.RegisterSink,
		"enable_prometheus": tm.EnablePrometheus,
		"gather":            tm.Gather,
		"set_sampling":      tm.SetSampling,
		"set_persist_path":  tm.SetPersistPath,
	}
}