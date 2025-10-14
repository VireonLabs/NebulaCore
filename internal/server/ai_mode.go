// internal/server/ai_mode.go
// AI Fallback Controller (AIFallbackController) — النسخة الإنتاجية النهائية مع إصلاحات التزامن وسلامة البيانات والمراقبة

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ----- Public Types & Interfaces -----

type AIMode int32

const (
	AIModeProxy AIMode = iota
	AIModeDirect
	AIModeDisabled
	AIModeFallback
)

func (m AIMode) String() string {
	switch m {
	case AIModeProxy:
		return "Proxy"
	case AIModeDirect:
		return "Direct"
	case AIModeDisabled:
		return "Disabled"
	case AIModeFallback:
		return "Fallback"
	default:
		return "Unknown"
	}
}

type HealthProbe func(ctx context.Context) error

type StateStore interface {
	Save(state *PersistedState) error
	Load() (*PersistedState, error)
}

type PersistedState struct {
	Mode         AIMode                 `json:"mode"`
	Locked       bool                   `json:"locked"`
	LastFallback time.Time              `json:"last_fallback"`
	Meta         map[string]interface{} `json:"meta,omitempty"`
}

type ResourceManager interface {
	ScaleUp(ctx context.Context, role string, count int) error
	ScaleDown(ctx context.Context, role string, count int) error
	DeployArtifact(ctx context.Context, target string, artifactURI string) error
	RedistributeWorkload(ctx context.Context, workloadID string, targets []string) error
}

type NoopResourceManager struct{}

func (n *NoopResourceManager) ScaleUp(ctx context.Context, role string, count int) error            { return nil }
func (n *NoopResourceManager) ScaleDown(ctx context.Context, role string, count int) error          { return nil }
func (n *NoopResourceManager) DeployArtifact(ctx context.Context, target string, artifactURI string) error {
	return nil
}
func (n *NoopResourceManager) RedistributeWorkload(ctx context.Context, workloadID string, targets []string) error {
	return nil
}

type RecoveryPolicy struct {
	Enabled        bool
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxAttempts    int
	VerifyWindow   time.Duration
}

type EventRecord struct {
	Time   time.Time              `json:"time"`
	Event  string                 `json:"event"`
	Meta   map[string]interface{} `json:"meta,omitempty"`
	Mode   string                 `json:"mode,omitempty"`
	Locked bool                   `json:"locked,omitempty"`
}

// ----- Controller -----

type AIFallbackController struct {
	mode         atomic.Int32
	stateMu      sync.RWMutex
	locked       bool

	probesMu     sync.RWMutex
	healthProbes map[string]HealthProbe
	probeTimeout time.Duration

	failThreshold int
	failCounts    map[string]int
	failCountsMu  sync.Mutex

	telemetry func(event string, meta map[string]interface{})
	metrics   func(name string, value float64)
	alertFn   func(level, msg string, meta map[string]interface{})

	store           StateStore
	resourceManager ResourceManager

	recoveryPolicy RecoveryPolicy

	historyMu   sync.Mutex
	history     []EventRecord
	histCap     int

	lastFallbackMu sync.RWMutex
	lastFallback   time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	started atomic.Int32

	logger *log.Logger
}

// ---- Constructor ----

func NewAIFallbackController(defaultMode AIMode, opts ...func(*AIFallbackController)) *AIFallbackController {
	ctx, cancel := context.WithCancel(context.Background())
	c := &AIFallbackController{
		probeTimeout:    3 * time.Second,
		failThreshold:   3,
		failCounts:      make(map[string]int),
		healthProbes:    make(map[string]HealthProbe),
		history:         make([]EventRecord, 0, 128),
		histCap:         512,
		recoveryPolicy:  RecoveryPolicy{
			Enabled:        true,
			InitialBackoff: 5 * time.Second,
			MaxBackoff:     2 * time.Minute,
			MaxAttempts:    6,
			VerifyWindow:   15 * time.Second,
		},
		store:           nil,
		resourceManager: &NoopResourceManager{},
		ctx:             ctx,
		cancel:          cancel,
		logger:          log.Default(),
	}
	c.mode.Store(int32(defaultMode))
	for _, o := range opts {
		o(c)
	}
	c.record(EventRecord{Time: time.Now(), Event: "controller_started", Mode: defaultMode.String(), Locked: false})
	return c
}

// ---- Lifecycle ----

func (a *AIFallbackController) Start() error {
	if a.started.Load() == 1 {
		return nil
	}
	if a.store != nil {
		if st, err := a.store.Load(); err == nil && st != nil {
			a.stateMu.Lock()
			a.mode.Store(int32(st.Mode))
			a.locked = st.Locked
			a.setLastFallback(st.LastFallback)
			a.stateMu.Unlock()
			a.record(EventRecord{Time: time.Now(), Event: "state_restored", Meta: map[string]interface{}{"mode": st.Mode.String(), "locked": st.Locked}})
		} else if err != nil {
			a.logger.Printf("[AIFallback] state restore error: %v", err)
		}
	}
	a.started.Store(1)
	a.record(EventRecord{Time: time.Now(), Event: "started"})
	return nil
}

func (a *AIFallbackController) Stop() {
	if a.started.Load() == 0 {
		return
	}
	a.cancel()
	a.wg.Wait()
	a.started.Store(0)
	a.record(EventRecord{Time: time.Now(), Event: "stopped"})
}

func (a *AIFallbackController) persistState() error {
	st := &PersistedState{
		Mode:         AIMode(a.mode.Load()),
		Locked:       a.isLockedUnsafe(),
		LastFallback: a.getLastFallback(),
	}
	if a.store == nil {
		return nil
	}
	return a.store.Save(st)
}

// ---- Mode Management ----

func (a *AIFallbackController) GetMode() AIMode {
	return AIMode(a.mode.Load())
}

func (a *AIFallbackController) setModeAtomic(m AIMode) {
	a.mode.Store(int32(m))
	a.metricsRecord("ai_mode_change", float64(m))
	a.record(EventRecord{Time: time.Now(), Event: "mode_set", Mode: m.String(), Locked: a.IsLocked()})
	a.recordTelemetry("ai_mode_change", map[string]interface{}{"mode": m.String()})
	go func() {
		if err := a.persistState(); err != nil {
			a.logger.Printf("[AIFallback] persistState error: %v", err)
		}
	}()
}

func (a *AIFallbackController) SetMode(newMode AIMode) error {
	a.stateMu.RLock()
	locked := a.locked
	a.stateMu.RUnlock()
	if locked && newMode != AIModeFallback {
		return errors.New("mode change is locked during fallback")
	}
	prev := a.GetMode()
	a.setModeAtomic(newMode)
	a.logger.Printf("[AIFallback] mode changed %s -> %s", prev.String(), newMode.String())
	return nil
}

func (a *AIFallbackController) IsLocked() bool {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.locked
}

func (a *AIFallbackController) isLockedUnsafe() bool {
	return a.locked
}

// ---- Probes & Polling ----

func (a *AIFallbackController) RegisterHealthProbe(name string, fn HealthProbe) {
	a.probesMu.Lock()
	a.healthProbes[name] = fn
	a.probesMu.Unlock()
	a.record(EventRecord{Time: time.Now(), Event: "probe_registered", Meta: map[string]interface{}{"name": name}})
}

func (a *AIFallbackController) UnregisterHealthProbe(name string) {
	a.probesMu.Lock()
	delete(a.healthProbes, name)
	a.probesMu.Unlock()
	a.record(EventRecord{Time: time.Now(), Event: "probe_unregistered", Meta: map[string]interface{}{"name": name}})
}

func (a *AIFallbackController) PollHealth(interval time.Duration, failThreshold int) {
	if failThreshold > 0 {
		a.failThreshold = failThreshold
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		consecutive := 0
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				if a.GetMode() == AIModeFallback {
					continue
				}
				bad := a.runAllProbes()
				if bad {
					consecutive++
					if consecutive >= a.failThreshold {
						_ = a.TriggerFallback("health probes failed threshold")
						consecutive = 0
						go a.defensiveActions()
					}
				} else {
					consecutive = 0
				}
			}
		}
	}()
}

func (a *AIFallbackController) runAllProbes() bool {
	a.probesMu.RLock()
	probes := make(map[string]HealthProbe, len(a.healthProbes))
	for k, v := range a.healthProbes {
		probes[k] = v
	}
	timeout := a.probeTimeout
	a.probesMu.RUnlock()

	if len(probes) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	resCh := make(chan string, len(probes))
	var wg sync.WaitGroup
	for name, fn := range probes {
		wg.Add(1)
		go func(n string, f HealthProbe) {
			defer wg.Done()
			pctx, pcancel := context.WithTimeout(ctx, timeout)
			defer pcancel()
			defer func() {
				if r := recover(); r != nil {
					a.logger.Printf("[AIFallback] probe panic recovered: %s - %v", n, r)
					select {
					case resCh <- fmt.Sprintf("%s:panic", n):
					default:
					}
				}
			}()
			if err := f(pctx); err != nil {
				select {
				case resCh <- fmt.Sprintf("%s:%v", n, err):
				default:
				}
			}
		}(name, fn)
	}

	wgDone := make(chan struct{})
	go func() { wg.Wait(); close(wgDone) }()

	select {
	case <-ctx.Done():
		a.recordTelemetry("probe_batch_timeout", nil)
		a.incrementFailCounter("timeout")
		return true
	case <-wgDone:
		close(resCh)
		failed := false
		for msg := range resCh {
			failed = true
			a.incrementFailCounter(msg)
			a.recordTelemetry("probe_failure", map[string]interface{}{"detail": msg})
		}
		return failed
	}
}

func (a *AIFallbackController) incrementFailCounter(key string) {
	a.failCountsMu.Lock()
	a.failCounts[key] = a.failCounts[key] + 1
	a.failCountsMu.Unlock()
}

// ---- Fallback & Recovery ----

func (a *AIFallbackController) TriggerFallback(reason string) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.locked {
		return errors.New("already in fallback mode")
	}
	a.locked = true
	a.setModeAtomic(AIModeFallback)
	now := time.Now()
	a.setLastFallback(now)
	a.record(EventRecord{Time: now, Event: "fallback_triggered", Meta: map[string]interface{}{"reason": reason}})
	a.recordTelemetry("fallback_triggered", map[string]interface{}{"reason": reason})
	a.logger.Printf("[AIFallback] triggered fallback: %s", reason)
	if a.alertFn != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				a.alertFn("critical", "AI fallback triggered", map[string]interface{}{"reason": reason, "time": now})
				close(done)
			}()
			select {
			case <-ctx.Done():
				a.logger.Println("[AIFallback] alertFn timed out")
			case <-done:
			}
		}()
	}
	go func() {
		if err := a.persistState(); err != nil {
			a.logger.Printf("[AIFallback] persist after trigger failed: %v", err)
		}
	}()
	if a.recoveryPolicy.Enabled {
		a.wg.Add(1)
		go a.autoRecoverLoop()
	}
	return nil
}

func (a *AIFallbackController) EndFallback(force bool) {
	a.stateMu.Lock()
	a.locked = false
	a.setModeAtomic(AIModeProxy)
	a.stateMu.Unlock()
	a.record(EventRecord{Time: time.Now(), Event: "fallback_ended"})
	a.recordTelemetry("fallback_ended", nil)
	a.logger.Println("[AIFallback] fallback ended, mode -> Proxy")
}

func (a *AIFallbackController) autoRecoverLoop() {
	defer a.wg.Done()
	p := a.recoveryPolicy
	attempt := 0
	backoff := p.InitialBackoff
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		if p.MaxAttempts > 0 && attempt >= p.MaxAttempts {
			a.logger.Printf("[AIFallback] autoRecoverLoop exhausted attempts=%d", attempt)
			a.record(EventRecord{Time: time.Now(), Event: "auto_recover_exhausted", Meta: map[string]interface{}{"attempts": attempt}})
			return
		}
		attempt++
		a.logger.Printf("[AIFallback] auto-recover attempt %d waiting %s", attempt, backoff)
		time.Sleep(backoff)
		if a.verifyStability(p.VerifyWindow) {
			a.logger.Println("[AIFallback] auto-recover successful: ending fallback")
			a.EndFallback(false)
			a.record(EventRecord{Time: time.Now(), Event: "auto_recover_success", Meta: map[string]interface{}{"attempt": attempt}})
			return
		}
		backoff = backoff * 2
		if backoff > p.MaxBackoff {
			backoff = p.MaxBackoff
		}
	}
}

func (a *AIFallbackController) verifyStability(window time.Duration) bool {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if a.GetMode() != AIModeFallback {
			return false
		}
		a.runAllProbes()
		a.failCountsMu.Lock()
		hasFailures := false
		for _, v := range a.failCounts {
			if v > 0 {
				hasFailures = true
				break
			}
		}
		a.failCountsMu.Unlock()
		if hasFailures {
			return false
		}
		time.Sleep(a.probeTimeout / 2)
	}
	return true
}

func (a *AIFallbackController) defensiveActions() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Safer timeout
	defer cancel()
	if a.resourceManager != nil {
		_ = a.resourceManager.ScaleUp(ctx, "ai-worker", 1)
		_ = a.resourceManager.RedistributeWorkload(ctx, "low-prio", nil)
	}
	a.record(EventRecord{Time: time.Now(), Event: "defensive_actions_executed"})
}

// ---- HTTP Routes ----

func (a *AIFallbackController) RegisterRoutes(mux *http.ServeMux, authz func(r *http.Request) bool) {
	writeJSON := func(w http.ResponseWriter, v interface{}, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/v1/ai/mode", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		switch r.Method {
		case "GET":
			writeJSON(w, map[string]interface{}{
				"mode":         a.GetMode().String(),
				"locked":       a.IsLocked(),
				"last_fallback": a.getLastFallback(),
			}, http.StatusOK)
		case "POST":
			var req struct{ Mode string `json:"Mode"` }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest); return
			}
			var m AIMode
			switch req.Mode {
			case "Proxy": m = AIModeProxy
			case "Direct": m = AIModeDirect
			case "Disabled": m = AIModeDisabled
			case "Fallback": m = AIModeFallback
			default: http.Error(w, "invalid mode", http.StatusBadRequest); return
			}
			if err := a.SetMode(m); err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
			writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/ai/status", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		writeJSON(w, map[string]interface{}{
			"mode":         a.GetMode().String(),
			"locked":       a.IsLocked(),
			"last_fallback": a.getLastFallback(),
			"probes":       a.listProbes(),
		}, http.StatusOK)
	})
	mux.HandleFunc("/api/v1/ai/trigger", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		if r.Method != "POST" { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
		var req struct{ Reason string `json:"reason"` }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" { req.Reason = "manual_trigger" }
		if err := a.TriggerFallback(req.Reason); err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
		writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
	})
	mux.HandleFunc("/api/v1/ai/end", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		if r.Method != "POST" { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
		var req struct{ Force bool `json:"force"` }
		_ = json.NewDecoder(r.Body).Decode(&req)
		a.EndFallback(req.Force)
		writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
	})
	mux.HandleFunc("/api/v1/ai/history", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		writeJSON(w, a.getHistory(), http.StatusOK)
	})
	mux.HandleFunc("/api/v1/ai/debug", func(w http.ResponseWriter, r *http.Request) {
		if !authz(r) { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		writeJSON(w, map[string]interface{}{
			"mode":         a.GetMode().String(),
			"locked":       a.IsLocked(),
			"last_fallback": a.getLastFallback(),
			"fail_counts":  a.snapshotFailCounts(),
			"probes":       a.listProbes(),
		}, http.StatusOK)
	})
}

// ---- History / Telemetry ----

func (a *AIFallbackController) record(ev EventRecord) {
	a.historyMu.Lock()
	defer a.historyMu.Unlock()
	ev.Mode = a.GetMode().String()
	ev.Locked = a.IsLocked()
	a.history = append(a.history, ev)
	if len(a.history) > a.histCap {
		a.history = a.history[len(a.history)-a.histCap:]
	}
	a.recordTelemetry(ev.Event, ev.Meta)
	a.metricsRecord("history_events", float64(len(a.history)))
}

func (a *AIFallbackController) getHistory() []EventRecord {
	a.historyMu.Lock()
	defer a.historyMu.Unlock()
	cp := make([]EventRecord, len(a.history))
	copy(cp, a.history)
	return cp
}

func (a *AIFallbackController) recordTelemetry(event string, meta map[string]interface{}) {
	if a.telemetry == nil { return }
	go func() {
		defer func() { if r := recover(); r != nil { a.logger.Printf("[AIFallback] telemetry panic: %v", r) } }()
		a.telemetry(event, meta)
	}()
}

func (a *AIFallbackController) metricsRecord(name string, val float64) {
	if a.metrics == nil { return }
	go func() {
		defer func() { if r := recover(); r != nil { a.logger.Printf("[AIFallback] metrics panic: %v", r) } }()
		a.metrics(name, val)
	}()
}

func (a *AIFallbackController) SetTelemetryHook(fn func(event string, meta map[string]interface{})) {
	a.telemetry = fn
}

func (a *AIFallbackController) SetMetricsHook(fn func(name string, value float64)) {
	a.metrics = fn
}

func (a *AIFallbackController) SetAlertHook(fn func(level, msg string, meta map[string]interface{})) {
	a.alertFn = fn
}

func (a *AIFallbackController) SetStore(s StateStore) {
	if s == nil { return }
	a.store = s
}

func (a *AIFallbackController) SetResourceManager(r ResourceManager) {
	if r == nil { r = &NoopResourceManager{} }
	a.resourceManager = r
}

func (a *AIFallbackController) listProbes() []string {
	a.probesMu.RLock()
	defer a.probesMu.RUnlock()
	out := make([]string, 0, len(a.healthProbes))
	for k := range a.healthProbes { out = append(out, k) }
	return out
}

func (a *AIFallbackController) getLastFallback() time.Time {
	a.lastFallbackMu.RLock()
	defer a.lastFallbackMu.RUnlock()
	return a.lastFallback
}
func (a *AIFallbackController) setLastFallback(t time.Time) {
	a.lastFallbackMu.Lock()
	a.lastFallback = t
	a.lastFallbackMu.Unlock()
}

func (a *AIFallbackController) snapshotFailCounts() map[string]int {
	a.failCountsMu.Lock()
	defer a.failCountsMu.Unlock()
	cp := make(map[string]int, len(a.failCounts))
	for k, v := range a.failCounts { cp[k] = v }
	return cp
}

// ---- FileStore ----

type FileStore struct { Path string }

func (fs *FileStore) Save(s *PersistedState) error {
	f, err := os.Create(fs.Path + ".tmp")
	if err != nil { return err }
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(fs.Path + ".tmp", fs.Path)
}

func (fs *FileStore) Load() (*PersistedState, error) {
	data, err := os.ReadFile(fs.Path)
	if err != nil {
		if os.IsNotExist(err) { return nil, nil }
		return nil, err
	}
	var s PersistedState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ---- Setters ----

func (a *AIFallbackController) SetProbeTimeout(d time.Duration) {
	if d <= 0 { return }
	a.probeTimeout = d
}

func (a *AIFallbackController) SetRecoveryPolicy(p RecoveryPolicy) {
	a.recoveryPolicy = p
}

func (a *AIFallbackController) SetFailThreshold(n int) {
	if n <= 0 { return }
	a.failThreshold = n
}

func (a *AIFallbackController) Shutdown() {
	a.Stop()
	a.record(EventRecord{Time: time.Now(), Event: "controller_shutdown"})
	a.logger.Println("[AIFallback] controller shutdown complete")
}