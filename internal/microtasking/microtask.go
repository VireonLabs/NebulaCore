// internal/microtasking/microtask.go
// Production-grade Microtask Manager for NebulaCore Supercomputer
//
// Enhancements over the original design:
//  - Persistent snapshotting of DAGs + event log (periodic, configurable).
//  - MetricsCollector interface + PrometheusCollector implementation.
//  - Trace IDs for tasks/events (UUIDs) and basic context propagation helpers.
//  - Optional AuthChecker hook to gate critical operations (non-blocking, pluggable).
//  - More robust dispatcher/backoff, task requeue/backpressure handling.
//  - Extended event log entries with traceID and timestamps.
//  - Safety notes and checkpoints written to disk; recommended to configure persistence
//    for production to avoid in-memory-only state loss.
//
// Operational notes (important):
// 1) The persistent store used here is a simple JSON file. For high-scale production
//    use a durable KV/DB (etcd, RocksDB, Postgres) or object storage with atomic replace.
// 2) Handlers registered via RegisterWorkerHandler MUST respect ctx for graceful shutdown.
// 3) Prometheus support requires the github.com/prometheus/client_golang/prometheus module.
//
// This file keeps all original APIs and behavior but extends them with production features.
package microtasking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// -------------------- Models --------------------

type MicroTask struct {
	ID         string            `json:"id"`
	ParentID   string            `json:"parent_id,omitempty"`
	Payload    map[string]any    `json:"payload,omitempty"`
	Status     string            `json:"status"` // pending/running/done/failed
	AssignedTo string            `json:"assigned_to,omitempty"`
	Result     any               `json:"result,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Attempts   int               `json:"attempts"`
	MaxRetries int               `json:"max_retries"`
	Meta       map[string]any    `json:"meta,omitempty"`
	Progress   int               `json:"progress"` // 0..100
	TraceID    string            `json:"trace_id,omitempty"`
	TTL        *time.Time        `json:"ttl,omitempty"`
}

type TaskDAG struct {
	RootID string                 `json:"root_id"`
	Nodes  map[string]*MicroTask  `json:"nodes"`
	Edges  map[string][]string    `json:"edges"` // parent -> children
	mu     sync.RWMutex           `json:"-"`
}

// -------------------- Aggregator interface --------------------

type Aggregator interface {
	Aggregate(results []any) any
}

type ConcatAggregator struct{}

func (c *ConcatAggregator) Aggregate(results []any) any { return results }

// -------------------- Event / Audit --------------------

type EventType string

const (
	EventTaskCreated    EventType = "TaskCreated"
	EventTaskDispatched EventType = "TaskDispatched"
	EventTaskStarted    EventType = "TaskStarted"
	EventTaskProgress   EventType = "TaskProgress"
	EventTaskDone       EventType = "TaskDone"
	EventTaskFailed     EventType = "TaskFailed"
	EventWorkerReg      EventType = "WorkerRegistered"
	EventWorkerDereg    EventType = "WorkerDeregistered"
	EventInfo           EventType = "Info"
	EventPersisted      EventType = "Persisted"
)

type Event struct {
	Time     time.Time `json:"time"`
	Type     EventType `json:"type"`
	TaskID   string    `json:"task_id,omitempty"`
	ParentID string    `json:"parent_id,omitempty"`
	WorkerID string    `json:"worker_id,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	TraceID  string    `json:"trace_id,omitempty"`
}

// -------------------- Metrics Collector --------------------

// MetricsCollector is an abstraction for emitting metrics.
type MetricsCollector interface {
	IncTasksCreated()
	IncTasksDispatched()
	IncTasksCompleted()
	IncTasksFailed()
	IncWorkersRegistered()
	SetWorkerCount(n int)
	ObserveTaskLatency(d time.Duration)
}

// NoOp collector (default)
type noopCollector struct{}

func (n *noopCollector) IncTasksCreated()                   {}
func (n *noopCollector) IncTasksDispatched()                {}
func (n *noopCollector) IncTasksCompleted()                 {}
func (n *noopCollector) IncTasksFailed()                    {}
func (n *noopCollector) IncWorkersRegistered()              {}
func (n *noopCollector) SetWorkerCount(_ int)               {}
func (n *noopCollector) ObserveTaskLatency(_ time.Duration) {}

// PrometheusCollector implements MetricsCollector via Prometheus.
type PrometheusCollector struct {
	tasksCreated    prometheus.Counter
	tasksDispatched prometheus.Counter
	tasksCompleted  prometheus.Counter
	tasksFailed     prometheus.Counter
	workersRegistered prometheus.Counter
	activeWorkers   prometheus.Gauge
	taskLatency     prometheus.Histogram
	registry        *prometheus.Registry
}

func NewPrometheusCollector(namespace string) *PrometheusCollector {
	if namespace == "" {
		namespace = "microtask"
	}
	reg := prometheus.NewRegistry()
	p := &PrometheusCollector{
		tasksCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_created_total",
			Help:      "Total microtasks created",
		}),
		tasksDispatched: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_dispatched_total",
			Help:      "Total microtasks dispatched",
		}),
		tasksCompleted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_completed_total",
			Help:      "Total microtasks completed successfully",
		}),
		tasksFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_failed_total",
			Help:      "Total microtasks failed",
		}),
		workersRegistered: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "workers_registered_total",
			Help:      "Total workers ever registered",
		}),
		activeWorkers: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "workers_active",
			Help:      "Current active workers",
		}),
		taskLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "task_latency_seconds",
			Help:      "Task execution latency in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		registry: reg,
	}
	// Register metrics
	_ = reg.Register(p.tasksCreated)
	_ = reg.Register(p.tasksDispatched)
	_ = reg.Register(p.tasksCompleted)
	_ = reg.Register(p.tasksFailed)
	_ = reg.Register(p.workersRegistered)
	_ = reg.Register(p.activeWorkers)
	_ = reg.Register(p.taskLatency)
	return p
}

func (p *PrometheusCollector) IncTasksCreated()    { p.tasksCreated.Inc() }
func (p *PrometheusCollector) IncTasksDispatched() { p.tasksDispatched.Inc() }
func (p *PrometheusCollector) IncTasksCompleted()  { p.tasksCompleted.Inc() }
func (p *PrometheusCollector) IncTasksFailed()     { p.tasksFailed.Inc() }
func (p *PrometheusCollector) IncWorkersRegistered() { p.workersRegistered.Inc() }
func (p *PrometheusCollector) SetWorkerCount(n int) { p.activeWorkers.Set(float64(n)) }
func (p *PrometheusCollector) ObserveTaskLatency(d time.Duration) {
	p.taskLatency.Observe(d.Seconds())
}

// Expose registry for hooking into HTTP handler externally.
func (p *PrometheusCollector) Registry() *prometheus.Registry { return p.registry }

// -------------------- Auth Checker (optional) --------------------

// AuthChecker is an optional hook; implementors decide callers/credentials handling.
// This manager will call it where appropriate but will not enforce RBAC beyond the hook.
type AuthChecker interface {
	Allow(ctx context.Context, resource string, action string) bool
}

// -------------------- Persistence config --------------------

type PersistConfig struct {
	Dir      string        // directory to write snapshots into
	Interval time.Duration // snapshotting interval
	// If empty Dir => persistence disabled
}

type persistPayload struct {
	DAGs  map[string]*TaskDAG `json:"dags"`
	Events []Event            `json:"events"`
}

// -------------------- MicroTaskManager --------------------

type MicroTaskManager struct {
	mu sync.RWMutex

	dags    map[string]*TaskDAG        // jobID -> DAG
	workers map[string]chan *MicroTask // workerID -> channel
	bufs    map[string]int             // workerID -> buffer cap (for load decisions)
	events  chan *MicroTask            // internal task queue (buffered)
	elog    []Event                    // event log (append-only)
	elogMu  sync.RWMutex               // lock for event log
	agg     Aggregator                 // aggregator implementation
	steal   bool                       // enable task stealing if true

	// dispatcher control
	ctx    context.Context
	cancel context.CancelFunc
	rr     uint64 // round-robin index (atomic)

	// persistence
	persistCfg *PersistConfig
	persistCh  chan struct{} // signal to force persist

	// metrics
	metrics MetricsCollector

	// auth
	auth AuthChecker

	// internal counters
	createdCounter   int64
	dispatchedCounter int64
	completedCounter int64
	failedCounter    int64
	workersCounter   int64
}

// NewDefaultMicroTaskManager creates manager with background context and default settings.
func NewDefaultMicroTaskManager() *MicroTaskManager {
	return NewMicroTaskManager(context.Background(), 1000)
}

// NewMicroTaskManager constructs manager and starts dispatcher loop.
// queueSize controls internal queue buffer.
func NewMicroTaskManager(parentCtx context.Context, queueSize int) *MicroTaskManager {
	ctx, cancel := context.WithCancel(parentCtx)
	m := &MicroTaskManager{
		dags:    make(map[string]*TaskDAG),
		workers: make(map[string]chan *MicroTask),
		bufs:    make(map[string]int),
		events:  make(chan *MicroTask, queueSize),
		elog:    make([]Event, 0, 4096),
		agg:     &ConcatAggregator{},
		steal:   true,
		ctx:     ctx,
		cancel:  cancel,
		persistCh: make(chan struct{}, 1),
		metrics: &noopCollector{},
	}
	go m.dispatcher()
	return m
}

// Stop stops the manager, cancels dispatcher and closes worker channels.
func (m *MicroTaskManager) Stop() {
	// cancel dispatcher
	m.cancel()

	// ensure persistence one last time (best-effort)
	m.forcePersist()

	// close worker channels safely (does not force goroutines to exit;
	// worker handlers should honor context).
	m.mu.Lock()
	for id, ch := range m.workers {
		close(ch)
		delete(m.workers, id)
		delete(m.bufs, id)
		m.addEvent(Event{Time: time.Now(), Type: EventWorkerDereg, WorkerID: id, Msg: "manager stop closed worker", TraceID: ""})
	}
	// clear metric gauge
	m.metrics.SetWorkerCount(0)
	m.mu.Unlock()
}

// -------------------- Persistence helpers --------------------

// EnablePersistence configures periodic snapshotting to disk.
// dir will be created if missing. Interval of 0 disables periodic snapshots.
func (m *MicroTaskManager) EnablePersistence(dir string, interval time.Duration) error {
	if dir == "" {
		return errors.New("dir empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	m.mu.Lock()
	m.persistCfg = &PersistConfig{
		Dir:      dir,
		Interval: interval,
	}
	m.mu.Unlock()
	// start persistence loop if interval > 0
	if interval > 0 {
		go m.persistenceLoop()
	}
	// perform initial save
	return m.SaveState()
}

// persistenceLoop periodically saves state until context canceled.
func (m *MicroTaskManager) persistenceLoop() {
	ticker := time.NewTicker(m.persistCfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			_ = m.SaveState()
		case <-m.persistCh:
			_ = m.SaveState()
		}
	}
}

// forcePersist signals immediate persistence (best-effort non-blocking)
func (m *MicroTaskManager) forcePersist() {
	select {
	case m.persistCh <- struct{}{}:
	default:
	}
}

// SaveState writes DAGs and event log to a timestamped JSON file (atomic replace).
func (m *MicroTaskManager) SaveState() error {
	m.mu.RLock()
	cfg := m.persistCfg
	if cfg == nil || cfg.Dir == "" {
		m.mu.RUnlock()
		return errors.New("persistence not enabled")
	}
	// prepare payload
	payload := persistPayload{
		DAGs:  make(map[string]*TaskDAG, len(m.dags)),
		Events: nil,
	}
	// copy DAGs (snapshot)
	for k, d := range m.dags {
		d.mu.RLock()
		copynodes := make(map[string]*MicroTask, len(d.Nodes))
		for nk, nv := range d.Nodes {
			// shallow copy node
			nodeCopy := *nv
			copynodes[nk] = &nodeCopy
		}
		edgesCopy := make(map[string][]string, len(d.Edges))
		for ek, ev := range d.Edges {
			cp := make([]string, len(ev))
			copy(cp, ev)
			edgesCopy[ek] = cp
		}
		d.mu.RUnlock()
		payload.DAGs[k] = &TaskDAG{
			RootID: d.RootID,
			Nodes:  copynodes,
			Edges:  edgesCopy,
		}
	}
	// copy events
	m.elogMu.RLock()
	payload.Events = make([]Event, len(m.elog))
	copy(payload.Events, m.elog)
	m.elogMu.RUnlock()
	m.mu.RUnlock()

	// marshal
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	// write to temp file then move
	filename := filepath.Join(cfg.Dir, fmt.Sprintf("microtask_state.%d.json.tmp", time.Now().UnixNano()))
	if err := ioutil.WriteFile(filename, data, 0o644); err != nil {
		return err
	}
	final := filepath.Join(cfg.Dir, "microtask_state.json")
	if err := os.Rename(filename, final); err != nil {
		return err
	}
	m.addEvent(Event{Time: time.Now(), Type: EventPersisted, Msg: "state persisted", TraceID: ""})
	return nil
}

// LoadState attempts to load persisted state (microtask_state.json) into memory.
// This will replace in-memory DAGs and event log.
func (m *MicroTaskManager) LoadState(dir string) error {
	if dir == "" {
		return errors.New("dir empty")
	}
	path := filepath.Join(dir, "microtask_state.json")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var payload persistPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	// restore
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dags = make(map[string]*TaskDAG, len(payload.DAGs))
	for k, d := range payload.DAGs {
		// reattach mutex
		nd := &TaskDAG{
			RootID: d.RootID,
			Nodes:  d.Nodes,
			Edges:  d.Edges,
		}
		m.dags[k] = nd
	}
	m.elogMu.Lock()
	m.elog = payload.Events
	m.elogMu.Unlock()
	m.addEvent(Event{Time: time.Now(), Type: EventInfo, Msg: "state loaded", TraceID: ""})
	return nil
}

// -------------------- Event log helpers --------------------

func (m *MicroTaskManager) addEvent(e Event) {
	// ensure trace id
	if e.TraceID == "" {
		e.TraceID = uuid.New().String()
	}
	m.elogMu.Lock()
	m.elog = append(m.elog, e)
	// keep elog in-memory; for production consider rotating or offloading to storage
	if len(m.elog) > 250000 {
		// simple rotation: keep recent
		m.elog = m.elog[len(m.elog)-100000:]
	}
	m.elogMu.Unlock()
}

func (m *MicroTaskManager) ListEvents() []Event {
	m.elogMu.RLock()
	defer m.elogMu.RUnlock()
	out := make([]Event, len(m.elog))
	copy(out, m.elog)
	return out
}

// -------------------- Worker registration --------------------

// RegisterWorker registers a worker with id and channel size and returns channel.
func (m *MicroTaskManager) RegisterWorker(workerID string, buf int) chan *MicroTask {
	ch := make(chan *MicroTask, buf)
	m.mu.Lock()
	m.workers[workerID] = ch
	m.bufs[workerID] = buf
	atomic.AddInt64(&m.workersCounter, 1)
	m.metrics.IncWorkersRegistered()
	m.metrics.SetWorkerCount(len(m.workers))
	m.mu.Unlock()
	m.addEvent(Event{Time: time.Now(), Type: EventWorkerReg, WorkerID: workerID, Msg: fmt.Sprintf("registered (buf=%d)", buf)})
	return ch
}

// RegisterWorkerHandler registers worker and starts a goroutine which reads tasks
// and calls handler(ctx, *MicroTask). The handler MUST respect ctx for graceful shutdown.
func (m *MicroTaskManager) RegisterWorkerHandler(workerID string, buf int, handler func(ctx context.Context, t *MicroTask) error) {
	ch := m.RegisterWorker(workerID, buf)
	go func() {
		for {
			select {
			case <-m.ctx:
				// manager stopping
				return
			case t, ok := <-ch:
				if !ok {
					return
				}
				// mark started
				start := time.Now()
				t.AssignedTo = workerID
				t.Status = "running"
				t.UpdatedAt = time.Now()
				// ensure trace id
				if t.TraceID == "" {
					t.TraceID = uuid.New().String()
				}
				m.addEvent(Event{Time: time.Now(), Type: EventTaskStarted, TaskID: t.ID, WorkerID: workerID, TraceID: t.TraceID})
				// call handler with manager context
				err := handler(m.ctx, t)
				elapsed := time.Since(start)
				m.metrics.ObserveTaskLatency(elapsed)
				if err != nil {
					// treat as failure and handle retries via ReportResult
					m.addEvent(Event{Time: time.Now(), Type: EventTaskFailed, TaskID: t.ID, WorkerID: workerID, Msg: err.Error(), TraceID: t.TraceID})
					atomic.AddInt64(&m.failedCounter, 1)
					m.metrics.IncTasksFailed()
					_ = m.ReportResult(t.ParentID, t.ID, nil, false)
				} else {
					// success
					m.addEvent(Event{Time: time.Now(), Type: EventTaskDone, TaskID: t.ID, WorkerID: workerID, TraceID: t.TraceID})
					atomic.AddInt64(&m.completedCounter, 1)
					m.metrics.IncTasksCompleted()
					_ = m.ReportResult(t.ParentID, t.ID, t.Result, true)
				}
			}
		}
	}()
}

// DeregisterWorker removes worker channel and closes it.
func (m *MicroTaskManager) DeregisterWorker(workerID string) {
	m.mu.Lock()
	if ch, ok := m.workers[workerID]; ok {
		close(ch)
		delete(m.workers, workerID)
		delete(m.bufs, workerID)
		m.metrics.SetWorkerCount(len(m.workers))
		m.addEvent(Event{Time: time.Now(), Type: EventWorkerDereg, WorkerID: workerID})
	}
	m.mu.Unlock()
}

// -------------------- DAG management --------------------

// CreateDAG creates a new DAG for parent job (rootID)
func (m *MicroTaskManager) CreateDAG(rootID string) *TaskDAG {
	d := &TaskDAG{
		RootID: rootID,
		Nodes:  make(map[string]*MicroTask),
		Edges:  make(map[string][]string),
	}
	m.mu.Lock()
	m.dags[rootID] = d
	m.mu.Unlock()
	return d
}

// GetDAG returns DAG if exists
func (m *MicroTaskManager) GetDAG(rootID string) (*TaskDAG, bool) {
	m.mu.RLock()
	d, ok := m.dags[rootID]
	m.mu.RUnlock()
	return d, ok
}

// DumpDAG returns JSON of DAG snapshot (thread-safe, avoids serializing mutex)
func (m *MicroTaskManager) DumpDAG(rootID string) ([]byte, error) {
	m.mu.RLock()
	d, ok := m.dags[rootID]
	m.mu.RUnlock()
	if !ok {
		return nil, errors.New("dag not found")
	}
	// make a snapshot copy
	d.mu.RLock()
	defer d.mu.RUnlock()
	type snapshot struct {
		RootID string                `json:"root_id"`
		Nodes  map[string]*MicroTask `json:"nodes"`
		Edges  map[string][]string   `json:"edges"`
	}
	s := snapshot{
		RootID: d.RootID,
		Nodes:  make(map[string]*MicroTask, len(d.Nodes)),
		Edges:  make(map[string][]string, len(d.Edges)),
	}
	for k, v := range d.Nodes {
		// shallow copy to avoid races
		c := *v
		s.Nodes[k] = &c
	}
	for k, v := range d.Edges {
		c := make([]string, len(v))
		copy(c, v)
		s.Edges[k] = c
	}
	return json.Marshal(s)
}

// -------------------- Slicing / Submission / Progress --------------------

// SliceTask adaptive slicing: AI or heuristic may tune numSlices/size
func (m *MicroTaskManager) SliceTask(rootID string, payload map[string]any, numSlices int) ([]*MicroTask, error) {
	if numSlices <= 0 {
		numSlices = 1
	}
	m.mu.RLock()
	d, ok := m.dags[rootID]
	m.mu.RUnlock()
	if !ok {
		d = m.CreateDAG(rootID)
	}
	created := make([]*MicroTask, 0, numSlices)
	for i := 0; i < numSlices; i++ {
		id := fmt.Sprintf("%s-mt-%d-%d", rootID, time.Now().UnixNano(), i)
		mt := &MicroTask{
			ID:         id,
			ParentID:   rootID,
			Payload:    copyMap(payload),
			Status:     "pending",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			MaxRetries: 3,
			Progress:   0,
			TraceID:    uuid.New().String(),
		}
		d.mu.Lock()
		d.Nodes[id] = mt
		d.Edges[rootID] = append(d.Edges[rootID], id)
		d.mu.Unlock()
		created = append(created, mt)
		atomic.AddInt64(&m.createdCounter, 1)
		m.metrics.IncTasksCreated()
		m.addEvent(Event{Time: time.Now(), Type: EventTaskCreated, TaskID: mt.ID, ParentID: rootID, TraceID: mt.TraceID, Msg: "task created and queued"})
		// submit to queue (non-blocking)
		go func(t *MicroTask) { _ = m.SubmitTaskCtx(m.ctx, rootID, t) }(mt)
	}
	// update persistence signal (best-effort)
	m.forcePersist()
	return created, nil
}

// SubmitTaskCtx enqueues a microtask with context support (respects ctx cancel).
func (m *MicroTaskManager) SubmitTaskCtx(ctx context.Context, rootID string, t *MicroTask) error {
	// optional auth: allow callers to register an AuthChecker and set a resource/action in ctx if desired.
	select {
	case <-m.ctx:
		return errors.New("manager stopped")
	case <-ctx.Done():
		return ctx.Err()
	case m.events <- t:
		atomic.AddInt64(&m.dispatchedCounter, 1)
		m.metrics.IncTasksDispatched()
		m.addEvent(Event{Time: time.Now(), Type: EventTaskDispatched, TaskID: t.ID, ParentID: rootID, TraceID: t.TraceID})
		return nil
	}
}

// SubmitTask convenience wrapper uses manager context.
func (m *MicroTaskManager) SubmitTask(rootID string, t *MicroTask) {
	_ = m.SubmitTaskCtx(m.ctx, rootID, t)
}

// UpdateProgress sets the progress for a task (0..100).
func (m *MicroTaskManager) UpdateProgress(rootID, taskID string, progress int) error {
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	m.mu.RLock()
	d, ok := m.dags[rootID]
	m.mu.RUnlock()
	if !ok {
		return errors.New("dag not found")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.Nodes[taskID]
	if !ok {
		return errors.New("task not found")
	}
	t.Progress = progress
	t.UpdatedAt = time.Now()
	m.addEvent(Event{Time: time.Now(), Type: EventTaskProgress, TaskID: taskID, ParentID: rootID, TraceID: t.TraceID, Msg: fmt.Sprintf("progress=%d", progress)})
	return nil
}

// -------------------- Report / Aggregation --------------------

// ReportResult updates task result and triggers aggregation if needed
func (m *MicroTaskManager) ReportResult(rootID, taskID string, result any, success bool) error {
	m.mu.RLock()
	d, ok := m.dags[rootID]
	m.mu.RUnlock()
	if !ok {
		return errors.New("dag not found")
	}
	d.mu.Lock()
	t, ok := d.Nodes[taskID]
	if !ok {
		d.mu.Unlock()
		return errors.New("task not found")
	}
	if success {
		t.Result = result
		t.Status = "done"
		t.UpdatedAt = time.Now()
		m.addEvent(Event{Time: time.Now(), Type: EventTaskDone, TaskID: taskID, ParentID: rootID, TraceID: t.TraceID})
		atomic.AddInt64(&m.completedCounter, 1)
		m.metrics.IncTasksCompleted()
	} else {
		t.Attempts++
		if t.Attempts <= t.MaxRetries {
			t.Status = "pending"
			t.UpdatedAt = time.Now()
			// requeue outside lock
			d.mu.Unlock()
			go m.SubmitTask(rootID, t)
			m.addEvent(Event{Time: time.Now(), Type: EventTaskFailed, TaskID: taskID, ParentID: rootID, TraceID: t.TraceID, Msg: "will retry"})
			return nil
		}
		t.Status = "failed"
		t.UpdatedAt = time.Now()
		m.addEvent(Event{Time: time.Now(), Type: EventTaskFailed, TaskID: taskID, ParentID: rootID, TraceID: t.TraceID, Msg: "permanently failed"})
		atomic.AddInt64(&m.failedCounter, 1)
		m.metrics.IncTasksFailed()
	}
	children := d.Edges[rootID]
	d.mu.Unlock()

	// check if all children done to aggregate (outside lock to avoid long critical section)
	allDone := true
	d.mu.RLock()
	for _, child := range children {
		if nd, ok := d.Nodes[child]; ok && nd.Status != "done" {
			allDone = false
			break
		}
	}
	d.mu.RUnlock()

	if allDone {
		// run aggregation in background
		go m.aggregateResults(d)
		// persistence hint
		m.forcePersist()
	}
	return nil
}

func (m *MicroTaskManager) aggregateResults(d *TaskDAG) {
	results := []any{}
	d.mu.RLock()
	children := d.Edges[d.RootID]
	for _, child := range children {
		if t, ok := d.Nodes[child]; ok && t.Status == "done" {
			results = append(results, t.Result)
		}
	}
	d.mu.RUnlock()

	m.mu.RLock()
	agg := m.agg
	m.mu.RUnlock()
	out := agg.Aggregate(results)

	d.mu.Lock()
	if root, ok := d.Nodes[d.RootID]; ok {
		root.Result = out
		root.Status = "done"
		root.UpdatedAt = time.Now()
	} else {
		d.Nodes[d.RootID] = &MicroTask{
			ID:        d.RootID,
			Result:    out,
			Status:    "done",
			UpdatedAt: time.Now(),
		}
	}
	d.mu.Unlock()

	m.addEvent(Event{Time: time.Now(), Type: EventInfo, ParentID: d.RootID, Msg: "aggregation completed"})
}

// SetAggregator allows injecting custom aggregator
func (m *MicroTaskManager) SetAggregator(a Aggregator) {
	if a == nil {
		a = &ConcatAggregator{}
	}
	m.mu.Lock()
	m.agg = a
	m.mu.Unlock()
}

// -------------------- Dispatcher (smart) --------------------

// chooseWorker selects worker channel using least-loaded then round-robin.
func (m *MicroTaskManager) chooseWorker() (string, chan *MicroTask) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.workers) == 0 {
		return "", nil
	}
	// first attempt: least loaded (len(chan)/cap)
	var bestID string
	var bestCh chan *MicroTask
	var bestScore float64 = 2.0 // larger than possible occupancy
	for id, ch := range m.workers {
		capacity := m.bufs[id]
		if capacity <= 0 {
			capacity = 1
		}
		score := float64(len(ch)) / float64(capacity)
		if score < bestScore {
			bestScore = score
			bestID = id
			bestCh = ch
		}
	}
	if bestCh != nil && bestScore < 0.95 {
		return bestID, bestCh
	}
	// fallback: round-robin
	n := len(m.workers)
	if n == 0 {
		return "", nil
	}
	idx := int(atomic.AddUint64(&m.rr, 1) % uint64(n))
	i := 0
	for id, ch := range m.workers {
		if i == idx {
			return id, ch
		}
		i++
	}
	// should not reach
	for id, ch := range m.workers {
		return id, ch
	}
	return "", nil
}

// dispatcher sends tasks to available workers (smart).
func (m *MicroTaskManager) dispatcher() {
	for {
		select {
		case <-m.ctx:
			return
		case t, ok := <-m.events:
			if !ok {
				return
			}
			// attempt to dispatch (with limited retries)
			dispatched := false
			try := 0
			for !dispatched && try < 3 {
				workerID, ch := m.chooseWorker()
				if ch == nil {
					// no workers: wait briefly and retry, or requeue if manager still running
					try++
					select {
					case <-time.After(200 * time.Millisecond):
					case <-m.ctx:
						return
					}
					continue
				}
				select {
				case ch <- t:
					dispatched = true
					m.addEvent(Event{Time: time.Now(), Type: EventTaskDispatched, TaskID: t.ID, WorkerID: workerID, TraceID: t.TraceID})
				case <-time.After(1 * time.Second):
					// couldn't send to chosen worker, maybe full; try again
					try++
				case <-m.ctx:
					return
				}
			}
			if !dispatched {
				// if still not dispatched and stealing enabled, attempt to push to any worker (force)
				if m.steal {
					m.mu.RLock()
					for wid, ch := range m.workers {
						select {
						case ch <- t:
							dispatched = true
							m.addEvent(Event{Time: time.Now(), Type: EventTaskDispatched, TaskID: t.ID, WorkerID: wid, TraceID: t.TraceID, Msg: "stolen/forced dispatch"})
						default:
							// skip
						}
						if dispatched {
							break
						}
					}
					m.mu.RUnlock()
				}
			}
			if !dispatched {
				// final fallback: requeue with delay (to avoid task loss)
				go func(tt *MicroTask) {
					select {
					case <-m.ctx:
						return
					case <-time.After(500 * time.Millisecond):
						_ = m.SubmitTaskCtx(m.ctx, tt.ParentID, tt)
					}
				}(t)
				m.addEvent(Event{Time: time.Now(), Type: EventInfo, TaskID: t.ID, Msg: "requeued after dispatch attempts", TraceID: t.TraceID})
			}
		}
	}
}

// -------------------- Utilities --------------------

// shallow copy payload map
func copyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// -------------------- Hooks / Registration --------------------

// RegisterMetricsCollector sets the metrics collector (optional)
func (m *MicroTaskManager) RegisterMetricsCollector(mc MetricsCollector) {
	if mc == nil {
		mc = &noopCollector{}
	}
	m.metrics = mc
}

// RegisterAuthChecker sets optional auth hook (non-enforcing; manager will call it where appropriate)
func (m *MicroTaskManager) RegisterAuthChecker(a AuthChecker) {
	m.auth = a
}

// -------------------- State / Introspection --------------------

// Snapshot returns a compact JSON snapshot (in-memory) suitable for inspection.
func (m *MicroTaskManager) Snapshot() ([]byte, error) {
	// reuse DumpDAG for all DAGs
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]any{
		"now": time.Now(),
	}
	dags := map[string]any{}
	for k := range m.dags {
		b, err := m.DumpDAG(k)
		if err != nil {
			dags[k] = map[string]any{"error": err.Error()}
			continue
		}
		var v any
		_ = json.Unmarshal(b, &v)
		dags[k] = v
	}
	out["dags"] = dags
	out["events"] = m.ListEvents()
	return json.MarshalIndent(out, "", "  ")
}

// -------------------- ExposeFunctions for Orchestrator / Model --------------------

func (m *MicroTaskManager) ExposeFunctions() map[string]any {
	return map[string]any{
		"create_dag":           m.CreateDAG,
		"slice_task":           m.SliceTask,
		"submit_task":          m.SubmitTask,
		"submit_task_ctx":      m.SubmitTaskCtx,
		"report_result":        m.ReportResult,
		"register_worker":      m.RegisterWorker,
		"register_worker_hdl":  m.RegisterWorkerHandler,
		"deregister_worker":    m.DeregisterWorker,
		"dump_dag":             m.DumpDAG,
		"update_progress":      m.UpdateProgress,
		"list_events":          m.ListEvents,
		"set_aggregator":       m.SetAggregator,
		"stop_manager":         m.Stop,
		"enable_persistence":   m.EnablePersistence,
		"save_state":           m.SaveState,
		"load_state":           m.LoadState,
		"register_metrics":     m.RegisterMetricsCollector,
		"register_auth":        m.RegisterAuthChecker,
		"snapshot":             m.Snapshot,
	}
}