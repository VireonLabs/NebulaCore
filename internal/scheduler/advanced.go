// internal/scheduler/advanced.go
// NebulaCore Advanced Scheduler (production-ready, AI-aware, explainable)
// - Multiple pluggable SchedulerAlgorithm implementations (AutoDev-ready).
// - Decision Journal (NDJSON) with optional file output and rotation.
// - Adaptive Rescheduling (fallbacks, requeue).
// - Explainability per-task (detailed trace).
// - Scheduler-level KPIs.
// - Integration points for Policy Engine (via PolicyChecker hook).
package scheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aggregation"
)

// -------------------- Task model --------------------

type Task struct {
	ID         string
	Type       string
	Payload    map[string]any // may contain "requirements": map[string]float64 or keys like "cpu","gpu","ram"
	Priority   int
	Deadline   time.Time
	Affinity   []string // Node IDs or label constraints (key=value)
	Region     string
	Status     string // pending, running, failed, done
	AssignedTo string // NodeID
	SLO        map[string]any
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Owner      string
}

// -------------------- Decision Journal --------------------

type DecisionEntry struct {
	Time       time.Time              `json:"time"`
	TaskID     string                 `json:"task_id"`
	Algo       string                 `json:"algorithm"`
	Requested  map[string]float64     `json:"requested,omitempty"`
	AssignedTo string                 `json:"assigned_to,omitempty"`
	Result     string                 `json:"result"` // "allocated","queued","failed","simulated","allocated_fallback","rejected_by_policy"
	Reason     string                 `json:"reason,omitempty"`
	ScoreVec   map[string]float64     `json:"score_vector,omitempty"`
	Explain    string                 `json:"explain,omitempty"`
	Meta       map[string]any         `json:"meta,omitempty"`
	Extra      map[string]any         `json:"extra,omitempty"`
	TimeMs     int64                  `json:"time_ms,omitempty"`
}

// decision journal writer (background) with simple rotation
type journalWriter struct {
	filePath  string
	file      *os.File
	w         *bufio.Writer
	ch        chan DecisionEntry
	closed    int32
	mu        sync.Mutex
	rotateMux sync.Mutex
	maxSize   int64 // bytes
}

const defaultJournalMaxSize = 10 * 1024 * 1024 // 10MB

func newJournalWriter(path string) (*journalWriter, error) {
	j := &journalWriter{
		filePath: path,
		ch:       make(chan DecisionEntry, 4096),
		maxSize:  defaultJournalMaxSize,
	}
	if path == "" || path == "-" {
		j.w = bufio.NewWriter(os.Stdout)
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		j.file = f
		j.w = bufio.NewWriter(f)
	}
	go j.loop()
	return j, nil
}

func (j *journalWriter) loop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case e, ok := <-j.ch:
			if !ok {
				j.flushAndClose()
				return
			}
			j.emit(e)
		case <-ticker.C:
			j.flush()
			j.tryRotate()
		}
	}
}

func (j *journalWriter) emit(e DecisionEntry) {
	b, _ := json.Marshal(e)
	j.mu.Lock()
	defer j.mu.Unlock()
	_, _ = j.w.Write(append(b, '\n'))
}

func (j *journalWriter) Write(e DecisionEntry) {
	if atomic.LoadInt32(&j.closed) == 1 {
		return
	}
	select {
	case j.ch <- e:
	default:
		// backpressure: try briefly, otherwise drop (best-effort)
		select {
		case j.ch <- e:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (j *journalWriter) flush() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.w.Flush()
}

func (j *journalWriter) flushAndClose() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.w.Flush()
	if j.file != nil {
		_ = j.file.Close()
	}
}

func (j *journalWriter) Close() {
	if !atomic.CompareAndSwapInt32(&j.closed, 0, 1) {
		return
	}
	close(j.ch)
}

func (j *journalWriter) tryRotate() {
	if j.file == nil {
		return
	}
	j.rotateMux.Lock()
	defer j.rotateMux.Unlock()
	fi, err := j.file.Stat()
	if err != nil {
		return
	}
	if fi.Size() < j.maxSize {
		return
	}
	// rotate
	_ = j.w.Flush()
	_ = j.file.Close()
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	newName := fmt.Sprintf("%s.%s", j.filePath, timestamp)
	_ = os.Rename(j.filePath, newName)
	f, err := os.OpenFile(j.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// try to reopen old file (best-effort)
		j.file = nil
		j.w = bufio.NewWriter(os.Stdout)
		return
	}
	j.file = f
	j.w = bufio.NewWriter(f)
}

// -------------------- SchedulerAlgorithm interface --------------------

type SchedulerAlgorithm interface {
	Name() string
	// Schedule returns map[taskID]nodeID, meta, error
	Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error)
	ExplainDecision(taskID string) string
}

// -------------------- Scheduler KPIs --------------------

type SchedulerKPIs struct {
	SuccessCount      uint64  `json:"success_count"`
	FailureCount      uint64  `json:"failure_count"`
	RequeueCount      uint64  `json:"requeue_count"`
	AvgWaitMs         float64 `json:"avg_wait_ms"`
	TotalScheduled    uint64  `json:"total_scheduled"`
	AvgAllocationTime float64 `json:"avg_allocation_time_ms"`
}

// -------------------- AdvancedScheduler --------------------

type PolicyChecker func(t *Task) error
type AlgoSelector func(telemetry map[string]any) string // returns algorithm name to prefer

type AdvancedScheduler struct {
	rp            *aggregation.ResourcePool
	mu            sync.Mutex
	tasks         map[string]*Task
	algos         map[string]SchedulerAlgorithm
	activeAlgo    string
	sandbox       map[string]any
	traces        []string
	decisions     map[string]string // persistent last scheduling decisions
	rand          *rand.Rand
	loopInterval  time.Duration
	loopStop      chan struct{}
	onSchedule    []func(map[string]string)
	journal       *journalWriter
	journalPath   string
	kpis          SchedulerKPIs
	policyChecker PolicyChecker
	selector      AlgoSelector
	// fallback order for adaptive rescheduling; if empty, use list of known algos
	fallbackOrder []string
	// storage for algorithm explanations per task (last run)
	explainMap map[string]string
}

// NewAdvancedScheduler creates scheduler attached to ResourcePool (can be nil)
func NewAdvancedScheduler(rp *aggregation.ResourcePool) *AdvancedScheduler {
	src := rand.NewSource(time.Now().UnixNano())
	return &AdvancedScheduler{
		rp:           rp,
		tasks:        make(map[string]*Task),
		algos:        make(map[string]SchedulerAlgorithm),
		sandbox:      map[string]any{},
		decisions:    make(map[string]string),
		rand:         rand.New(src),
		loopInterval: 2 * time.Second,
		explainMap:   map[string]string{},
	}
}

// -------------------- Task ops --------------------

func (s *AdvancedScheduler) AddTask(t *Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	t.UpdatedAt = time.Now()
	if t.Status == "" {
		t.Status = "pending"
	}
	s.tasks[t.ID] = t
	s.traces = append(s.traces, "Added task "+t.ID)
}

func (s *AdvancedScheduler) RemoveTask(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, id)
	s.traces = append(s.traces, "Removed task "+id)
}

func (s *AdvancedScheduler) GetTask(taskID string) *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[taskID]; ok {
		c := *t
		return &c
	}
	return nil
}

func (s *AdvancedScheduler) listTasks() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, *t)
	}
	return out
}

// -------------------- Decision Journal & Policy --------------------

func (s *AdvancedScheduler) SetJournalPath(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal != nil {
		s.journal.Close()
		s.journal = nil
	}
	if path == "" {
		s.journal = nil
		s.journalPath = ""
		return nil
	}
	j, err := newJournalWriter(path)
	if err != nil {
		return err
	}
	s.journal = j
	s.journalPath = path
	return nil
}

func (s *AdvancedScheduler) SetPolicyChecker(pc PolicyChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyChecker = pc
}

func (s *AdvancedScheduler) SetAlgoSelector(sel AlgoSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selector = sel
}

// -------------------- Algorithm registration & AutoDev --------------------

func (s *AdvancedScheduler) RegisterAlgorithm(algo SchedulerAlgorithm) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.algos[algo.Name()] = algo
	if s.activeAlgo == "" {
		s.activeAlgo = algo.Name()
	}
	s.traces = append(s.traces, "Registered algorithm "+algo.Name())
}

func (s *AdvancedScheduler) RegisterAlgorithmFromLoader(name string, bytes []byte, loader func([]byte) (SchedulerAlgorithm, error)) error {
	if loader == nil {
		return errors.New("loader nil")
	}
	a, err := loader(bytes)
	if err != nil {
		return err
	}
	if a.Name() == "" {
		return errors.New("algorithm must have name")
	}
	s.RegisterAlgorithm(a)
	return nil
}

func (s *AdvancedScheduler) SetActiveAlgorithm(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.algos[name]; !ok {
		return fmt.Errorf("algorithm %s not registered", name)
	}
	s.activeAlgo = name
	s.traces = append(s.traces, "Active algorithm set to "+name)
	return nil
}

func (s *AdvancedScheduler) SetFallbackOrder(order []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallbackOrder = append([]string{}, order...)
}

// -------------------- Scheduling core --------------------

// Schedule runs active algorithm once and attempts to allocate via ResourcePool (if attached).
// Returns applied assignments map[taskID]nodeID.
func (s *AdvancedScheduler) Schedule(telemetry map[string]any) map[string]string {
	// Choose algorithm possibly via selector
	s.mu.Lock()
	algoName := s.activeAlgo
	if s.selector != nil {
		if sel := s.selector(telemetry); sel != "" {
			if _, ok := s.algos[sel]; ok {
				algoName = sel
			}
		}
	}
	algo, ok := s.algos[algoName]
	if !ok {
		s.traces = append(s.traces, "no active algorithm")
		s.mu.Unlock()
		return nil
	}
	// snapshot pending tasks
	var pending []*Task
	for _, t := range s.tasks {
		// deadline-aware early filtering: tasks near deadline get priority in algorithms that respect it
		if t.Status == "pending" {
			copy := *t
			pending = append(pending, &copy)
		}
	}
	s.mu.Unlock()

	// node snapshot
	var nodes []*aggregation.ResourceNode
	if s.rp != nil {
		s.rp.mu.RLock()
		for _, n := range s.rp.nodes {
			c := *n
			c.Resources = copyMapResources(n.Resources)
			c.Allocated = copyMapResources(n.Allocated)
			c.Labels = copyMapString(n.Labels)
			c.Meta = copyMapAny(n.Meta)
			nodes = append(nodes, &c)
		}
		s.rp.mu.RUnlock()
	}

	// run algorithm
	startAlgo := time.Now()
	decisions, meta, err := algo.Schedule(pending, nodes, telemetry)
	algoDuration := time.Since(startAlgo)
	if err != nil {
		s.mu.Lock()
		s.traces = append(s.traces, fmt.Sprintf("algo %s error: %v", algoName, err))
		s.mu.Unlock()
		return nil
	}

	applied := map[string]string{}
	// attempt to apply decisions
	for tid, nid := range decisions {
		now := time.Now()
		t := s.GetTask(tid)
		if t == nil {
			continue
		}
		// policy check
		if s.policyChecker != nil {
			if err := s.policyChecker(t); err != nil {
				s.recordJournal(DecisionEntry{
					Time:       now,
					TaskID:     tid,
					Algo:       algoName,
					Requested:  parseRequirementsFromPayload(t.Payload),
					AssignedTo: nid,
					Result:     "rejected_by_policy",
					Reason:     err.Error(),
					Meta:       meta,
					TimeMs:     int64(algoDuration / time.Millisecond),
				})
				atomic.AddUint64(&s.kpis.FailureCount, 1)
				s.mu.Lock()
				s.traces = append(s.traces, fmt.Sprintf("Task %s rejected by policy: %v", tid, err))
				if task, ok := s.tasks[tid]; ok {
					task.Status = "failed"
					task.UpdatedAt = time.Now()
				}
				s.mu.Unlock()
				continue
			}
		}

		req := parseRequirementsFromPayload(t.Payload)
		resv := aggregation.Reservation{
			ID:           "",
			Requirements: req,
			Priority:     t.Priority,
			Soft:         false,
			Affinity:     t.Affinity,
			Policy:       "",
			CreatedAt:    time.Now(),
			Owner:        t.Owner,
		}

		allocStart := time.Now()
		var nodeID string
		var scoreVec map[string]float64
		var allocErr error
		if s.rp == nil {
			nodeID = nid
			allocErr = nil
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan struct{})
			go func() {
				nodeID, scoreVec, allocErr = s.rp.Allocate(resv)
				close(done)
			}()
			select {
			case <-done:
				cancel()
			case <-ctx.Done():
				cancel()
				allocErr = fmt.Errorf("allocation-timeout")
			}
		}
		allocDur := time.Since(allocStart)

		entry := DecisionEntry{
			Time:       now,
			TaskID:     tid,
			Algo:       algoName,
			Requested:  req,
			AssignedTo: nodeID,
			ScoreVec:   scoreVec,
			Meta:       meta,
			TimeMs:     int64(allocDur / time.Millisecond),
		}

		if allocErr == nil {
			s.mu.Lock()
			if task, ok := s.tasks[tid]; ok {
				task.Status = "running"
				task.AssignedTo = nodeID
				task.UpdatedAt = time.Now()
			}
			s.decisions[tid] = nodeID
			// ask algorithm for explanation and store it
			exp := algo.ExplainDecision(tid)
			if exp == "" {
				exp = fmt.Sprintf("Scheduled by %s", algoName)
			}
			s.explainMap[tid] = exp
			s.traces = append(s.traces, fmt.Sprintf("Allocated %s -> %s", tid, nodeID))
			s.mu.Unlock()

			entry.Result = "allocated"
			entry.Explain = exp
			s.recordJournal(entry)
			atomic.AddUint64(&s.kpis.SuccessCount, 1)
			atomic.AddUint64(&s.kpis.TotalScheduled, 1)
			s.updateWaitMetric(t)
			applied[tid] = nodeID
			s.callOnScheduleListeners(map[string]string{tid: nodeID})
			continue
		}

		// failed allocation
		entry.Result = "failed"
		entry.Reason = allocErr.Error()
		entry.Explain = algo.ExplainDecision(tid)
		s.recordJournal(entry)
		atomic.AddUint64(&s.kpis.FailureCount, 1)
		s.mu.Lock()
		s.traces = append(s.traces, fmt.Sprintf("Allocation failed for %s on %s: %v", tid, nid, allocErr))
		fallbackTried := s.tryFallbacks(tid, nid, algoName, req, allocErr)
		if !fallbackTried {
			// requeue by default
			if task, ok := s.tasks[tid]; ok {
				task.Status = "pending"
				task.AssignedTo = ""
				task.UpdatedAt = time.Now()
			}
			atomic.AddUint64(&s.kpis.RequeueCount, 1)
			s.traces = append(s.traces, fmt.Sprintf("Task %s requeued after fail", tid))
		}
		s.mu.Unlock()
	}
	// store algorithm meta/traces
	s.mu.Lock()
	if meta != nil {
		s.sandbox[algoName] = meta
	}
	prev := s.kpis.AvgAllocationTime
	if prev == 0 {
		s.kpis.AvgAllocationTime = float64(algoDuration.Milliseconds())
	} else {
		s.kpis.AvgAllocationTime = 0.2*float64(algoDuration.Milliseconds()) + 0.8*prev
	}
	s.mu.Unlock()
	return applied
}

func (s *AdvancedScheduler) updateWaitMetric(t *Task) {
	now := time.Now()
	waitMs := float64(now.Sub(t.CreatedAt).Milliseconds())
	prevAvg := s.kpis.AvgWaitMs
	total := float64(atomic.LoadUint64(&s.kpis.TotalScheduled))
	if total <= 1 {
		s.kpis.AvgWaitMs = waitMs
	} else {
		alpha := 1.0 / (total + 1.0)
		s.kpis.AvgWaitMs = alpha*waitMs + (1-alpha)*prevAvg
	}
}

// tryFallbacks attempts to schedule the task using a fallback sequence of algorithms (non-blocking).
// returns true if any fallback led to immediate allocation success.
func (s *AdvancedScheduler) tryFallbacks(taskID, failedNode, origAlgo string, req map[aggregation.ResourceType]float64, allocErr error) bool {
	s.mu.Lock()
	order := append([]string{}, s.fallbackOrder...)
	if len(order) == 0 {
		for k := range s.algos {
			if k != origAlgo {
				order = append(order, k)
			}
		}
	}
	s.mu.Unlock()

	for _, algoName := range order {
		if algoName == origAlgo {
			continue
		}
		s.mu.Lock()
		algo, ok := s.algos[algoName]
		s.mu.Unlock()
		if !ok {
			continue
		}
		var nodes []*aggregation.ResourceNode
		if s.rp != nil {
			s.rp.mu.RLock()
			for _, n := range s.rp.nodes {
				c := *n
				c.Resources = copyMapResources(n.Resources)
				c.Allocated = copyMapResources(n.Allocated)
				c.Labels = copyMapString(n.Labels)
				c.Meta = copyMapAny(n.Meta)
				nodes = append(nodes, &c)
			}
			s.rp.mu.RUnlock()
		}
		s.mu.Lock()
		origTask, ok := s.tasks[taskID]
		var tSnap *Task
		if ok {
			c := *origTask
			tSnap = &c
		}
		s.mu.Unlock()
		if tSnap == nil {
			continue
		}
		decisions, meta, err := algo.Schedule([]*Task{tSnap}, nodes, nil)
		if err != nil {
			_ = meta
			continue
		}
		if nodeID, ok := decisions[taskID]; ok {
			resv := aggregation.Reservation{
				ID:           "",
				Requirements: req,
				Priority:     tSnap.Priority,
				Soft:         false,
				Affinity:     tSnap.Affinity,
				CreatedAt:    time.Now(),
				Owner:        tSnap.Owner,
			}
			var nodeAlloc string
			var allocErr2 error
			if s.rp == nil {
				nodeAlloc = nodeID
			} else {
				nodeAlloc, _, allocErr2 = s.rp.Allocate(resv)
			}
			if allocErr2 == nil {
				s.mu.Lock()
				if task, ok := s.tasks[taskID]; ok {
					task.Status = "running"
					task.AssignedTo = nodeAlloc
					task.UpdatedAt = time.Now()
				}
				s.decisions[taskID] = nodeAlloc
				s.traces = append(s.traces, fmt.Sprintf("Fallback %s allocated %s -> %s", algoName, taskID, nodeAlloc))
				s.mu.Unlock()
				s.recordJournal(DecisionEntry{
					Time:       time.Now(),
					TaskID:     taskID,
					Algo:       algoName,
					Requested:  req,
					AssignedTo: nodeAlloc,
					Result:     "allocated_fallback",
					Reason:     allocErr.Error(),
					Meta:       meta,
					Explain:    algo.ExplainDecision(taskID),
				})
				atomic.AddUint64(&s.kpis.SuccessCount, 1)
				atomic.AddUint64(&s.kpis.TotalScheduled, 1)
				return true
			}
		}
	}
	return false
}

// -------------------- Simulation / Sandbox --------------------

func (s *AdvancedScheduler) SimulateAlgorithm(algo SchedulerAlgorithm, telemetry map[string]any) map[string]any {
	s.mu.Lock()
	var pending []*Task
	for _, t := range s.tasks {
		if t.Status == "pending" {
			c := *t
			pending = append(pending, &c)
		}
	}
	s.mu.Unlock()

	var nodes []*aggregation.ResourceNode
	if s.rp != nil {
		s.rp.mu.RLock()
		for _, n := range s.rp.nodes {
			c := *n
			c.Resources = copyMapResources(n.Resources)
			c.Allocated = copyMapResources(n.Allocated)
			c.Labels = copyMapString(n.Labels)
			c.Meta = copyMapAny(n.Meta)
			nodes = append(nodes, &c)
		}
		s.rp.mu.RUnlock()
	}
	decisions, meta, err := algo.Schedule(pending, nodes, telemetry)
	out := map[string]any{"decisions": decisions, "meta": meta}
	if err != nil {
		out["error"] = err.Error()
	}
	explain := map[string]string{}
	for _, t := range pending {
		explain[t.ID] = algo.ExplainDecision(t.ID)
	}
	out["explain"] = explain
	return out
}

// -------------------- Loop control --------------------

func (s *AdvancedScheduler) StartLoop(interval time.Duration) {
	s.mu.Lock()
	if s.loopStop != nil {
		s.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = s.loopInterval
	}
	s.loopInterval = interval
	stop := make(chan struct{})
	s.loopStop = stop
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(s.loopInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				telemetry := map[string]any{}
				if s.rp != nil {
					telemetry["kpis"] = s.rp.GetKPIs()
				}
				if s.selector != nil {
					if sel := s.selector(telemetry); sel != "" {
						_ = s.SetActiveAlgorithm(sel)
					}
				}
				_ = s.Schedule(telemetry)
			case <-stop:
				return
			}
		}
	}()
	s.mu.Lock()
	s.traces = append(s.traces, "Scheduler loop started")
	s.mu.Unlock()
}

func (s *AdvancedScheduler) StopLoop() {
	s.mu.Lock()
	if s.loopStop != nil {
		close(s.loopStop)
		s.loopStop = nil
		s.traces = append(s.traces, "Scheduler loop stopped")
	}
	s.mu.Unlock()
}

// -------------------- Builtin Algorithms (complete & explainable) --------------------

// RoundRobinAlgo
type RoundRobinAlgo struct {
	idx         int
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewRoundRobinAlgo(name string) *RoundRobinAlgo {
	return &RoundRobinAlgo{name: name, lastExplain: map[string]string{}}
}
func (rr *RoundRobinAlgo) Name() string {
	if rr.name == "" {
		return "round-robin"
	}
	return rr.name
}

func (rr *RoundRobinAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes available")
	}
	for _, t := range tasks {
		start := rr.idx % len(nodes)
		assigned := ""
		assignedIndex := -1
		for i := 0; i < len(nodes); i++ {
			n := nodes[(start+i)%len(nodes)]
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			assigned = n.ID
			assignedIndex = (start + i) % len(nodes)
			rr.mu.Lock()
			rr.idx = (assignedIndex + 1) % len(nodes)
			rr.mu.Unlock()
			break
		}
		if assigned == "" {
			rr.mu.Lock()
			assigned = nodes[rr.idx%len(nodes)].ID
			assignedIndex = rr.idx % len(nodes)
			rr.idx = (rr.idx + 1) % len(nodes)
			rr.mu.Unlock()
		}
		out[t.ID] = assigned
		rr.mu.Lock()
		rr.lastExplain[t.ID] = fmt.Sprintf("RoundRobin: assigned to node %s (round index %d)", assigned, assignedIndex)
		rr.mu.Unlock()
	}
	return out, nil, nil
}

func (rr *RoundRobinAlgo) ExplainDecision(taskID string) string {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if v, ok := rr.lastExplain[taskID]; ok {
		return v
	}
	return "RoundRobin evenly distributes tasks"
}

// CostAwareAlgo
type CostAwareAlgo struct {
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewCostAwareAlgo(name string) *CostAwareAlgo {
	return &CostAwareAlgo{name: name, lastExplain: map[string]string{}}
}
func (c *CostAwareAlgo) Name() string {
	if c.name == "" {
		return "cost-aware"
	}
	return c.name
}

func (c *CostAwareAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	for _, t := range tasks {
		type cand struct {
			node  *aggregation.ResourceNode
			score float64
			reason string
		}
		var cands []cand
		req := bsonRequirementsFromTask(t)
		for _, n := range nodes {
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			ok := true
			for rt, amt := range req {
				if n.Resources[rt] < amt {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			cost := 1.0
			if v, ok := n.Meta["cost"]; ok {
				switch vv := v.(type) {
				case float64:
					cost = vv
				case int:
					cost = float64(vv)
				case string:
					// ignore parse in core; orchestrator may normalize meta
				}
			}
			free := 0.0
			for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
				free += n.Resources[rt]
			}
			score := free / (cost + 1e-6)
			reason := fmt.Sprintf("free=%.2f cost=%.4f score=%.4f", free, cost, score)
			cands = append(cands, cand{node: n, score: score, reason: reason})
		}
		if len(cands) == 0 {
			continue
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
		choice := cands[0]
		out[t.ID] = choice.node.ID
		c.mu.Lock()
		c.lastExplain[t.ID] = fmt.Sprintf("CostAware: chose node %s because %s", choice.node.ID, choice.reason)
		c.mu.Unlock()
	}
	return out, nil, nil
}

func (c *CostAwareAlgo) ExplainDecision(taskID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.lastExplain[taskID]; ok {
		return v
	}
	return "CostAware: maximize free capacity per cost unit"
}

// EnergyAwareAlgo
type EnergyAwareAlgo struct {
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewEnergyAwareAlgo(name string) *EnergyAwareAlgo {
	return &EnergyAwareAlgo{name: name, lastExplain: map[string]string{}}
}
func (e *EnergyAwareAlgo) Name() string {
	if e.name == "" {
		return "energy-aware"
	}
	return e.name
}

func (e *EnergyAwareAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	for _, t := range tasks {
		best := -1
		bestScore := math.Inf(-1)
		req := bsonRequirementsFromTask(t)
		for i, n := range nodes {
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			ok := true
			for rt, amt := range req {
				if n.Resources[rt] < amt {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			free := 0.0
			for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
				free += n.Resources[rt]
			}
			score := free - 0.05*float64(n.TDP)
			if score > bestScore {
				bestScore = score
				best = i
			}
		}
		if best >= 0 {
			out[t.ID] = nodes[best].ID
			e.mu.Lock()
			e.lastExplain[t.ID] = fmt.Sprintf("EnergyAware: chose node %s with score %.4f (free-capacity adjusted by TDP)", nodes[best].ID, bestScore)
			e.mu.Unlock()
		}
	}
	return out, nil, nil
}

func (e *EnergyAwareAlgo) ExplainDecision(taskID string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v, ok := e.lastExplain[taskID]; ok {
		return v
	}
	return "EnergyAware: prefer nodes with high free capacity and lower TDP"
}

// FairShareAlgo: balances between owners/projects
type FairShareAlgo struct {
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewFairShareAlgo(name string) *FairShareAlgo {
	return &FairShareAlgo{name: name, lastExplain: map[string]string{}}
}
func (f *FairShareAlgo) Name() string {
	if f.name == "" {
		return "fair-share"
	}
	return f.name
}

func (f *FairShareAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	ownerUsage := map[string]float64{}
	if telemetry != nil {
		if v, ok := telemetry["owner_usage"]; ok {
			// expected map[string]float64 but tolerate interface{}
			if m, ok := v.(map[string]float64); ok {
				ownerUsage = m
			} else if mm, ok := v.(map[string]any); ok {
				for k, vv := range mm {
					switch t := vv.(type) {
					case float64:
						ownerUsage[k] = t
					case int:
						ownerUsage[k] = float64(t)
					}
				}
			}
		}
	}
	for _, t := range tasks {
		req := bsonRequirementsFromTask(t)
		best := -1
		bestScore := math.Inf(-1)
		for i, n := range nodes {
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			ok := true
			for rt, amt := range req {
				if n.Resources[rt] < amt {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			usage := ownerUsage[t.Owner]
			score := 1.0 / (1.0 + usage)
			free := 0.0
			for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
				free += n.Resources[rt]
			}
			score += free * 0.001
			if score > bestScore {
				bestScore = score
				best = i
			}
		}
		if best >= 0 {
			out[t.ID] = nodes[best].ID
			f.mu.Lock()
			f.lastExplain[t.ID] = fmt.Sprintf("FairShare: assigned to node %s to balance owner %s (score %.4f)", nodes[best].ID, t.Owner, bestScore)
			f.mu.Unlock()
		}
	}
	return out, nil, nil
}

func (f *FairShareAlgo) ExplainDecision(taskID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.lastExplain[taskID]; ok {
		return v
	}
	return "FairShare: balance allocations across owners/projects"
}

// ThroughputAlgo: favor short-running tasks to maximize throughput
type ThroughputAlgo struct {
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewThroughputAlgo(name string) *ThroughputAlgo {
	return &ThroughputAlgo{name: name, lastExplain: map[string]string{}}
}
func (th *ThroughputAlgo) Name() string {
	if th.name == "" {
		return "throughput"
	}
	return th.name
}

func (th *ThroughputAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	sort.Slice(tasks, func(i, j int) bool {
		a := 1e9
		b := 1e9
		if v, ok := tasks[i].Payload["expected_runtime"]; ok {
			if f, ok := v.(float64); ok {
				a = f
			}
		}
		if v, ok := tasks[j].Payload["expected_runtime"]; ok {
			if f, ok := v.(float64); ok {
				b = f
			}
		}
		return a < b
	})
	for _, t := range tasks {
		req := bsonRequirementsFromTask(t)
		best := -1
		bestScore := math.Inf(-1)
		for i, n := range nodes {
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			ok := true
			for rt, amt := range req {
				if n.Resources[rt] < amt {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			free := 0.0
			for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
				free += n.Resources[rt]
			}
			score := free
			if score > bestScore {
				bestScore = score
				best = i
			}
		}
		if best >= 0 {
			out[t.ID] = nodes[best].ID
			th.mu.Lock()
			th.lastExplain[t.ID] = fmt.Sprintf("Throughput: assigned to node %s maximizing local free capacity (score %.4f)", nodes[best].ID, bestScore)
			th.mu.Unlock()
		}
	}
	return out, nil, nil
}

func (th *ThroughputAlgo) ExplainDecision(taskID string) string {
	th.mu.Lock()
	defer th.mu.Unlock()
	if v, ok := th.lastExplain[taskID]; ok {
		return v
	}
	return "Throughput: favor short tasks to maximize throughput"
}

// LearningAlgo stub: uses decision journal + KPIs to pick heuristics
type LearningAlgo struct {
	name   string
	memory map[string]any
	mu     sync.Mutex
	lastExplain map[string]string
}

func NewLearningAlgo(name string) *LearningAlgo { return &LearningAlgo{name: name, memory: map[string]any{}, lastExplain: map[string]string{}} }
func (la *LearningAlgo) Name() string {
	if la.name == "" {
		return "learning"
	}
	return la.name
}

func (la *LearningAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	var cpuUtil float64
	if telemetry != nil {
		if kpis, ok := telemetry["kpis"].(map[string]float64); ok {
			cpuUtil = kpis["utilization_cpu"]
		}
	}
	useEnergy := cpuUtil > 0.7
	if useEnergy {
		for _, t := range tasks {
			best := -1
			bestScore := math.Inf(-1)
			req := bsonRequirementsFromTask(t)
			for i, n := range nodes {
				if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
					continue
				}
				ok := true
				for rt, amt := range req {
					if n.Resources[rt] < amt {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				free := 0.0
				for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
					free += n.Resources[rt]
				}
				score := free - 0.05*float64(n.TDP)
				if score > bestScore {
					bestScore = score
					best = i
				}
			}
			if best >= 0 {
				out[t.ID] = nodes[best].ID
				la.mu.Lock()
				la.lastExplain[t.ID] = fmt.Sprintf("Learning(stub): selected energy-aware node %s (score %.4f) due to cpuUtil=%.2f", nodes[best].ID, bestScore, cpuUtil)
				la.mu.Unlock()
			}
		}
	} else {
		idx := 0
		for _, t := range tasks {
			for i := 0; i < len(nodes); i++ {
				n := nodes[(idx+i)%len(nodes)]
				if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
					continue
				}
				out[t.ID] = n.ID
				la.mu.Lock()
				la.lastExplain[t.ID] = fmt.Sprintf("Learning(stub): round-robin fallback chose %s", n.ID)
				la.mu.Unlock()
				idx = (idx + 1) % len(nodes)
				break
			}
		}
	}
	la.mu.Lock()
	la.memory["last_telemetry"] = telemetry
	la.mu.Unlock()
	return out, map[string]any{"policy": "learning-stub", "use_energy": useEnergy}, nil
}

func (la *LearningAlgo) ExplainDecision(taskID string) string {
	la.mu.Lock()
	defer la.mu.Unlock()
	if v, ok := la.lastExplain[taskID]; ok {
		return v
	}
	return fmt.Sprintf("LearningAlgo: heuristic decision (stub) - memory keys=%v", len(la.memory))
}

// DeadlineFirstAlgo: prioritizes imminent deadlines and balances priority
type DeadlineFirstAlgo struct {
	name        string
	mu          sync.Mutex
	lastExplain map[string]string
}

func NewDeadlineFirstAlgo(name string) *DeadlineFirstAlgo {
	return &DeadlineFirstAlgo{name: name, lastExplain: map[string]string{}}
}
func (d *DeadlineFirstAlgo) Name() string {
	if d.name == "" {
		return "deadline-first"
	}
	return d.name
}

func (d *DeadlineFirstAlgo) Schedule(tasks []*Task, nodes []*aggregation.ResourceNode, telemetry map[string]any) (map[string]string, map[string]any, error) {
	out := map[string]string{}
	if len(nodes) == 0 {
		return out, nil, errors.New("no nodes")
	}
	// sort by priority desc then deadline asc
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].Priority != tasks[j].Priority {
			return tasks[i].Priority > tasks[j].Priority
		}
		if tasks[i].Deadline.IsZero() && tasks[j].Deadline.IsZero() {
			return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
		}
		if tasks[i].Deadline.IsZero() {
			return false
		}
		if tasks[j].Deadline.IsZero() {
			return true
		}
		return tasks[i].Deadline.Before(tasks[j].Deadline)
	})
	for _, t := range tasks {
		req := bsonRequirementsFromTask(t)
		best := -1
		bestScore := math.Inf(-1)
		for i, n := range nodes {
			if !aggregationMatchesAffinityShim(n, aggregation.Reservation{Affinity: t.Affinity}) {
				continue
			}
			ok := true
			for rt, amt := range req {
				if n.Resources[rt] < amt {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			score := 0.0
			if t.Region != "" && n.Region == t.Region {
				score += 10.0
			}
			free := 0.0
			for _, rt := range []aggregation.ResourceType{aggregation.ResourceCPU, aggregation.ResourceGPU, aggregation.ResourceRAM} {
				free += n.Resources[rt]
			}
			score += free
			if !t.Deadline.IsZero() {
				rem := time.Until(t.Deadline).Seconds()
				if rem > 0 {
					score += 1.0 / (rem + 1.0)
				} else {
					score += 1000.0 // overdue tasks get top priority
				}
			}
			if score > bestScore {
				bestScore = score
				best = i
			}
		}
		if best >= 0 {
			out[t.ID] = nodes[best].ID
			d.mu.Lock()
			d.lastExplain[t.ID] = fmt.Sprintf("DeadlineFirst: chose node %s (score %.4f) for task with deadline %v", nodes[best].ID, bestScore, t.Deadline)
			d.mu.Unlock()
		}
	}
	return out, nil, nil
}

func (d *DeadlineFirstAlgo) ExplainDecision(taskID string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.lastExplain[taskID]; ok {
		return v
	}
	return "DeadlineFirst: prioritize by priority and deadline"
}

// -------------------- Helpers & utilities --------------------

// parseRequirementsFromPayload reads patterns from Task.Payload into map[ResourceType]float64
func parseRequirementsFromPayload(payload map[string]any) map[aggregation.ResourceType]float64 {
	out := map[aggregation.ResourceType]float64{}
	if payload == nil {
		return out
	}
	if v, ok := payload["requirements"]; ok {
		switch m := v.(type) {
		case map[string]float64:
			for k, vv := range m {
				out[aggregation.ResourceType(k)] = vv
			}
		case map[string]any:
			for k, vv := range m {
				switch t := vv.(type) {
				case float64:
					out[aggregation.ResourceType(k)] = t
				case int:
					out[aggregation.ResourceType(k)] = float64(t)
				}
			}
		}
		return out
	}
	if v, ok := payload["cpu"]; ok {
		switch t := v.(type) {
		case float64:
			out[aggregation.ResourceCPU] = t
		case int:
			out[aggregation.ResourceCPU] = float64(t)
		}
	}
	if v, ok := payload["gpu"]; ok {
		switch t := v.(type) {
		case float64:
			out[aggregation.ResourceGPU] = t
		case int:
			out[aggregation.ResourceGPU] = float64(t)
		}
	}
	if v, ok := payload["ram"]; ok {
		switch t := v.(type) {
		case float64:
			out[aggregation.ResourceRAM] = t
		case int:
			out[aggregation.ResourceRAM] = float64(t)
		}
	}
	return out
}

func bsonRequirementsFromTask(t *Task) map[aggregation.ResourceType]float64 {
	return parseRequirementsFromPayload(t.Payload)
}

// aggregationMatchesAffinityShim: re-implement affinity check to avoid depending on rp internals
func aggregationMatchesAffinityShim(node *aggregation.ResourceNode, r aggregation.Reservation) bool {
	if node == nil {
		return false
	}
	if len(r.Affinity) == 0 && len(r.AntiAffinity) == 0 {
		return true
	}
	if len(r.Affinity) > 0 {
		ok := false
		for _, a := range r.Affinity {
			if a == node.ID {
				ok = true
				break
			}
			parts := strings.SplitN(a, "=", 2)
			if len(parts) == 2 {
				if v, exists := node.Labels[parts[0]]; exists && v == parts[1] {
					ok = true
					break
				}
			}
		}
		if !ok {
			return false
		}
	}
	for _, a := range r.AntiAffinity {
		if a == node.ID {
			return false
		}
		parts := strings.SplitN(a, "=", 2)
		if len(parts) == 2 {
			if v, exists := node.Labels[parts[0]]; exists && v == parts[1] {
				return false
			}
		}
	}
	return true
}

// copy helpers
func copyMapString(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func copyMapAny(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func copyMapResources(in map[aggregation.ResourceType]float64) map[aggregation.ResourceType]float64 {
	if in == nil {
		return nil
	}
	out := make(map[aggregation.ResourceType]float64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// -------------------- Journal / KPIs helpers --------------------

func (s *AdvancedScheduler) recordJournal(e DecisionEntry) {
	if s.journal != nil {
		s.journal.Write(e)
	} else {
		s.mu.Lock()
		b, _ := json.Marshal(e)
		s.traces = append(s.traces, string(b))
		s.mu.Unlock()
	}
}

func (s *AdvancedScheduler) GetKPIs() SchedulerKPIs {
	return SchedulerKPIs{
		SuccessCount:      atomic.LoadUint64(&s.kpis.SuccessCount),
		FailureCount:      atomic.LoadUint64(&s.kpis.FailureCount),
		RequeueCount:      atomic.LoadUint64(&s.kpis.RequeueCount),
		AvgWaitMs:         s.kpis.AvgWaitMs,
		TotalScheduled:    atomic.LoadUint64(&s.kpis.TotalScheduled),
		AvgAllocationTime: s.kpis.AvgAllocationTime,
	}
}
  
// -------------------- OnSchedule listeners --------------------

func (s *AdvancedScheduler) RegisterOnSchedule(f func(map[string]string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onSchedule = append(s.onSchedule, f)
}

func (s *AdvancedScheduler) callOnScheduleListeners(dec map[string]string) {
	s.mu.Lock()
	list := append([]func(map[string]string){}, s.onSchedule...)
	s.mu.Unlock()
	for _, f := range list {
		go f(dec)
	}
}

// -------------------- ExposeFunctions --------------------

func (s *AdvancedScheduler) ExposeFunctions() map[string]any {
	return map[string]any{
		"add_task":               s.AddTask,
		"remove_task":            s.RemoveTask,
		"get_task":               s.GetTask,
		"list_tasks":             s.listTasks,
		"register_algorithm":     s.RegisterAlgorithm,
		"register_from_loader":   s.RegisterAlgorithmFromLoader,
		"set_active_algorithm":   s.SetActiveAlgorithm,
		"simulate_algorithm":     s.SimulateAlgorithm,
		"schedule":               s.Schedule,
		"start_loop":             s.StartLoop,
		"stop_loop":              s.StopLoop,
		"set_journal_path":       s.SetJournalPath,
		"set_policy_checker":     s.SetPolicyChecker,
		"set_algo_selector":      s.SetAlgoSelector,
		"set_fallback_order":     s.SetFallbackOrder,
		"get_kpis":               s.GetKPIs,
		"explain_decision":       func(taskID string) string { return s.explainDecision(taskID) },
		"list_algorithms":        s.listAlgorithms,
		"register_on_schedule":   s.RegisterOnSchedule,
	}
}

func (s *AdvancedScheduler) listAlgorithms() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.algos))
	for k := range s.algos {
		out = append(out, k)
	}
	return out
}

func (s *AdvancedScheduler) explainDecision(taskID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.explainMap[taskID]; ok {
		return v
	}
	if a, ok := s.algos[s.activeAlgo]; ok {
		return a.ExplainDecision(taskID)
	}
	return "no explanation available"
}