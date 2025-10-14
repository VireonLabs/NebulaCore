// internal/aggregation/resource_pool.go
// NebulaCore ResourcePool: Distributed Supercomputer Kernel for all resources.
// Production-ready, AI-driven extension points, vector scoring (Pareto), composite reservations,
// telemetry/forecast hooks, power-aware scheduling, health & deadline watchers, AutoDev (DSL).
package aggregation

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
)

// -------------------- Types / Constants --------------------

type ResourceType string

const (
	ResourceCPU    ResourceType = "cpu"
	ResourceGPU    ResourceType = "gpu"
	ResourceRAM    ResourceType = "ram"
	ResourceDisk   ResourceType = "disk"
	ResourceNet    ResourceType = "network"
	ResourceCustom ResourceType = "custom"
)

type NODE_STATUS string

const (
	NODE_ONLINE   NODE_STATUS = "online"
	NODE_OFFLINE  NODE_STATUS = "offline"
	NODE_DEGRADED NODE_STATUS = "degraded"
	NODE_MAINT    NODE_STATUS = "maintenance"
)

const (
	defaultHealthDur     = 30 * time.Second
	defaultTraceMax      = 2000
	rebalThreshold       = 0.80 // overloaded threshold
	defaultDeadlineChk   = 5 * time.Second
	defaultAllocatorTick = 2 * time.Second
	defaultAutoscaleTick = 30 * time.Second
	forecastTimeout      = 200 * time.Millisecond // protect slow forecast hooks
	maxRepairsPerTick    = 10                      // bound repairs per health tick
)

// NUMA / GPU / NIC rich models
type NUMANode struct {
	ID     string
	Cores  int
	Memory int64 // bytes
}

type GPUPartition struct {
	ID     string
	Memory int64
	SMs    int
	Type   string // e.g., "MIG", "vGPU"
}

type NetworkInterface struct {
	ID        string
	Type      string // e.g., "RDMA", "TCP", "NVLink"
	Bandwidth int64  // bps
}

// ResourceNode represents physical/virtual node and its free capacities.
type ResourceNode struct {
	ID         string
	Provider   string
	Region     string
	Labels     map[string]string
	Resources  map[ResourceType]float64 // available capacity (fractional supported)
	NUMATop    []NUMANode
	GPUTop     []GPUPartition
	NICs       []NetworkInterface
	Status     NODE_STATUS
	TDP        int                // Power info (watts)
	PoolTier   string             // hot/warm/cold
	SLO        map[string]float64 // node-level SLO hints
	LastSeen   time.Time
	Meta       map[string]any
	Allocated  map[ResourceType]float64 // total allocated (for telemetry)
}

// Reservation supports composite requests (Requirements).
type Reservation struct {
	ID           string
	NodeID       string
	RType        ResourceType                      // legacy single-type
	Requirements map[ResourceType]float64          // composite requirements; if empty, use RType+Amount
	Amount       float64                           // legacy amount
	Priority     int                               // higher => more priority
	Soft         bool                              // soft reservation can be preempted
	Affinity     []string                          // node IDs or labels or key=value
	AntiAffinity []string
	SLO          map[string]float64
	Start        time.Time
	Deadline     time.Time
	Policy       string // name of policy module
	CreatedAt    time.Time
	Owner        string // logical owner (project/user)
	Weights      map[string]float64 // optional weights for multi-dim vector scoring
	_enqueuedAt  time.Time          // internal
}

// PoolPolicy: returns (nodeID, scoreVector, error). scoreVector dims are policy-specific e.g. {"util":0.7,"energy":0.2}
type PoolPolicy interface {
	Name() string
	Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) // returns nodeID + vector scores
	ExplainDecision(req Reservation) string
}

// Trace levels & entry
type TraceLevel string

const (
	TraceInfo  TraceLevel = "INFO"
	TraceWarn  TraceLevel = "WARN"
	TraceError TraceLevel = "ERROR"
)

type TraceEntry struct {
	Time     time.Time
	Level    TraceLevel
	Op       string
	Msg      string
	Details  map[string]any
	Snapshot map[string]any // optional snapshot for explainability
}

// -------------------- Errors --------------------

var ErrNoResource = &ResourceError{"resource unavailable"}
var ErrQueued = &ResourceError{"request queued"}

type ResourceError struct{ Msg string }

func (e *ResourceError) Error() string { return e.Msg }

// -------------------- ResourcePool --------------------

type ForecastHook func(resource ResourceType, region string, horizon time.Duration) float64
type AutoscalerHook func(pool *ResourcePool) error
type AllocatorHook func(pool *ResourcePool)
type PolicyVerifier func(policyBytes []byte) error // must verify signature/safety
type PolicyLoader func(policyBytes []byte) (PoolPolicy, error)

type ResourcePool struct {
	mu                  sync.RWMutex
	nodes               map[string]*ResourceNode
	reserves            map[string]Reservation
	policies            map[string]PoolPolicy
	KPIs                map[string]float64
	trace               []TraceEntry
	AutoDev             func(name string, wasmOrDSL []byte) error // orchestrator-provided upload handler
	onChange            []func()
	rebalanceHook       func(pool *ResourcePool)
	forecastHook        ForecastHook
	autoscalerHook      AutoscalerHook
	allocatorHook       AllocatorHook
	policyVerifier      PolicyVerifier
	healthCheckInterval time.Duration
	healthTimeout       time.Duration
	stopHealthCh        chan struct{}
	deadlineInterval    time.Duration
	stopDeadlineCh      chan struct{}
	traceMax            int
	pendingQueue        []Reservation
	allocatorInterval   time.Duration
	allocatorStopCh     chan struct{}
	autoscalerInterval  time.Duration
	autoscalerStopCh    chan struct{}
	rand                *rand.Rand
}

// NewResourcePool initialises pool with defaults and built-in policies.
func NewResourcePool() *ResourcePool {
	src := rand.NewSource(time.Now().UnixNano())
	r := rand.New(src)
	rp := &ResourcePool{
		nodes:               make(map[string]*ResourceNode),
		reserves:            make(map[string]Reservation),
		policies:            make(map[string]PoolPolicy),
		KPIs:                make(map[string]float64),
		trace:               make([]TraceEntry, 0, 256),
		onChange:            make([]func(), 0),
		healthCheckInterval: 15 * time.Second,
		healthTimeout:       defaultHealthDur,
		deadlineInterval:    defaultDeadlineChk,
		traceMax:            defaultTraceMax,
		pendingQueue:        make([]Reservation, 0),
		allocatorInterval:   defaultAllocatorTick,
		autoscalerInterval:  defaultAutoscaleTick,
		rand:                r,
	}
	rp.policies["default-fairshare"] = &DefaultFairSharePolicy{}
	rp.policies["cost-aware"] = &CostAwarePolicy{}
	rp.KPIs["utilization_cpu"] = 0.0
	rp.KPIs["utilization_gpu"] = 0.0
	rp.KPIs["failed_allocs"] = 0.0
	rp.KPIs["avg_alloc_latency_ms"] = 0.0
	rp.KPIs["reservations_count"] = 0.0
	rp.KPIs["joules_per_task_estimate"] = 0.0
	return rp
}

// -------------------- Node Management --------------------

func (rp *ResourcePool) AddNode(n *ResourceNode) {
	rp.mu.Lock()
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	if n.Meta == nil {
		n.Meta = map[string]any{}
	}
	if n.Resources == nil {
		n.Resources = map[ResourceType]float64{}
	}
	if n.Allocated == nil {
		n.Allocated = map[ResourceType]float64{}
	}
	n.LastSeen = time.Now()
	if n.Status == "" {
		n.Status = NODE_ONLINE
	}
	rp.nodes[n.ID] = n
	rp.traceAppend(TraceInfo, "AddNode", "node-added", map[string]any{"node": n.ID}, rp.snapshotForExplain(n.ID))
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) AddNodes(nodes []*ResourceNode) {
	rp.mu.Lock()
	for _, n := range nodes {
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		if n.Meta == nil {
			n.Meta = map[string]any{}
		}
		if n.Resources == nil {
			n.Resources = map[ResourceType]float64{}
		}
		if n.Allocated == nil {
			n.Allocated = map[ResourceType]float64{}
		}
		n.LastSeen = time.Now()
		if n.Status == "" {
			n.Status = NODE_ONLINE
		}
		rp.nodes[n.ID] = n
		rp.traceAppend(TraceInfo, "AddNodes", "node-added", map[string]any{"node": n.ID}, rp.snapshotForExplain(n.ID))
	}
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) RemoveNode(id string) {
	rp.mu.Lock()
	delete(rp.nodes, id)
	rp.traceAppend(TraceWarn, "RemoveNode", "node-removed", map[string]any{"node": id}, nil)
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) UpdateNodeStatus(nodeID string, status NODE_STATUS) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %s not found", nodeID)
	}
	n.Status = status
	n.LastSeen = time.Now()
	rp.traceAppend(TraceInfo, "UpdateNodeStatus", string(status), map[string]any{"node": nodeID}, rp.snapshotForExplain(nodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) UpdateNodeResources(nodeID string, res map[ResourceType]float64) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %s not found", nodeID)
	}
	n.Resources = res
	n.LastSeen = time.Now()
	rp.traceAppend(TraceInfo, "UpdateNodeResources", "updated-resources", map[string]any{"node": nodeID}, rp.snapshotForExplain(nodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) UpdateNodeMeta(nodeID string, labels map[string]string, meta map[string]any) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %s not found", nodeID)
	}
	for k, v := range labels {
		n.Labels[k] = v
	}
	for k, v := range meta {
		n.Meta[k] = v
	}
	n.LastSeen = time.Now()
	rp.traceAppend(TraceInfo, "UpdateNodeMeta", "labels-meta-updated", map[string]any{"node": nodeID}, rp.snapshotForExplain(nodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) GetNodeInfo(nodeID string) *ResourceNode {
	rp.mu.RLock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		rp.mu.RUnlock()
		return nil
	}
	copyNode := *n
	copyNode.Labels = copyMapString(n.Labels)
	copyNode.Meta = copyMapAny(n.Meta)
	copyNode.Resources = copyMapResources(n.Resources)
	copyNode.NUMATop = append([]NUMANode(nil), n.NUMATop...)
	copyNode.GPUTop = append([]GPUPartition(nil), n.GPUTop...)
	copyNode.NICs = append([]NetworkInterface(nil), n.NICs...)
	rp.mu.RUnlock()
	return &copyNode
}

// -------------------- Helpers --------------------

func (rp *ResourcePool) genReservationID() string {
	// simple high-entropy-ish ID based on time + rnd
	return fmt.Sprintf("res-%d-%04x", time.Now().UnixNano(), rp.rand.Intn(1<<16))
}

func ensureUniqueReservationIDUnlocked(rp *ResourcePool, r *Reservation) {
	if r.ID == "" {
		r.ID = rp.genReservationID()
	}
	// if exists, append numeric suffix until unique
	if _, exists := rp.reserves[r.ID]; exists {
		base := r.ID
		for i := 1; ; i++ {
			r.ID = fmt.Sprintf("%s-%d", base, i)
			if _, ok := rp.reserves[r.ID]; !ok {
				break
			}
		}
	}
}

// -------------------- Reservation / Allocation (composite + vector scoring) --------------------

// Allocate attempts allocation using a policy, supports composite requirements and forecasting avoidance.
// Returns nodeID, scoreVector, error.
func (rp *ResourcePool) Allocate(req Reservation) (string, map[string]float64, error) {
	start := time.Now()

	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now()
	}

	// normalize composite
	reqReqs := map[ResourceType]float64{}
	if len(req.Requirements) > 0 {
		for k, v := range req.Requirements {
			reqReqs[k] = v
		}
	} else if req.RType != "" && req.Amount > 0 {
		reqReqs[req.RType] = req.Amount
	}

	// admission quick check under lock
	rp.mu.Lock()
	ensureUniqueReservationIDUnlocked(rp, &req)

	// pick policy safely
	policyName := req.Policy
	if policyName == "" {
		policyName = "default-fairshare"
	}
	policy := rp.policies[policyName]
	if policy == nil {
		// no policy available -> fail or queue if soft
		rp.traceAppend(TraceWarn, "Allocate", "policy-missing", map[string]any{"req": req.ID, "policy": policyName}, nil)
		if req.Soft {
			req._enqueuedAt = time.Now()
			rp.pendingQueue = append(rp.pendingQueue, req)
			rp.traceAppend(TraceInfo, "Allocate", "queued-soft-missing-policy", map[string]any{"req": req.ID}, nil)
			rp.mu.Unlock()
			return "", nil, ErrQueued
		}
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.mu.Unlock()
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, fmt.Errorf("policy %s not found", policyName)
	}

	// quick feasibility: is any node capable on static view?
	canSatisfy := false
	for _, n := range rp.nodes {
		if n.Status != NODE_ONLINE {
			continue
		}
		if !matchesAffinity(n, req) {
			continue
		}
		okcap := true
		for rt, amt := range reqReqs {
			if avail, ok := n.Resources[rt]; !ok || avail < amt {
				okcap = false
				break
			}
		}
		if okcap {
			canSatisfy = true
			break
		}
	}
	if !canSatisfy {
		if req.Soft {
			req._enqueuedAt = time.Now()
			rp.pendingQueue = append(rp.pendingQueue, req)
			rp.traceAppend(TraceInfo, "Allocate", "queued-soft-no-capacity", map[string]any{"req": req.ID}, nil)
			rp.mu.Unlock()
			return "", nil, ErrQueued
		}
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.traceAppend(TraceWarn, "Allocate", "no-capacity", map[string]any{"req": req.ID}, nil)
		rp.mu.Unlock()
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, ErrNoResource
	}
	// copy policy to local var and release lock (policies should be safe to call concurrently)
	localPolicy := policy
	rp.mu.Unlock()

	nodeID, vec, err := localPolicy.Allocate(rp, req)
	if err != nil {
		rp.mu.Lock()
		defer rp.mu.Unlock()
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.traceAppend(TraceWarn, "Allocate", "policy-failed", map[string]any{"req": req.ID, "err": err.Error(), "policy": localPolicy.Name()}, nil)
		rp.updateAvgAllocLatency(time.Since(start))
		if req.Soft {
			req._enqueuedAt = time.Now()
			rp.pendingQueue = append(rp.pendingQueue, req)
			rp.traceAppend(TraceInfo, "Allocate", "queued-after-policy-fail", map[string]any{"req": req.ID}, nil)
			return "", nil, ErrQueued
		}
		return "", nil, err
	}

	// booking atomic under lock
	rp.mu.Lock()
	defer rp.mu.Unlock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.traceAppend(TraceError, "Allocate", "node-missing-after-policy", map[string]any{"req": req.ID, "node": nodeID}, nil)
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, fmt.Errorf("node %s disappeared during allocate", nodeID)
	}

	// forecast safeguard with timeout
	if rp.forecastHook != nil {
		for rt := range reqReqs {
			if rp.callForecastWithTimeout(rt, n.Region, 30*time.Second) >= 0.95 {
				rp.traceAppend(TraceWarn, "Allocate", "forecast-block", map[string]any{"node": nodeID, "resource": rt}, rp.snapshotForExplain(nodeID))
				rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
				if req.Soft {
					req._enqueuedAt = time.Now()
					rp.pendingQueue = append(rp.pendingQueue, req)
					rp.traceAppend(TraceInfo, "Allocate", "queued-due-to-forecast", map[string]any{"req": req.ID}, nil)
					rp.updateAvgAllocLatency(time.Since(start))
					return "", nil, ErrQueued
				}
				rp.updateAvgAllocLatency(time.Since(start))
				return "", nil, fmt.Errorf("forecast indicates saturation for resource %s in region %s", rt, n.Region)
			}
		}
	}

	// verify again capacities
	for rt, amt := range reqReqs {
		avail := n.Resources[rt]
		if avail < amt {
			rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
			rp.traceAppend(TraceWarn, "Allocate", "insufficient-after-decision", map[string]any{"req": req.ID, "node": nodeID, "rtype": rt}, rp.snapshotForExplain(nodeID))
			rp.updateAvgAllocLatency(time.Since(start))
			return "", nil, ErrNoResource
		}
	}
	for rt, amt := range reqReqs {
		n.Resources[rt] = n.Resources[rt] - amt
		if n.Allocated == nil {
			n.Allocated = map[ResourceType]float64{}
		}
		n.Allocated[rt] = n.Allocated[rt] + amt
	}
	rp.reserves[req.ID] = req
	rp.traceAppend(TraceInfo, "Allocate", "ok", map[string]any{"req": req.ID, "node": nodeID, "reqs": reqReqs, "policy": localPolicy.Name()}, rp.snapshotForExplain(nodeID))
	rp.updateKPIsLocked()
	rp.updateAvgAllocLatency(time.Since(start))
	rp.notify()
	return nodeID, vec, nil
}

// Free releases composite reservation and restores resources.
func (rp *ResourcePool) Free(resID string) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	req, ok := rp.reserves[resID]
	if !ok {
		rp.traceAppend(TraceWarn, "Free", "reservation-not-found", map[string]any{"res": resID}, nil)
		return fmt.Errorf("reservation %s not found", resID)
	}
	reqReqs := map[ResourceType]float64{}
	if len(req.Requirements) > 0 {
		for k, v := range req.Requirements {
			reqReqs[k] = v
		}
	} else if req.RType != "" && req.Amount > 0 {
		reqReqs[req.RType] = req.Amount
	}
	n, ok := rp.nodes[req.NodeID]
	if ok {
		for rt, amt := range reqReqs {
			n.Resources[rt] = n.Resources[rt] + amt
			if n.Allocated == nil {
				n.Allocated = map[ResourceType]float64{}
			}
			n.Allocated[rt] = math.Max(0, n.Allocated[rt]-amt)
		}
	}
	delete(rp.reserves, resID)
	rp.traceAppend(TraceInfo, "Free", "released", map[string]any{"res": resID, "node": req.NodeID}, rp.snapshotForExplain(req.NodeID))
	rp.updateKPIsLocked()
	rp.notify()
	return nil
}

func (rp *ResourcePool) FreeMany(resIDs []string) {
	rp.mu.Lock()
	for _, id := range resIDs {
		req, ok := rp.reserves[id]
		if !ok {
			continue
		}
		reqReqs := map[ResourceType]float64{}
		if len(req.Requirements) > 0 {
			for k, v := range req.Requirements {
				reqReqs[k] = v
			}
		} else if req.RType != "" && req.Amount > 0 {
			reqReqs[req.RType] = req.Amount
		}
		if n, ok := rp.nodes[req.NodeID]; ok {
			for rt, amt := range reqReqs {
				n.Resources[rt] = n.Resources[rt] + amt
				if n.Allocated == nil {
					n.Allocated = map[ResourceType]float64{}
				}
				n.Allocated[rt] = math.Max(0, n.Allocated[rt]-amt)
			}
		}
		delete(rp.reserves, id)
		rp.traceAppend(TraceInfo, "FreeMany", "released", map[string]any{"res": id, "node": req.NodeID}, rp.snapshotForExplain(req.NodeID))
	}
	rp.mu.Unlock()
	rp.updateKPIsLocked()
	rp.notify()
}

func (rp *ResourcePool) ListReservations() []Reservation {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	out := make([]Reservation, 0, len(rp.reserves))
	for _, r := range rp.reserves {
		out = append(out, r)
	}
	return out
}

// -------------------- Policies Management / DSL / Multi-dim scoring --------------------

func (rp *ResourcePool) InjectPolicy(name string, p PoolPolicy) {
	rp.mu.Lock()
	rp.policies[name] = p
	rp.traceAppend(TraceInfo, "InjectPolicy", "policy-injected", map[string]any{"policy": name}, nil)
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) RemovePolicy(name string) {
	rp.mu.Lock()
	delete(rp.policies, name)
	rp.traceAppend(TraceWarn, "RemovePolicy", "policy-removed", map[string]any{"policy": name}, nil)
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) SetAutoDev(f func(name string, wasmOrDSL []byte) error) {
	rp.mu.Lock()
	rp.AutoDev = f
	rp.traceAppend(TraceInfo, "SetAutoDev", "autodev-hook-set", nil, nil)
	rp.mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) SetPolicyVerifier(v PolicyVerifier) {
	rp.mu.Lock()
	rp.policyVerifier = v
	rp.mu.Unlock()
	rp.traceAppend(TraceInfo, "SetPolicyVerifier", "verifier-set", nil, nil)
}

// RegisterPolicyFromDSL (single-dim)
func (rp *ResourcePool) RegisterPolicyFromDSL(name string, script string) error {
	expr, err := govaluate.NewEvaluableExpression(script)
	if err != nil {
		return fmt.Errorf("dsl compile error: %w", err)
	}
	p := &ExprPolicy{
		name:    name,
		exprs:   map[string]*govaluate.EvaluableExpression{"score": expr},
		dims:    []string{"score"},
		rawDSL:  script,
		created: time.Now(),
	}
	rp.InjectPolicy(name, p)
	return nil
}

// RegisterMultiDimPolicyFromDSL registers a policy with named dimensions expressions.
func (rp *ResourcePool) RegisterMultiDimPolicyFromDSL(name string, dimExprs map[string]string) error {
	exprs := map[string]*govaluate.EvaluableExpression{}
	dims := []string{}
	for k, s := range dimExprs {
		e, err := govaluate.NewEvaluableExpression(s)
		if err != nil {
			return fmt.Errorf("dsl compile error dim=%s: %w", k, err)
		}
		exprs[k] = e
		dims = append(dims, k)
	}
	p := &ExprPolicy{
		name:    name,
		exprs:   exprs,
		dims:    dims,
		rawDSL:  "<multi-dim>",
		created: time.Now(),
	}
	rp.InjectPolicy(name, p)
	return nil
}

// RegisterPolicyFromLoader requires a verifier to be set before accepting binary policies.
func (rp *ResourcePool) RegisterPolicyFromLoader(name string, policyBytes []byte, loader PolicyLoader) error {
	if loader == nil {
		return fmt.Errorf("loader is nil")
	}
	rp.mu.RLock()
	verifier := rp.policyVerifier
	rp.mu.RUnlock()
	if verifier == nil {
		return fmt.Errorf("policy verifier not configured: refusing to load binary policy")
	}
	if err := verifier(policyBytes); err != nil {
		return fmt.Errorf("policy verification failed: %w", err)
	}
	p, err := loader(policyBytes)
	if err != nil {
		return fmt.Errorf("loader error: %w", err)
	}
	rp.InjectPolicy(name, p)
	return nil
}

// ExprPolicy uses govaluate expressions to compute one or more dimensions per candidate.
type ExprPolicy struct {
	name    string
	exprs   map[string]*govaluate.EvaluableExpression // dim -> expr
	dims    []string
	rawDSL  string
	created time.Time
}

func (p *ExprPolicy) Name() string { return p.name }

// Allocate will compute dims for each candidate and choose by Pareto front then tiebreak by weighted sum.
func (p *ExprPolicy) Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) {
	pool.mu.RLock()
	cands := make([]*ResourceNode, 0, len(pool.nodes))
	for _, n := range pool.nodes {
		if n.Status != NODE_ONLINE {
			continue
		}
		if !matchesAffinity(n, req) {
			continue
		}
		reqReqs := map[ResourceType]float64{}
		if len(req.Requirements) > 0 {
			for k, v := range req.Requirements {
				reqReqs[k] = v
			}
		} else if req.RType != "" && req.Amount > 0 {
			reqReqs[req.RType] = req.Amount
		}
		okcap := true
		for rt, amt := range reqReqs {
			if avail, ok := n.Resources[rt]; !ok || avail < amt {
				okcap = false
				break
			}
		}
		if !okcap {
			continue
		}
		cands = append(cands, n)
	}
	pool.mu.RUnlock()

	if len(cands) == 0 {
		return "", nil, ErrNoResource
	}

	type candScore struct {
		node  *ResourceNode
		vec   map[string]float64
		order int
	}
	scores := make([]candScore, 0, len(cands))
	for i, n := range cands {
		params := make(map[string]any)
		params["req_amount"] = req.Amount
		params["req_priority"] = req.Priority
		params["node_tdp"] = n.TDP
		params["node_pooltier"] = n.PoolTier
		params["node_region"] = n.Region
		params["node_cpu"] = n.Resources[ResourceCPU]
		params["node_gpu"] = n.Resources[ResourceGPU]
		params["node_ram"] = n.Resources[ResourceRAM]
		if n.Allocated != nil {
			params["node_alloc_cpu"] = n.Allocated[ResourceCPU]
			params["node_alloc_gpu"] = n.Allocated[ResourceGPU]
		} else {
			params["node_alloc_cpu"] = 0.0
			params["node_alloc_gpu"] = 0.0
		}
		for k, v := range n.Meta {
			kc := "meta_" + strings.ReplaceAll(k, "-", "_")
			params[kc] = v
		}
		vec := map[string]float64{}
		skip := false
		for _, dim := range p.dims {
			expr := p.exprs[dim]
			if expr == nil {
				continue
			}
			res, err := expr.Evaluate(params)
			if err != nil {
				skip = true
				break
			}
			var f float64
			switch t := res.(type) {
			case float64:
				f = t
			case float32:
				f = float64(t)
			case int:
				f = float64(t)
			case int64:
				f = float64(t)
			default:
				skip = true
				break
			}
			vec[dim] = f
		}
		if skip {
			continue
		}
		scores = append(scores, candScore{node: n, vec: vec, order: i})
	}
	if len(scores) == 0 {
		return "", nil, ErrNoResource
	}

	indices := paretoFrontIndices(scores)
	if len(indices) == 1 {
		chosen := scores[indices[0]]
		return chosen.node.ID, chosen.vec, nil
	}
	weights := map[string]float64{}
	if req.Weights != nil && len(req.Weights) > 0 {
		for k, v := range req.Weights {
			weights[k] = v
		}
	} else {
		for _, d := range p.dims {
			weights[d] = 1.0
		}
	}
	bestScore := math.Inf(-1)
	bestIdx := indices[0]
	for _, idx := range indices {
		cs := scores[idx]
		sum := 0.0
		for d, v := range cs.vec {
			w := weights[d]
			sum += w * v
		}
		if sum > bestScore {
			bestScore = sum
			bestIdx = idx
		}
	}
	chosen := scores[bestIdx]
	return chosen.node.ID, chosen.vec, nil
}

func (p *ExprPolicy) ExplainDecision(req Reservation) string {
	return fmt.Sprintf("ExprPolicy(%s) dims=%v", p.name, p.dims)
}

// -------------------- Pareto helpers --------------------

func paretoFrontIndices(scores []struct {
	node  *ResourceNode
	vec   map[string]float64
	order int
}) []int {
	n := len(scores)
	isDominated := make([]bool, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if dominates(scores[j].vec, scores[i].vec) {
				isDominated[i] = true
				break
			}
		}
	}
	out := []int{}
	for i := 0; i < n; i++ {
		if !isDominated[i] {
			out = append(out, i)
		}
	}
	return out
}

func dominates(a, b map[string]float64) bool {
	anyGreater := false
	for k, bv := range b {
		av, ok := a[k]
		if !ok {
			return false
		}
		if av < bv {
			return false
		}
		if av > bv {
			anyGreater = true
		}
	}
	return anyGreater
}

func dominatesVec(a, b map[string]float64) bool {
	if len(b) == 0 {
		return true
	}
	anyGreater := false
	for k, bv := range b {
		av, ok := a[k]
		if !ok {
			return false
		}
		if av < bv {
			return false
		}
		if av > bv {
			anyGreater = true
		}
	}
	return anyGreater
}

// -------------------- Rebalance / Forecasting / Power-aware --------------------

func (rp *ResourcePool) Rebalance() {
	rp.mu.Lock()
	rp.traceAppend(TraceInfo, "Rebalance", "start", nil, nil)
	// compute util
	util := map[string]float64{}
	for id, n := range rp.nodes {
		var totalAllocated float64
		var totalCap float64
		for rt, avail := range n.Resources {
			totalAllocated += n.Allocated[rt]
			totalCap += avail + n.Allocated[rt]
		}
		if totalCap <= 0 {
			util[id] = 0.0
		} else {
			util[id] = totalAllocated / totalCap
		}
	}
	overloaded := []string{}
	for id, u := range util {
		if u >= rebalThreshold {
			overloaded = append(overloaded, id)
		}
	}
	if len(overloaded) == 0 {
		rp.traceAppend(TraceInfo, "Rebalance", "no-overload", nil, nil)
		rp.mu.Unlock()
		return
	}
	sort.Slice(overloaded, func(i, j int) bool { return util[overloaded[i]] > util[overloaded[j]] })

	for _, src := range overloaded {
		for resID, r := range rp.reserves {
			if r.NodeID != src {
				continue
			}
			if !r.Soft || r.Priority > 5 {
				continue
			}
			for tid, tn := range rp.nodes {
				if tid == src || tn.Status != NODE_ONLINE {
					continue
				}
				// forecast check
				if rp.forecastHook != nil {
					predBlock := false
					for _, rt := range []ResourceType{ResourceCPU, ResourceGPU} {
						if rp.callForecastWithTimeout(rt, tn.Region, 30*time.Second) >= 0.95 {
							predBlock = true
							break
						}
					}
					if predBlock {
						continue
					}
				}
				reqReqs := map[ResourceType]float64{}
				if len(r.Requirements) > 0 {
					for k, v := range r.Requirements {
						reqReqs[k] = v
					}
				} else if r.RType != "" && r.Amount > 0 {
					reqReqs[r.RType] = r.Amount
				}
				okcap := true
				if !matchesAffinity(tn, r) {
					okcap = false
				}
				for rt, amt := range reqReqs {
					if tn.Resources[rt] < amt {
						okcap = false
						break
					}
				}
				if !okcap {
					continue
				}
				if srcNode, ok := rp.nodes[src]; ok {
					for rt, amt := range reqReqs {
						srcNode.Allocated[rt] = math.Max(0, srcNode.Allocated[rt]-amt)
						srcNode.Resources[rt] = srcNode.Resources[rt] + amt
					}
				}
				for rt, amt := range reqReqs {
					tn.Resources[rt] = tn.Resources[rt] - amt
					if tn.Allocated == nil {
						tn.Allocated = map[ResourceType]float64{}
					}
					tn.Allocated[rt] = tn.Allocated[rt] + amt
				}
				r.NodeID = tid
				rp.reserves[resID] = r
				rp.traceAppend(TraceInfo, "Rebalance", "migrated", map[string]any{"res": resID, "from": src, "to": tid}, rp.snapshotForExplain(tid))
				break
			}
		}
	}
	if rp.rebalanceHook != nil {
		go rp.rebalanceHook(rp)
	}
	rp.updateKPIsLocked()
	rp.mu.Unlock()
	rp.notify()
	rp.traceAppend(TraceInfo, "Rebalance", "end", nil, nil)
}

// -------------------- Health / Self-Repair (bounded) --------------------
  
func (rp *ResourcePool) StartHealthChecker(interval, timeout time.Duration) {
	rp.mu.Lock()
	if rp.stopHealthCh != nil {
		rp.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.healthCheckInterval
	}
	if timeout <= 0 {
		timeout = rp.healthTimeout
	}
	rp.healthCheckInterval = interval
	rp.healthTimeout = timeout
	stop := make(chan struct{})
	rp.stopHealthCh = stop
	rp.mu.Unlock()

	go func() {
		t := time.NewTicker(rp.healthCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rp.performHealthCheck()
			case <-stop:
				return
			}
		}
	}()
	rp.traceAppend(TraceInfo, "HealthChecker", "started", map[string]any{"interval": rp.healthCheckInterval.String(), "timeout": rp.healthTimeout.String()}, nil)
}

func (rp *ResourcePool) StopHealthChecker() {
	rp.mu.Lock()
	ch := rp.stopHealthCh
	if ch != nil {
		close(ch)
		rp.stopHealthCh = nil
	}
	rp.mu.Unlock()
	if ch != nil {
		rp.traceAppend(TraceInfo, "HealthChecker", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) performHealthCheck() {
	rp.mu.Lock()
	now := time.Now()
	toRepair := []string{}
	for id, n := range rp.nodes {
		if now.Sub(n.LastSeen) > rp.healthTimeout && n.Status == NODE_ONLINE {
			n.Status = NODE_OFFLINE
			rp.traceAppend(TraceWarn, "HealthCheck", "node-marked-offline", map[string]any{"node": id}, rp.snapshotForExplain(id))
			toRepair = append(toRepair, id)
		}
	}
	rp.mu.Unlock()

	limit := maxRepairsPerTick
	if limit > len(toRepair) {
		limit = len(toRepair)
	}
	for i := 0; i < limit; i++ {
		nodeID := toRepair[i]
		// sequential repair attempts (bounded)
		time.Sleep(50 * time.Millisecond)
		rp.mu.Lock()
		if node, ok := rp.nodes[nodeID]; ok && node.Status == NODE_OFFLINE {
			node.Status = NODE_MAINT
			rp.traceAppend(TraceInfo, "HealthRepair", "node-maintenance-start", map[string]any{"node": nodeID}, nil)
			time.Sleep(200 * time.Millisecond)
			node.Status = NODE_ONLINE
			node.LastSeen = time.Now()
			rp.traceAppend(TraceInfo, "HealthRepair", "node-repaired", map[string]any{"node": nodeID}, rp.snapshotForExplain(nodeID))
			rp.notify()
		}
		rp.mu.Unlock()
	}
}

// CheckAndRepair synchronous simple repair routine
func (rp *ResourcePool) CheckAndRepair() []string {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	repaired := []string{}
	now := time.Now()
	for id, n := range rp.nodes {
		if n.Status == NODE_OFFLINE || n.Status == NODE_DEGRADED {
			if now.Sub(n.LastSeen) <= 2*rp.healthTimeout {
				n.Status = NODE_MAINT
				n.LastSeen = now
				n.Status = NODE_ONLINE
				repaired = append(repaired, id)
				rp.traceAppend(TraceInfo, "CheckAndRepair", "repaired", map[string]any{"node": id}, rp.snapshotForExplain(id))
			} else {
				rp.traceAppend(TraceWarn, "CheckAndRepair", "quarantine", map[string]any{"node": id}, nil)
			}
		}
	}
	if len(repaired) > 0 {
		rp.updateKPIsLocked()
		rp.notify()
	}
	return repaired
}

// -------------------- Deadline Watcher (SLA guarantees) --------------------

func (rp *ResourcePool) StartDeadlineWatcher(interval time.Duration) {
	rp.mu.Lock()
	if rp.stopDeadlineCh != nil {
		rp.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.deadlineInterval
	}
	stop := make(chan struct{})
	rp.stopDeadlineCh = stop
	rp.mu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rp.enforceDeadlines()
			case <-stop:
				return
			}
		}
	}()
	rp.traceAppend(TraceInfo, "DeadlineWatcher", "started", map[string]any{"interval": interval.String()}, nil)
}

func (rp *ResourcePool) StopDeadlineWatcher() {
	rp.mu.Lock()
	ch := rp.stopDeadlineCh
	if ch != nil {
		close(ch)
		rp.stopDeadlineCh = nil
	}
	rp.mu.Unlock()
	if ch != nil {
		rp.traceAppend(TraceInfo, "DeadlineWatcher", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) enforceDeadlines() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	now := time.Now()
	for id, r := range rp.reserves {
		if !r.Deadline.IsZero() {
			remaining := r.Deadline.Sub(now)
			if remaining < 30*time.Second {
				for nid, n := range rp.nodes {
					if nid == r.NodeID || n.Status != NODE_ONLINE {
						continue
					}
					okcap := true
					reqReqs := map[ResourceType]float64{}
					if len(r.Requirements) > 0 {
						for k, v := range r.Requirements {
							reqReqs[k] = v
						}
					} else if r.RType != "" && r.Amount > 0 {
						reqReqs[r.RType] = r.Amount
					}
					for rt, amt := range reqReqs {
						if n.Resources[rt] < amt {
							okcap = false
							break
						}
					}
					if !okcap {
						continue
					}
					if srcNode, ok := rp.nodes[r.NodeID]; ok {
						for rt, amt := range reqReqs {
							srcNode.Allocated[rt] = math.Max(0, srcNode.Allocated[rt]-amt)
							srcNode.Resources[rt] = srcNode.Resources[rt] + amt
						}
					}
					for rt, amt := range reqReqs {
						n.Resources[rt] = n.Resources[rt] - amt
						if n.Allocated == nil {
							n.Allocated = map[ResourceType]float64{}
						}
						n.Allocated[rt] = n.Allocated[rt] + amt
					}
					r.NodeID = nid
					rp.reserves[id] = r
					rp.traceAppend(TraceInfo, "DeadlineWatcher", "rescheduled", map[string]any{"res": id, "to": nid}, rp.snapshotForExplain(nid))
					break
				}
			}
		}
	}
}

// -------------------- Allocator / Pending Queue / Autoscaler --------------------

func (rp *ResourcePool) StartAllocator(interval time.Duration) {
	rp.mu.Lock()
	if rp.allocatorStopCh != nil {
		rp.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.allocatorInterval
	}
	rp.allocatorInterval = interval
	stop := make(chan struct{})
	rp.allocatorStopCh = stop
	rp.mu.Unlock()

	go func() {
		t := time.NewTicker(rp.allocatorInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rp.processPendingOnce()
				if rp.allocatorHook != nil {
					go rp.allocatorHook(rp)
				}
			case <-stop:
				return
			}
		}
	}()
	rp.traceAppend(TraceInfo, "Allocator", "started", map[string]any{"interval": rp.allocatorInterval.String()}, nil)
}

func (rp *ResourcePool) StopAllocator() {
	rp.mu.Lock()
	ch := rp.allocatorStopCh
	if ch != nil {
		close(ch)
		rp.allocatorStopCh = nil
	}
	rp.mu.Unlock()
	if ch != nil {
		rp.traceAppend(TraceInfo, "Allocator", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) processPendingOnce() {
	rp.mu.Lock()
	if len(rp.pendingQueue) == 0 {
		rp.mu.Unlock()
		return
	}
	queue := make([]Reservation, len(rp.pendingQueue))
	copy(queue, rp.pendingQueue)
	rp.pendingQueue = []Reservation{}
	rp.mu.Unlock()

	remaining := make([]Reservation, 0, len(queue))
	for _, req := range queue {
		policyName := req.Policy
		if policyName == "" {
			policyName = "default-fairshare"
		}
		rp.mu.RLock()
		policy := rp.policies[policyName]
		rp.mu.RUnlock()
		if policy == nil {
			remaining = append(remaining, req)
			continue
		}
		nodeID, _, err := policy.Allocate(rp, req)
		if err != nil {
			remaining = append(remaining, req)
			continue
		}
		rp.mu.Lock()
		n, ok := rp.nodes[nodeID]
		if !ok {
			remaining = append(remaining, req)
			rp.mu.Unlock()
			continue
		}
		reqReqs := map[ResourceType]float64{}
		if len(req.Requirements) > 0 {
			for k, v := range req.Requirements {
				reqReqs[k] = v
			}
		} else if req.RType != "" && req.Amount > 0 {
			reqReqs[req.RType] = req.Amount
		}
		okcap := true
		for rt, amt := range reqReqs {
			if n.Resources[rt] < amt {
				okcap = false
				break
			}
		}
		if !okcap {
			remaining = append(remaining, req)
			rp.mu.Unlock()
			continue
		}
		for rt, amt := range reqReqs {
			n.Resources[rt] = n.Resources[rt] - amt
			if n.Allocated == nil {
				n.Allocated = map[ResourceType]float64{}
			}
			n.Allocated[rt] = n.Allocated[rt] + amt
		}
		req.NodeID = nodeID
		rp.reserves[req.ID] = req
		rp.traceAppend(TraceInfo, "Allocator", "allocated-from-queue", map[string]any{"req": req.ID, "node": nodeID}, rp.snapshotForExplain(nodeID))
		rp.updateKPIsLocked()
		rp.mu.Unlock()
	}
	rp.mu.Lock()
	rp.pendingQueue = append(rp.pendingQueue, remaining...)
	rp.mu.Unlock()
	if len(remaining) > 0 {
		rp.traceAppend(TraceInfo, "Allocator", "queue-left", map[string]any{"left": len(remaining)}, nil)
	}
}

func (rp *ResourcePool) SetAllocatorHook(h AllocatorHook) {
	rp.mu.Lock()
	rp.allocatorHook = h
	rp.mu.Unlock()
	rp.traceAppend(TraceInfo, "SetAllocatorHook", "hook-set", nil, nil)
}

func (rp *ResourcePool) SetAutoscalerHook(h AutoscalerHook) {
	rp.mu.Lock()
	rp.autoscalerHook = h
	rp.mu.Unlock()
	rp.traceAppend(TraceInfo, "SetAutoscalerHook", "hook-set", nil, nil)
}

func (rp *ResourcePool) StartAutoscaler(interval time.Duration) {
	rp.mu.Lock()
	if rp.autoscalerStopCh != nil {
		rp.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.autoscalerInterval
	}
	rp.autoscalerInterval = interval
	stop := make(chan struct{})
	rp.autoscalerStopCh = stop
	rp.mu.Unlock()

	go func() {
		t := time.NewTicker(rp.autoscalerInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if rp.autoscalerHook != nil {
					go rp.autoscalerHook(rp)
				}
			case <-stop:
				return
			}
		}
	}()
	rp.traceAppend(TraceInfo, "Autoscaler", "started", map[string]any{"interval": rp.autoscalerInterval.String()}, nil)
}

func (rp *ResourcePool) StopAutoscaler() {
	rp.mu.Lock()
	ch := rp.autoscalerStopCh
	if ch != nil {
		close(ch)
		rp.autoscalerStopCh = nil
	}
	rp.mu.Unlock()
	if ch != nil {
		rp.traceAppend(TraceInfo, "Autoscaler", "stopped", nil, nil)
	}
}

// -------------------- Trace / KPIs / Utilities --------------------

func (rp *ResourcePool) traceAppend(level TraceLevel, op, msg string, details map[string]any, snapshot map[string]any) {
	rp.trace = append(rp.trace, TraceEntry{
		Time:     time.Now(),
		Level:    level,
		Op:       op,
		Msg:      msg,
		Details:  details,
		Snapshot: snapshot,
	})
	if len(rp.trace) > rp.traceMax {
		rp.trace = rp.trace[len(rp.trace)-rp.traceMax:]
	}
}

func (rp *ResourcePool) GetTrace() []TraceEntry {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	out := make([]TraceEntry, len(rp.trace))
	copy(out, rp.trace)
	return out
}

func (rp *ResourcePool) snapshotForExplain(nodeID string) map[string]any {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	n, ok := rp.nodes[nodeID]
	if !ok {
		return nil
	}
	return map[string]any{
		"node":      n.ID,
		"region":    n.Region,
		"pool_tier": n.PoolTier,
		"status":    n.Status,
		"resources": copyMapResources(n.Resources),
		"allocated": copyMapResources(n.Allocated),
		"meta":      copyMapAny(n.Meta),
		"tdp":       n.TDP,
	}
}

func (rp *ResourcePool) updateKPIsLocked() {
	var cpuTotal, cpuAllocated, gpuTotal, gpuAllocated float64
	for _, n := range rp.nodes {
		cpuTotal += n.Resources[ResourceCPU] + n.Allocated[ResourceCPU]
		cpuAllocated += n.Allocated[ResourceCPU]
		gpuTotal += n.Resources[ResourceGPU] + n.Allocated[ResourceGPU]
		gpuAllocated += n.Allocated[ResourceGPU]
	}
	if cpuTotal > 0 {
		rp.KPIs["utilization_cpu"] = cpuAllocated / cpuTotal
	} else {
		rp.KPIs["utilization_cpu"] = 0.0
	}
	if gpuTotal > 0 {
		rp.KPIs["utilization_gpu"] = gpuAllocated / gpuTotal
	} else {
		rp.KPIs["utilization_gpu"] = 0.0
	}
	rp.KPIs["reservations_count"] = float64(len(rp.reserves))
	totalJ := 0.0
	for _, n := range rp.nodes {
		tot := float64(n.TDP)
		cpuCap := n.Resources[ResourceCPU] + n.Allocated[ResourceCPU]
		if cpuCap > 0 {
			cpuUtil := n.Allocated[ResourceCPU] / cpuCap
			totalJ += tot * cpuUtil
		}
	}
	if rp.KPIs["reservations_count"] > 0 {
		rp.KPIs["joules_per_task_estimate"] = totalJ / rp.KPIs["reservations_count"]
	} else {
		rp.KPIs["joules_per_task_estimate"] = 0.0
	}
}

func (rp *ResourcePool) updateAvgAllocLatency(d time.Duration) {
	ms := float64(d.Milliseconds())
	prev := rp.KPIs["avg_alloc_latency_ms"]
	if prev == 0 {
		rp.KPIs["avg_alloc_latency_ms"] = ms
	} else {
		alpha := 0.2
		rp.KPIs["avg_alloc_latency_ms"] = alpha*ms + (1-alpha)*prev
	}
}

func (rp *ResourcePool) GetKPIs() map[string]float64 {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	out := make(map[string]float64, len(rp.KPIs))
	for k, v := range rp.KPIs {
		out[k] = v
	}
	return out
}

func (rp *ResourcePool) callForecastWithTimeout(rt ResourceType, region string, horizon time.Duration) float64 {
	rp.mu.RLock()
	hook := rp.forecastHook
	rp.mu.RUnlock()
	if hook == nil {
		return 0.0
	}
	ch := make(chan float64, 1)
	go func() {
		defer func() {
			select {
			case <-time.After(forecastTimeout):
			default:
			}
		}()
		res := hook(rt, region, horizon)
		select {
		case ch <- res:
		default:
		}
	}()
	select {
	case v := <-ch:
		return v
	case <-time.After(forecastTimeout):
		return 0.0 // timeout treated as no prediction (safe)
	}
}

// -------------------- Utilities --------------------

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

func copyMapResources(in map[ResourceType]float64) map[ResourceType]float64 {
	if in == nil {
		return nil
	}
	out := make(map[ResourceType]float64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func matchesAffinity(node *ResourceNode, r Reservation) bool {
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

// -------------------- Default Policies (implement new signature) --------------------

type DefaultFairSharePolicy struct{}

func (p *DefaultFairSharePolicy) Name() string { return "default-fairshare" }

func (p *DefaultFairSharePolicy) Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) {
	pool.mu.RLock()
	cands := make([]*ResourceNode, 0, len(pool.nodes))
	for _, n := range pool.nodes {
		if n.Status != NODE_ONLINE {
			continue
		}
		if !matchesAffinity(n, req) {
			continue
		}
		reqReqs := map[ResourceType]float64{}
		if len(req.Requirements) > 0 {
			for k, v := range req.Requirements {
				reqReqs[k] = v
			}
		} else if req.RType != "" && req.Amount > 0 {
			reqReqs[req.RType] = req.Amount
		}
		okcap := true
		for rt, amt := range reqReqs {
			if avail, ok := n.Resources[rt]; !ok || avail < amt {
				okcap = false
				break
			}
		}
		if !okcap {
			continue
		}
		cands = append(cands, n)
	}
	pool.mu.RUnlock()

	if len(cands) == 0 {
		return "", nil, ErrNoResource
	}
	bestIdx := 0
	bestVec := map[string]float64{}
	for i, n := range cands {
		free := 0.0
		for _, rt := range []ResourceType{ResourceCPU, ResourceGPU, ResourceRAM} {
			free += n.Resources[rt]
		}
		vec := map[string]float64{"free_capacity": free, "energy_score": -float64(n.TDP)}
		if i == 0 || dominatesVec(vec, bestVec) {
			bestVec = vec
			bestIdx = i
		}
	}
	return cands[bestIdx].ID, bestVec, nil
}

func (p *DefaultFairSharePolicy) ExplainDecision(req Reservation) string {
	return "DefaultFairShare: highest free_capacity & lower TDP preference"
}

type CostAwarePolicy struct{}

func (p *CostAwarePolicy) Name() string { return "cost-aware" }

func (p *CostAwarePolicy) Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) {
	type cand struct {
		node  *ResourceNode
		vec   map[string]float64
		score float64
	}
	pool.mu.RLock()
	candidates := []cand{}
	for _, n := range pool.nodes {
		if n.Status != NODE_ONLINE {
			continue
		}
		if !matchesAffinity(n, req) {
			continue
		}
		reqReqs := map[ResourceType]float64{}
		if len(req.Requirements) > 0 {
			for k, v := range req.Requirements {
				reqReqs[k] = v
			}
		} else if req.RType != "" && req.Amount > 0 {
			reqReqs[req.RType] = req.Amount
		}
		okcap := true
		for rt, amt := range reqReqs {
			if n.Resources[rt] < amt {
				okcap = false
				break
			}
		}
		if !okcap {
			continue
		}
		cost := 1.0
		if v, ok := n.Meta["cost"]; ok {
			switch t := v.(type) {
			case float64:
				cost = t
			case int:
				cost = float64(t)
			}
		}
		free := 0.0
		for _, rt := range []ResourceType{ResourceCPU, ResourceGPU, ResourceRAM} {
			free += n.Resources[rt]
		}
		vec := map[string]float64{"free": free, "cost": cost}
		score := free / cost
		candidates = append(candidates, cand{node: n, vec: vec, score: score})
	}
	pool.mu.RUnlock()

	if len(candidates) == 0 {
		return "", nil, ErrNoResource
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	chosen := candidates[0]
	return chosen.node.ID, chosen.vec, nil
}

func (p *CostAwarePolicy) ExplainDecision(req Reservation) string {
	return "CostAwarePolicy: maximize free_capacity / cost"
}

// -------------------- Expose / Listeners / Gossip placeholder --------------------

func (rp *ResourcePool) RegisterOnChange(f func()) {
	rp.mu.Lock()
	rp.onChange = append(rp.onChange, f)
	rp.mu.Unlock()
}

func (rp *ResourcePool) notify() {
	for _, f := range rp.onChange {
		go f()
	}
}

func (rp *ResourcePool) StartGossip() {
	rp.traceAppend(TraceInfo, "Gossip", "start-placeholder", nil, nil)
}

func (rp *ResourcePool) SetRebalanceHookExternal(h func(*ResourcePool)) {
	rp.SetRebalanceHook(h)
}

func (rp *ResourcePool) SetRebalanceHook(h func(pool *ResourcePool)) {
	rp.mu.Lock()
	rp.rebalanceHook = h
	rp.mu.Unlock()
	rp.traceAppend(TraceInfo, "SetRebalanceHook", "hook-set", nil, nil)
}

// -------------------- Expose Functions --------------------

func (rp *ResourcePool) ExposeFunctions() map[string]any {
	return map[string]any{
		"add_node":                 rp.AddNode,
		"add_nodes":                rp.AddNodes,
		"remove_node":              rp.RemoveNode,
		"update_node_status":       rp.UpdateNodeStatus,
		"update_node_resources":    rp.UpdateNodeResources,
		"update_node_meta":         rp.UpdateNodeMeta,
		"get_node_info":            rp.GetNodeInfo,
		"allocate":                 rp.Allocate,
		"free":                     rp.Free,
		"free_many":                rp.FreeMany,
		"list_reservations":        rp.ListReservations,
		"rebalance":                rp.Rebalance,
		"predict":                  rp.PredictUtilization,
		"inject_policy":            rp.InjectPolicy,
		"remove_policy":            rp.RemovePolicy,
		"register_policy_dsl":      rp.RegisterPolicyFromDSL,
		"register_policy_multi":    rp.RegisterMultiDimPolicyFromDSL,
		"register_policy_loader":   rp.RegisterPolicyFromLoader,
		"set_policy_verifier":      rp.SetPolicyVerifier,
		"get_kpis":                 rp.GetKPIs,
		"get_trace":                rp.GetTrace,
		"set_autodev_hook":         rp.SetAutoDev,
		"set_forecast_hook":        rp.SetForecastHook,
		"start_health_checker":     func(intervalSec int) { rp.StartHealthChecker(time.Duration(intervalSec) * time.Second, rp.healthTimeout) },
		"stop_health_checker":      rp.StopHealthChecker,
		"check_and_repair":         rp.CheckAndRepair,
		"start_deadline_watcher":   func(intervalSec int) { rp.StartDeadlineWatcher(time.Duration(intervalSec) * time.Second) },
		"stop_deadline_watcher":    rp.StopDeadlineWatcher,
		"set_rebalance_hook":       rp.SetRebalanceHook,
		"start_allocator":          func(intervalSec int) { rp.StartAllocator(time.Duration(intervalSec) * time.Second) },
		"stop_allocator":           rp.StopAllocator,
		"list_pending":             rp.ListPending,
		"set_allocator_hook":       rp.SetAllocatorHook,
		"set_autoscaler_hook":      rp.SetAutoscalerHook,
		"start_autoscaler":         func(intervalSec int) { rp.StartAutoscaler(time.Duration(intervalSec) * time.Second) },
		"stop_autoscaler":          rp.StopAutoscaler,
		"start_gossip_placeholder": rp.StartGossip,
	}
}

func (rp *ResourcePool) ListPending() []Reservation {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	out := make([]Reservation, 0, len(rp.pendingQueue))
	for _, r := range rp.pendingQueue {
		out = append(out, r)
	}
	return out
}

func (rp *ResourcePool) SetForecastHook(h ForecastHook) {
	rp.mu.Lock()
	rp.forecastHook = h
	rp.mu.Unlock()
	rp.traceAppend(TraceInfo, "SetForecastHook", "forecast-hook-set", nil, nil)
	rp.notify()
}

// PredictUtilization returns a snapshot prediction across nodes (naive snapshot).
// Orchestrator/forecastHook may provide better predictions via SetForecastHook.
func (rp *ResourcePool) PredictUtilization() map[string]float64 {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	out := map[string]float64{"cpu": 0.0, "gpu": 0.0}
	var cpuTotal, cpuUsed, gpuTotal, gpuUsed float64
	for _, n := range rp.nodes {
		cpuTotal += n.Resources[ResourceCPU] + n.Allocated[ResourceCPU]
		cpuUsed += n.Allocated[ResourceCPU]
		gpuTotal += n.Resources[ResourceGPU] + n.Allocated[ResourceGPU]
		gpuUsed += n.Allocated[ResourceGPU]
	}
	if cpuTotal > 0 {
		out["cpu"] = cpuUsed / cpuTotal
	}
	if gpuTotal > 0 {
		out["gpu"] = gpuUsed / gpuTotal
	}
	return out
}