// internal/Aggregation/resource_pool.go
// NebulaCore ResourcePool: Distributed Supercomputer Kernel for all resources.
// Production-ready, AI-driven extension points, Vector scoring (Pareto), composite reservations,
// telemetry/forecast hooks, power-aware scheduling, health & deadline watchers, AutoDev (DSL).
package aggregation

import (
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

// ResourceNode represents physical/virtual Node and its free capacities.
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
	SLO        map[string]float64 // Node-level SLO hints
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
	Affinity     []string                          // Node IDs or labels or key=value
	AntiAffinity []string
	SLO          map[string]float64
	Start        time.Time
	Deadline     time.Time
	Policy       string // name of policy module
	CreatedAt    time.Time
	Owner        string // logical owner (project/user)
	Weights      map[string]float64 // optional Weights for Multi-Dim Vector scoring
	_enqueuedAt  time.Time          // internal
}

// PoolPolicy: returns (NodeID, scoreVector, error). scoreVector Dims are policy-specific e.g. {"util":0.7,"energy":0.2}
type PoolPolicy interface {
	Name() string
	Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) // returns NodeID + Vector Scores
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
type PolicyVerifier func(policyBytes []byte) error // Must verify signature/safety
type PolicyLoader func(policyBytes []byte) (PoolPolicy, error)

type ResourcePool struct {
	Mu                  sync.RWMutex
	Nodes               map[string]*ResourceNode
	Reserves            map[string]Reservation
	Policies            map[string]PoolPolicy
	KPIs                map[string]float64
	Trace               []TraceEntry
	AutoDev             func(name string, wasmOrDSL []byte) error // orchestrator-provided upload handler
	OnChange            []func()
	RebalanceHook       func(pool *ResourcePool)
	ForecastHook        ForecastHook
	autoscalerHook      AutoscalerHook
	allocatorHook       AllocatorHook
	policyVerifier      PolicyVerifier
	healthCheckInterval time.Duration
	healthTimeout       time.Duration
	stopHealthCh        chan struct{}
	deadlineInterval    time.Duration
	stopDeadlineCh      chan struct{}
	TraceMax            int
	pendingQueue        []Reservation
	allocatorInterval   time.Duration
	allocatorStopCh     chan struct{}
	autoscalerInterval  time.Duration
	autoscalerStopCh    chan struct{}
	rand                *rand.Rand
}

// NewResourcePool initialises pool with defaults and built-in Policies.
func NewResourcePool() *ResourcePool {
	src := rand.NewSource(time.Now().UnixNano())
	r := rand.New(src)
	rp := &ResourcePool{
		Nodes:               make(map[string]*ResourceNode),
		Reserves:            make(map[string]Reservation),
		Policies:            make(map[string]PoolPolicy),
		KPIs:                make(map[string]float64),
		Trace:               make([]TraceEntry, 0, 256),
		OnChange:            make([]func(), 0),
		healthCheckInterval: 15 * time.Second,
		healthTimeout:       defaultHealthDur,
		deadlineInterval:    defaultDeadlineChk,
		TraceMax:            defaultTraceMax,
		pendingQueue:        make([]Reservation, 0),
		allocatorInterval:   defaultAllocatorTick,
		autoscalerInterval:  defaultAutoscaleTick,
		rand:                r,
	}
	rp.Policies["default-fairshare"] = &DefaultFairSharePolicy{}
	rp.Policies["cost-aware"] = &CostAwarePolicy{}
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
	rp.Mu.Lock()
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
	rp.Nodes[n.ID] = n
	rp.TraceAppend(TraceInfo, "AddNode", "Node-added", map[string]any{"Node": n.ID}, rp.snapshotForExplain(n.ID))
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) AddNodes(Nodes []*ResourceNode) {
	rp.Mu.Lock()
	for _, n := range Nodes {
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
		rp.Nodes[n.ID] = n
		rp.TraceAppend(TraceInfo, "AddNodes", "Node-added", map[string]any{"Node": n.ID}, rp.snapshotForExplain(n.ID))
	}
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) RemoveNode(id string) {
	rp.Mu.Lock()
	delete(rp.Nodes, id)
	rp.TraceAppend(TraceWarn, "RemoveNode", "Node-removed", map[string]any{"Node": id}, nil)
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) UpdateNodeStatus(NodeID string, status NODE_STATUS) error {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		return fmt.Errorf("Node %s not found", NodeID)
	}
	n.Status = status
	n.LastSeen = time.Now()
	rp.TraceAppend(TraceInfo, "UpdateNodeStatus", string(status), map[string]any{"Node": NodeID}, rp.snapshotForExplain(NodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) UpdateNodeResources(NodeID string, res map[ResourceType]float64) error {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		return fmt.Errorf("Node %s not found", NodeID)
	}
	n.Resources = res
	n.LastSeen = time.Now()
	rp.TraceAppend(TraceInfo, "UpdateNodeResources", "updated-resources", map[string]any{"Node": NodeID}, rp.snapshotForExplain(NodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) UpdateNodeMeta(NodeID string, labels map[string]string, meta map[string]any) error {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		return fmt.Errorf("Node %s not found", NodeID)
	}
	for k, v := range labels {
		n.Labels[k] = v
	}
	for k, v := range meta {
		n.Meta[k] = v
	}
	n.LastSeen = time.Now()
	rp.TraceAppend(TraceInfo, "UpdateNodeMeta", "labels-meta-updated", map[string]any{"Node": NodeID}, rp.snapshotForExplain(NodeID))
	rp.notify()
	return nil
}

func (rp *ResourcePool) GetNodeInfo(NodeID string) *ResourceNode {
	rp.Mu.RLock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		rp.Mu.RUnlock()
		return nil
	}
	copyNode := *n
	copyNode.Labels = copyMapString(n.Labels)
	copyNode.Meta = copyMapAny(n.Meta)
	copyNode.Resources = copyMapResources(n.Resources)
	copyNode.NUMATop = append([]NUMANode(nil), n.NUMATop...)
	copyNode.GPUTop = append([]GPUPartition(nil), n.GPUTop...)
	copyNode.NICs = append([]NetworkInterface(nil), n.NICs...)
	rp.Mu.RUnlock()
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
	if _, exists := rp.Reserves[r.ID]; exists {
		base := r.ID
		for i := 1; ; i++ {
			r.ID = fmt.Sprintf("%s-%d", base, i)
			if _, ok := rp.Reserves[r.ID]; !ok {
				break
			}
		}
	}
}

// -------------------- Reservation / Allocation (composite + Vector scoring) --------------------

// Allocate attempts allocation using a policy, supports composite requirements and forecasting avoidance.
// Returns NodeID, scoreVector, error.
func (rp *ResourcePool) Allocate(req Reservation) (string, map[string]float64, error) {
	start := time.Now()

	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now()
	}

	// Normalize composite
	reqReqs := map[ResourceType]float64{}
	if len(req.Requirements) > 0 {
		for k, v := range req.Requirements {
			reqReqs[k] = v
		}
	} else if req.RType != "" && req.Amount > 0 {
		reqReqs[req.RType] = req.Amount
	}

	// admission quick check under lock
	rp.Mu.Lock()
	ensureUniqueReservationIDUnlocked(rp, &req)

	// pick policy safely
	policyName := req.Policy
	if policyName == "" {
		policyName = "default-fairshare"
	}
	policy := rp.Policies[policyName]
	if policy == nil {
		// no policy available -> fail or queue if soft
		rp.TraceAppend(TraceWarn, "Allocate", "policy-missing", map[string]any{"req": req.ID, "policy": policyName}, nil)
		if req.Soft {
			req._enqueuedAt = time.Now()
			rp.pendingQueue = append(rp.pendingQueue, req)
			rp.TraceAppend(TraceInfo, "Allocate", "queued-soft-missing-policy", map[string]any{"req": req.ID}, nil)
			rp.Mu.Unlock()
			return "", nil, ErrQueued
		}
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.Mu.Unlock()
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, fmt.Errorf("policy %s not found", policyName)
	}

	// quick feasibility: is any Node capable on static view?
	canSatisfy := false
	for _, n := range rp.Nodes {
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
			rp.TraceAppend(TraceInfo, "Allocate", "queued-soft-no-capacity", map[string]any{"req": req.ID}, nil)
			rp.Mu.Unlock()
			return "", nil, ErrQueued
		}
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.TraceAppend(TraceWarn, "Allocate", "no-capacity", map[string]any{"req": req.ID}, nil)
		rp.Mu.Unlock()
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, ErrNoResource
	}
	// copy policy to local var and release lock (Policies should be safe to call concurrently)
	localPolicy := policy
	rp.Mu.Unlock()

	NodeID, Vec, err := localPolicy.Allocate(rp, req)
	if err != nil {
		rp.Mu.Lock()
		defer rp.Mu.Unlock()
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.TraceAppend(TraceWarn, "Allocate", "policy-failed", map[string]any{"req": req.ID, "err": err.Error(), "policy": localPolicy.Name()}, nil)
		rp.updateAvgAllocLatency(time.Since(start))
		if req.Soft {
			req._enqueuedAt = time.Now()
			rp.pendingQueue = append(rp.pendingQueue, req)
			rp.TraceAppend(TraceInfo, "Allocate", "queued-after-policy-fail", map[string]any{"req": req.ID}, nil)
			return "", nil, ErrQueued
		}
		return "", nil, err
	}

	// booking atomic under lock
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
		rp.TraceAppend(TraceError, "Allocate", "Node-missing-after-policy", map[string]any{"req": req.ID, "Node": NodeID}, nil)
		rp.updateAvgAllocLatency(time.Since(start))
		return "", nil, fmt.Errorf("Node %s disappeared during allocate", NodeID)
	}

	// forecast safeguard with timeout
	if rp.ForecastHook != nil {
		for rt := range reqReqs {
			if rp.callForecastWithTimeout(rt, n.Region, 30*time.Second) >= 0.95 {
				rp.TraceAppend(TraceWarn, "Allocate", "forecast-block", map[string]any{"Node": NodeID, "resource": rt}, rp.snapshotForExplain(NodeID))
				rp.KPIs["failed_allocs"] = rp.KPIs["failed_allocs"] + 1
				if req.Soft {
					req._enqueuedAt = time.Now()
					rp.pendingQueue = append(rp.pendingQueue, req)
					rp.TraceAppend(TraceInfo, "Allocate", "queued-due-to-forecast", map[string]any{"req": req.ID}, nil)
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
			rp.TraceAppend(TraceWarn, "Allocate", "insufficient-after-decision", map[string]any{"req": req.ID, "Node": NodeID, "rtype": rt}, rp.snapshotForExplain(NodeID))
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
	rp.Reserves[req.ID] = req
	rp.TraceAppend(TraceInfo, "Allocate", "ok", map[string]any{"req": req.ID, "Node": NodeID, "reqs": reqReqs, "policy": localPolicy.Name()}, rp.snapshotForExplain(NodeID))
	rp.updateKPIsLocked()
	rp.updateAvgAllocLatency(time.Since(start))
	rp.notify()
	return NodeID, Vec, nil
}

// Free releases composite reservation and restores resources.
func (rp *ResourcePool) Free(resID string) error {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	req, ok := rp.Reserves[resID]
	if !ok {
		rp.TraceAppend(TraceWarn, "Free", "reservation-not-found", map[string]any{"res": resID}, nil)
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
	n, ok := rp.Nodes[req.NodeID]
	if ok {
		for rt, amt := range reqReqs {
			n.Resources[rt] = n.Resources[rt] + amt
			if n.Allocated == nil {
				n.Allocated = map[ResourceType]float64{}
			}
			n.Allocated[rt] = math.Max(0, n.Allocated[rt]-amt)
		}
	}
	delete(rp.Reserves, resID)
	rp.TraceAppend(TraceInfo, "Free", "released", map[string]any{"res": resID, "Node": req.NodeID}, rp.snapshotForExplain(req.NodeID))
	rp.updateKPIsLocked()
	rp.notify()
	return nil
}

func (rp *ResourcePool) FreeMany(resIDs []string) {
	rp.Mu.Lock()
	for _, id := range resIDs {
		req, ok := rp.Reserves[id]
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
		if n, ok := rp.Nodes[req.NodeID]; ok {
			for rt, amt := range reqReqs {
				n.Resources[rt] = n.Resources[rt] + amt
				if n.Allocated == nil {
					n.Allocated = map[ResourceType]float64{}
				}
				n.Allocated[rt] = math.Max(0, n.Allocated[rt]-amt)
			}
		}
		delete(rp.Reserves, id)
		rp.TraceAppend(TraceInfo, "FreeMany", "released", map[string]any{"res": id, "Node": req.NodeID}, rp.snapshotForExplain(req.NodeID))
	}
	rp.Mu.Unlock()
	rp.updateKPIsLocked()
	rp.notify()
}

func (rp *ResourcePool) ListReservations() []Reservation {
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	out := make([]Reservation, 0, len(rp.Reserves))
	for _, r := range rp.Reserves {
		out = append(out, r)
	}
	return out
}

// -------------------- Policies Management / DSL / Multi-Dim scoring --------------------

func (rp *ResourcePool) InjectPolicy(name string, p PoolPolicy) {
	rp.Mu.Lock()
	rp.Policies[name] = p
	rp.TraceAppend(TraceInfo, "InjectPolicy", "policy-injected", map[string]any{"policy": name}, nil)
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) RemovePolicy(name string) {
	rp.Mu.Lock()
	delete(rp.Policies, name)
	rp.TraceAppend(TraceWarn, "RemovePolicy", "policy-removed", map[string]any{"policy": name}, nil)
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) SetAutoDev(f func(name string, wasmOrDSL []byte) error) {
	rp.Mu.Lock()
	rp.AutoDev = f
	rp.TraceAppend(TraceInfo, "SetAutoDev", "autodev-hook-set", nil, nil)
	rp.Mu.Unlock()
	rp.notify()
}

func (rp *ResourcePool) SetPolicyVerifier(v PolicyVerifier) {
	rp.Mu.Lock()
	rp.policyVerifier = v
	rp.Mu.Unlock()
	rp.TraceAppend(TraceInfo, "SetPolicyVerifier", "verifier-set", nil, nil)
}

// RegisterPolicyFromDSL (single-Dim)
func (rp *ResourcePool) RegisterPolicyFromDSL(name string, script string) error {
	expr, err := govaluate.NewEvaluableExpression(script)
	if err != nil {
		return fmt.Errorf("dsl compile error: %w", err)
	}
	p := &ExprPolicy{
		name:    name,
		exprs:   map[string]*govaluate.EvaluableExpression{"score": expr},
		Dims:    []string{"score"},
		rawDSL:  script,
		created: time.Now(),
	}
	rp.InjectPolicy(name, p)
	return nil
}

// RegisterMultiDimPolicyFromDSL registers a policy with named Dimensions expressions.
func (rp *ResourcePool) RegisterMultiDimPolicyFromDSL(name string, DimExprs map[string]string) error {
	exprs := map[string]*govaluate.EvaluableExpression{}
	Dims := []string{}
	for k, s := range DimExprs {
		e, err := govaluate.NewEvaluableExpression(s)
		if err != nil {
			return fmt.Errorf("dsl compile error Dim=%s: %w", k, err)
		}
		exprs[k] = e
		Dims = append(Dims, k)
	}
	p := &ExprPolicy{
		name:    name,
		exprs:   exprs,
		Dims:    Dims,
		rawDSL:  "<Multi-Dim>",
		created: time.Now(),
	}
	rp.InjectPolicy(name, p)
	return nil
}

// RegisterPolicyFromLoader requires a verifier to be set before accepting binary Policies.
func (rp *ResourcePool) RegisterPolicyFromLoader(name string, policyBytes []byte, loader PolicyLoader) error {
	if loader == nil {
		return fmt.Errorf("loader is nil")
	}
	rp.Mu.RLock()
	verifier := rp.policyVerifier
	rp.Mu.RUnlock()
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

// ExprPolicy uses govaluate expressions to compute one or more Dimensions per candidate.
type ExprPolicy struct {
	name    string
	exprs   map[string]*govaluate.EvaluableExpression // Dim -> expr
	Dims    []string
	rawDSL  string
	created time.Time
}

func (p *ExprPolicy) Name() string { return p.name }

// Allocate will compute Dims for each candidate and choose by Pareto front then tiebreak by weighted sum.
func (p *ExprPolicy) Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) {
	pool.Mu.RLock()
	Cands := make([]*ResourceNode, 0, len(pool.Nodes))
	for _, n := range pool.Nodes {
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
		Cands = append(Cands, n)
	}
	pool.Mu.RUnlock()

	if len(Cands) == 0 {
		return "", nil, ErrNoResource
	}

	Scores := make([]candScore, 0, len(Cands))
	for i, n := range Cands {
		Params := make(map[string]any)
		Params["req_amount"] = req.Amount
		Params["req_priority"] = req.Priority
		Params["Node_tdp"] = n.TDP
		Params["Node_pooltier"] = n.PoolTier
		Params["Node_region"] = n.Region
		Params["Node_cpu"] = n.Resources[ResourceCPU]
		Params["Node_gpu"] = n.Resources[ResourceGPU]
		Params["Node_ram"] = n.Resources[ResourceRAM]
		if n.Allocated != nil {
			Params["Node_alloc_cpu"] = n.Allocated[ResourceCPU]
			Params["Node_alloc_gpu"] = n.Allocated[ResourceGPU]
		} else {
			Params["Node_alloc_cpu"] = 0.0
			Params["Node_alloc_gpu"] = 0.0
		}
		for k, v := range n.Meta {
			kc := "meta_" + strings.ReplaceAll(k, "-", "_")
			Params[kc] = v
		}
		Vec := map[string]float64{}
		Skip := false
		for _, Dim := range p.Dims {
			expr := p.exprs[Dim]
			if expr == nil {
				continue
			}
			res, err := expr.Evaluate(Params)
			if err != nil {
				Skip = true
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
				Skip = true
				break
			}
			Vec[Dim] = f
		}
		if Skip {
			continue
		}
		Scores = append(Scores, candScore{Node: n, Vec: Vec, Order: i})
	}
	if len(Scores) == 0 {
		return "", nil, ErrNoResource
	}

	Indices := paretoFrontIndices(Scores)
	if len(Indices) == 1 {
		Chosen := Scores[Indices[0]]
		return Chosen.Node.ID, Chosen.Vec, nil
	}
	Weights := map[string]float64{}
	if req.Weights != nil && len(req.Weights) > 0 {
		for k, v := range req.Weights {
			Weights[k] = v
		}
	} else {
		for _, d := range p.Dims {
			Weights[d] = 1.0
		}
	}
	BestScore := math.Inf(-1)
	BestIdx := Indices[0]
	for _, idx := range Indices {
		cs := Scores[idx]
		sum := 0.0
		for d, v := range cs.Vec {
			w := Weights[d]
			sum += w * v
		}
		if sum > BestScore {
			BestScore = sum
			BestIdx = idx
		}
	}
	Chosen := Scores[BestIdx]
	return Chosen.Node.ID, Chosen.Vec, nil
}

func (p *ExprPolicy) ExplainDecision(req Reservation) string {
	return fmt.Sprintf("ExprPolicy(%s) Dims=%v", p.name, p.Dims)
}

// -------------------- Pareto helpers --------------------

type candScore struct {
	Node  *ResourceNode
	Vec   map[string]float64
	Order int
}

func paretoFrontIndices(Scores []candScore) []int {
	n := len(Scores)
	IsDominated := make([]bool, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if dominates(Scores[j].Vec, Scores[i].Vec) {
				IsDominated[i] = true
				break
			}
		}
	}
	out := []int{}
	for i := 0; i < n; i++ {
		if !IsDominated[i] {
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
	rp.Mu.Lock()
	rp.TraceAppend(TraceInfo, "Rebalance", "start", nil, nil)
	// compute util
	util := map[string]float64{}
	for id, n := range rp.Nodes {
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
		rp.TraceAppend(TraceInfo, "Rebalance", "no-overload", nil, nil)
		rp.Mu.Unlock()
		return
	}
	sort.Slice(overloaded, func(i, j int) bool { return util[overloaded[i]] > util[overloaded[j]] })

	for _, src := range overloaded {
		for resID, r := range rp.Reserves {
			if r.NodeID != src {
				continue
			}
			if !r.Soft || r.Priority > 5 {
				continue
			}
			for tid, tn := range rp.Nodes {
				if tid == src || tn.Status != NODE_ONLINE {
					continue
				}
				// forecast check
				if rp.ForecastHook != nil {
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
				if srcNode, ok := rp.Nodes[src]; ok {
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
				rp.Reserves[resID] = r
				rp.TraceAppend(TraceInfo, "Rebalance", "migrated", map[string]any{"res": resID, "from": src, "to": tid}, rp.snapshotForExplain(tid))
				break
			}
		}
	}
	if rp.RebalanceHook != nil {
		go rp.RebalanceHook(rp)
	}
	rp.updateKPIsLocked()
	rp.Mu.Unlock()
	rp.notify()
	rp.TraceAppend(TraceInfo, "Rebalance", "end", nil, nil)
}

// -------------------- Health / Self-Repair (bounded) --------------------
  
func (rp *ResourcePool) StartHealthChecker(interval, timeout time.Duration) {
	rp.Mu.Lock()
	if rp.stopHealthCh != nil {
		rp.Mu.Unlock()
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
	rp.Mu.Unlock()

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
	rp.TraceAppend(TraceInfo, "HealthChecker", "started", map[string]any{"interval": rp.healthCheckInterval.String(), "timeout": rp.healthTimeout.String()}, nil)
}

func (rp *ResourcePool) StopHealthChecker() {
	rp.Mu.Lock()
	ch := rp.stopHealthCh
	if ch != nil {
		close(ch)
		rp.stopHealthCh = nil
	}
	rp.Mu.Unlock()
	if ch != nil {
		rp.TraceAppend(TraceInfo, "HealthChecker", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) performHealthCheck() {
	rp.Mu.Lock()
	now := time.Now()
	toRepair := []string{}
	for id, n := range rp.Nodes {
		if now.Sub(n.LastSeen) > rp.healthTimeout && n.Status == NODE_ONLINE {
			n.Status = NODE_OFFLINE
			rp.TraceAppend(TraceWarn, "HealthCheck", "Node-marked-offline", map[string]any{"Node": id}, rp.snapshotForExplain(id))
			toRepair = append(toRepair, id)
		}
	}
	rp.Mu.Unlock()

	limit := maxRepairsPerTick
	if limit > len(toRepair) {
		limit = len(toRepair)
	}
	for i := 0; i < limit; i++ {
		NodeID := toRepair[i]
		// sequential repair attempts (bounded)
		time.Sleep(50 * time.Millisecond)
		rp.Mu.Lock()
		if Node, ok := rp.Nodes[NodeID]; ok && Node.Status == NODE_OFFLINE {
			Node.Status = NODE_MAINT
			rp.TraceAppend(TraceInfo, "HealthRepair", "Node-maintenance-start", map[string]any{"Node": NodeID}, nil)
			time.Sleep(200 * time.Millisecond)
			Node.Status = NODE_ONLINE
			Node.LastSeen = time.Now()
			rp.TraceAppend(TraceInfo, "HealthRepair", "Node-repaired", map[string]any{"Node": NodeID}, rp.snapshotForExplain(NodeID))
			rp.notify()
		}
		rp.Mu.Unlock()
	}
}

// CheckAndRepair synchronous simple repair routine
func (rp *ResourcePool) CheckAndRepair() []string {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	repaired := []string{}
	now := time.Now()
	for id, n := range rp.Nodes {
		if n.Status == NODE_OFFLINE || n.Status == NODE_DEGRADED {
			if now.Sub(n.LastSeen) <= 2*rp.healthTimeout {
				n.Status = NODE_MAINT
				n.LastSeen = now
				n.Status = NODE_ONLINE
				repaired = append(repaired, id)
				rp.TraceAppend(TraceInfo, "CheckAndRepair", "repaired", map[string]any{"Node": id}, rp.snapshotForExplain(id))
			} else {
				rp.TraceAppend(TraceWarn, "CheckAndRepair", "quarantine", map[string]any{"Node": id}, nil)
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
	rp.Mu.Lock()
	if rp.stopDeadlineCh != nil {
		rp.Mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.deadlineInterval
	}
	stop := make(chan struct{})
	rp.stopDeadlineCh = stop
	rp.Mu.Unlock()

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
	rp.TraceAppend(TraceInfo, "DeadlineWatcher", "started", map[string]any{"interval": interval.String()}, nil)
}

func (rp *ResourcePool) StopDeadlineWatcher() {
	rp.Mu.Lock()
	ch := rp.stopDeadlineCh
	if ch != nil {
		close(ch)
		rp.stopDeadlineCh = nil
	}
	rp.Mu.Unlock()
	if ch != nil {
		rp.TraceAppend(TraceInfo, "DeadlineWatcher", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) enforceDeadlines() {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	now := time.Now()
	for id, r := range rp.Reserves {
		if !r.Deadline.IsZero() {
			remaining := r.Deadline.Sub(now)
			if remaining < 30*time.Second {
				for nid, n := range rp.Nodes {
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
					if srcNode, ok := rp.Nodes[r.NodeID]; ok {
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
					rp.Reserves[id] = r
					rp.TraceAppend(TraceInfo, "DeadlineWatcher", "rescheduled", map[string]any{"res": id, "to": nid}, rp.snapshotForExplain(nid))
					break
				}
			}
		}
	}
}

// -------------------- Allocator / Pending Queue / Autoscaler --------------------

func (rp *ResourcePool) StartAllocator(interval time.Duration) {
	rp.Mu.Lock()
	if rp.allocatorStopCh != nil {
		rp.Mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.allocatorInterval
	}
	rp.allocatorInterval = interval
	stop := make(chan struct{})
	rp.allocatorStopCh = stop
	rp.Mu.Unlock()

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
	rp.TraceAppend(TraceInfo, "Allocator", "started", map[string]any{"interval": rp.allocatorInterval.String()}, nil)
}

func (rp *ResourcePool) StopAllocator() {
	rp.Mu.Lock()
	ch := rp.allocatorStopCh
	if ch != nil {
		close(ch)
		rp.allocatorStopCh = nil
	}
	rp.Mu.Unlock()
	if ch != nil {
		rp.TraceAppend(TraceInfo, "Allocator", "stopped", nil, nil)
	}
}

func (rp *ResourcePool) processPendingOnce() {
	rp.Mu.Lock()
	if len(rp.pendingQueue) == 0 {
		rp.Mu.Unlock()
		return
	}
	queue := make([]Reservation, len(rp.pendingQueue))
	copy(queue, rp.pendingQueue)
	rp.pendingQueue = []Reservation{}
	rp.Mu.Unlock()

	remaining := make([]Reservation, 0, len(queue))
	for _, req := range queue {
		policyName := req.Policy
		if policyName == "" {
			policyName = "default-fairshare"
		}
		rp.Mu.RLock()
		policy := rp.Policies[policyName]
		rp.Mu.RUnlock()
		if policy == nil {
			remaining = append(remaining, req)
			continue
		}
		NodeID, _, err := policy.Allocate(rp, req)
		if err != nil {
			remaining = append(remaining, req)
			continue
		}
		rp.Mu.Lock()
		n, ok := rp.Nodes[NodeID]
		if !ok {
			remaining = append(remaining, req)
			rp.Mu.Unlock()
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
			rp.Mu.Unlock()
			continue
		}
		for rt, amt := range reqReqs {
			n.Resources[rt] = n.Resources[rt] - amt
			if n.Allocated == nil {
				n.Allocated = map[ResourceType]float64{}
			}
			n.Allocated[rt] = n.Allocated[rt] + amt
		}
		req.NodeID = NodeID
		rp.Reserves[req.ID] = req
		rp.TraceAppend(TraceInfo, "Allocator", "allocated-from-queue", map[string]any{"req": req.ID, "Node": NodeID}, rp.snapshotForExplain(NodeID))
		rp.updateKPIsLocked()
		rp.Mu.Unlock()
	}
	rp.Mu.Lock()
	rp.pendingQueue = append(rp.pendingQueue, remaining...)
	rp.Mu.Unlock()
	if len(remaining) > 0 {
		rp.TraceAppend(TraceInfo, "Allocator", "queue-left", map[string]any{"left": len(remaining)}, nil)
	}
}

func (rp *ResourcePool) SetAllocatorHook(h AllocatorHook) {
	rp.Mu.Lock()
	rp.allocatorHook = h
	rp.Mu.Unlock()
	rp.TraceAppend(TraceInfo, "SetAllocatorHook", "hook-set", nil, nil)
}

func (rp *ResourcePool) SetAutoscalerHook(h AutoscalerHook) {
	rp.Mu.Lock()
	rp.autoscalerHook = h
	rp.Mu.Unlock()
	rp.TraceAppend(TraceInfo, "SetAutoscalerHook", "hook-set", nil, nil)
}

func (rp *ResourcePool) StartAutoscaler(interval time.Duration) {
	rp.Mu.Lock()
	if rp.autoscalerStopCh != nil {
		rp.Mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = rp.autoscalerInterval
	}
	rp.autoscalerInterval = interval
	stop := make(chan struct{})
	rp.autoscalerStopCh = stop
	rp.Mu.Unlock()

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
	rp.TraceAppend(TraceInfo, "Autoscaler", "started", map[string]any{"interval": rp.autoscalerInterval.String()}, nil)
}

func (rp *ResourcePool) StopAutoscaler() {
	rp.Mu.Lock()
	ch := rp.autoscalerStopCh
	if ch != nil {
		close(ch)
		rp.autoscalerStopCh = nil
	}
	rp.Mu.Unlock()
	if ch != nil {
		rp.TraceAppend(TraceInfo, "Autoscaler", "stopped", nil, nil)
	}
}

// -------------------- Trace / KPIs / Utilities --------------------

func (rp *ResourcePool) TraceAppend(level TraceLevel, op, msg string, details map[string]any, snapshot map[string]any) {
	rp.Trace = append(rp.Trace, TraceEntry{
		Time:     time.Now(),
		Level:    level,
		Op:       op,
		Msg:      msg,
		Details:  details,
		Snapshot: snapshot,
	})
	if len(rp.Trace) > rp.TraceMax {
		rp.Trace = rp.Trace[len(rp.Trace)-rp.TraceMax:]
	}
}

func (rp *ResourcePool) GetTrace() []TraceEntry {
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	out := make([]TraceEntry, len(rp.Trace))
	copy(out, rp.Trace)
	return out
}

func (rp *ResourcePool) snapshotForExplain(NodeID string) map[string]any {
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	n, ok := rp.Nodes[NodeID]
	if !ok {
		return nil
	}
	return map[string]any{
		"Node":      n.ID,
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
	for _, n := range rp.Nodes {
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
	rp.KPIs["reservations_count"] = float64(len(rp.Reserves))
	totalJ := 0.0
	for _, n := range rp.Nodes {
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
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	out := make(map[string]float64, len(rp.KPIs))
	for k, v := range rp.KPIs {
		out[k] = v
	}
	return out
}

func (rp *ResourcePool) callForecastWithTimeout(rt ResourceType, region string, horizon time.Duration) float64 {
	rp.Mu.RLock()
	hook := rp.ForecastHook
	rp.Mu.RUnlock()
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

func matchesAffinity(Node *ResourceNode, r Reservation) bool {
	if len(r.Affinity) == 0 && len(r.AntiAffinity) == 0 {
		return true
	}
	if len(r.Affinity) > 0 {
		ok := false
		for _, a := range r.Affinity {
			if a == Node.ID {
				ok = true
				break
			}
			parts := strings.SplitN(a, "=", 2)
			if len(parts) == 2 {
				if v, exists := Node.Labels[parts[0]]; exists && v == parts[1] {
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
		if a == Node.ID {
			return false
		}
		parts := strings.SplitN(a, "=", 2)
		if len(parts) == 2 {
			if v, exists := Node.Labels[parts[0]]; exists && v == parts[1] {
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
	pool.Mu.RLock()
	Cands := make([]*ResourceNode, 0, len(pool.Nodes))
	for _, n := range pool.Nodes {
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
		Cands = append(Cands, n)
	}
	pool.Mu.RUnlock()

	if len(Cands) == 0 {
		return "", nil, ErrNoResource
	}
	BestIdx := 0
	BestVec := map[string]float64{}
	for i, n := range Cands {
		free := 0.0
		for _, rt := range []ResourceType{ResourceCPU, ResourceGPU, ResourceRAM} {
			free += n.Resources[rt]
		}
		Vec := map[string]float64{"free_capacity": free, "energy_score": -float64(n.TDP)}
		if i == 0 || dominatesVec(Vec, BestVec) {
			BestVec = Vec
			BestIdx = i
		}
	}
	return Cands[BestIdx].ID, BestVec, nil
}

func (p *DefaultFairSharePolicy) ExplainDecision(req Reservation) string {
	return "DefaultFairShare: highest free_capacity & lower TDP preference"
}

type CostAwarePolicy struct{}

func (p *CostAwarePolicy) Name() string { return "cost-aware" }

func (p *CostAwarePolicy) Allocate(pool *ResourcePool, req Reservation) (string, map[string]float64, error) {
	type cand struct {
		Node  *ResourceNode
		Vec   map[string]float64
		score float64
	}
	pool.Mu.RLock()
	candidates := []cand{}
	for _, n := range pool.Nodes {
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
		Vec := map[string]float64{"free": free, "cost": cost}
		score := free / cost
		candidates = append(candidates, cand{Node: n, Vec: Vec, score: score})
	}
	pool.Mu.RUnlock()

	if len(candidates) == 0 {
		return "", nil, ErrNoResource
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	Chosen := candidates[0]
	return Chosen.Node.ID, Chosen.Vec, nil
}

func (p *CostAwarePolicy) ExplainDecision(req Reservation) string {
	return "CostAwarePolicy: maximize free_capacity / cost"
}

// -------------------- Expose / Listeners / Gossip placeholder --------------------

func (rp *ResourcePool) RegisterOnChange(f func()) {
	rp.Mu.Lock()
	rp.OnChange = append(rp.OnChange, f)
	rp.Mu.Unlock()
}

func (rp *ResourcePool) notify() {
	for _, f := range rp.OnChange {
		go f()
	}
}

func (rp *ResourcePool) StartGossip() {
	rp.TraceAppend(TraceInfo, "Gossip", "start-placeholder", nil, nil)
}

func (rp *ResourcePool) SetRebalanceHookExternal(h func(*ResourcePool)) {
	rp.SetRebalanceHook(h)
}

func (rp *ResourcePool) SetRebalanceHook(h func(pool *ResourcePool)) {
	rp.Mu.Lock()
	rp.RebalanceHook = h
	rp.Mu.Unlock()
	rp.TraceAppend(TraceInfo, "SetRebalanceHook", "hook-set", nil, nil)
}

// -------------------- Expose Functions --------------------

func (rp *ResourcePool) ExposeFunctions() map[string]any {
	return map[string]any{
		"add_Node":                 rp.AddNode,
		"add_Nodes":                rp.AddNodes,
		"remove_Node":              rp.RemoveNode,
		"update_Node_status":       rp.UpdateNodeStatus,
		"update_Node_resources":    rp.UpdateNodeResources,
		"update_Node_meta":         rp.UpdateNodeMeta,
		"get_Node_info":            rp.GetNodeInfo,
		"allocate":                 rp.Allocate,
		"free":                     rp.Free,
		"free_many":                rp.FreeMany,
		"list_reservations":        rp.ListReservations,
		"rebalance":                rp.Rebalance,
		"predict":                  rp.PredictUtilization,
		"inject_policy":            rp.InjectPolicy,
		"remove_policy":            rp.RemovePolicy,
		"register_policy_dsl":      rp.RegisterPolicyFromDSL,
		"register_policy_Multi":    rp.RegisterMultiDimPolicyFromDSL,
		"register_policy_loader":   rp.RegisterPolicyFromLoader,
		"set_policy_verifier":      rp.SetPolicyVerifier,
		"get_kpis":                 rp.GetKPIs,
		"get_Trace":                rp.GetTrace,
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
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	out := make([]Reservation, 0, len(rp.pendingQueue))
	for _, r := range rp.pendingQueue {
		out = append(out, r)
	}
	return out
}

func (rp *ResourcePool) SetForecastHook(h ForecastHook) {
	rp.Mu.Lock()
	rp.ForecastHook = h
	rp.Mu.Unlock()
	rp.TraceAppend(TraceInfo, "SetForecastHook", "forecast-hook-set", nil, nil)
	rp.notify()
}

// PredictUtilization returns a snapshot prediction across Nodes (naive snapshot).
// Orchestrator/ForecastHook may provide better predictions via SetForecastHook.
func (rp *ResourcePool) PredictUtilization() map[string]float64 {
	rp.Mu.RLock()
	defer rp.Mu.RUnlock()
	out := map[string]float64{"cpu": 0.0, "gpu": 0.0}
	var cpuTotal, cpuUsed, gpuTotal, gpuUsed float64
	for _, n := range rp.Nodes {
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