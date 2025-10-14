// internal/qos/qos.go
// QoS manager: token-bucket per owner/job, priority queues, admission controller,
// usage accounting persisted daily, adaptation hooks and ExposeFunctions.
//
// Key fixes:
// - persistUsageSnapshot now copies state under lock and performs IO outside the lock
//   (prevents IO while holding RW locks).
// - persist uses atomic temp file with fsync before rename.
// - SetPolicy validates AppliesTo and persists outside the lock (avoids deadlock).
package qos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ModuleInfo
type ModuleInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	Health       string   `json:"health"`
}

// QoS classes and policy
type QoSClass string

const (
	QoSRealtime   QoSClass = "realtime"
	QoSBestEffort QoSClass = "besteffort"
	QoSBatch      QoSClass = "batch"
)

type QoSPolicy struct {
	ID              string    `json:"id"`
	Class           QoSClass  `json:"class"`
	Bandwidth       int64     `json:"bandwidth"`
	Priority        int       `json:"priority"`
	AppliesTo       string    `json:"applies_to"`
	EnforcementMode string    `json:"enforcement_mode"` // soft|hard
	TTL             time.Time `json:"ttl,omitempty"`
	Meta            map[string]any `json:"meta,omitempty"`
}

// tokenBucket for rate enforcement
type tokenBucket struct {
	capacity float64
	rate     float64
	tokens   float64
	last     time.Time
	mu       sync.Mutex
}

func newTokenBucket(capacity, rate float64) *tokenBucket {
	return &tokenBucket{capacity: capacity, rate: rate, tokens: capacity, last: time.Now()}
}

func (t *tokenBucket) consume(amount float64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(t.last).Seconds()
	t.tokens += elapsed * t.rate
	if t.tokens > t.capacity {
		t.tokens = t.capacity
	}
	t.last = now
	if t.tokens >= amount {
		t.tokens -= amount
		return true
	}
	return false
}

// QueuedTask metadata for admission
type QueuedTask struct {
	TaskID   string            `json:"task_id"`
	Owner    string            `json:"owner"`
	ReqBW    int64             `json:"req_bw"`
	Priority int               `json:"priority"`
	Meta     map[string]any    `json:"meta"`
	Enqueued time.Time         `json:"enqueued"`
}

// UsageReport persisted
type UsageReport struct {
	AppliesTo string  `json:"applies_to"`
	Consumed  float64 `json:"consumed"`
	Period    string  `json:"period"`
}

// QoSManager
type QoSManager struct {
	mu            sync.RWMutex
	policies      map[string]QoSPolicy
	buckets       map[string]*tokenBucket
	usage         map[string]float64 // accumulation in current period
	baseDir       string
	refillCancel  context.CancelFunc
	highQueue     chan *QueuedTask
	medQueue      chan *QueuedTask
	lowQueue      chan *QueuedTask
	adaptFn       func(report UsageReport) QoSPolicy
	refillRunning bool
}

// NewQoSManager
func NewQoSManager(baseDir string) *QoSManager {
	_ = os.MkdirAll(baseDir, 0o750)
	q := &QoSManager{
		policies:  map[string]QoSPolicy{},
		buckets:   map[string]*tokenBucket{},
		usage:     map[string]float64{},
		baseDir:   baseDir,
		highQueue: make(chan *QueuedTask, 1000),
		medQueue:  make(chan *QueuedTask, 1000),
		lowQueue:  make(chan *QueuedTask, 1000),
	}
	return q
}

// SetPolicy creates/updates a QoS policy and bucket
func (qm *QoSManager) SetPolicy(p QoSPolicy) error {
	if p.ID == "" {
		return errors.New("policy id required")
	}
	// ensure AppliesTo is set (avoid creating bucket with empty key)
	if p.AppliesTo == "" {
		return errors.New("policy.AppliesTo required")
	}

	// update policy under lock (quick)
	qm.mu.Lock()
	qm.policies[p.ID] = p
	// create token bucket (bandwidth tokens per second)
	capacity := float64(p.Bandwidth)
	if capacity <= 0 {
		capacity = 1
	}
	qm.buckets[p.AppliesTo] = newTokenBucket(capacity, capacity) // refill rate = bandwidth per sec
	qm.mu.Unlock()

	// persist outside lock to avoid RW deadlocks / IO under lock
	if err := qm.persistUsageSnapshot(); err != nil {
		return fmt.Errorf("persistUsageSnapshot failed: %w", err)
	}
	return nil
}

func (qm *QoSManager) RemovePolicy(id string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	if p, ok := qm.policies[id]; ok {
		delete(qm.buckets, p.AppliesTo)
		delete(qm.policies, id)
	}
}

// CheckAdmission tries to consume tokens for appliesTo, returns admit bool and reason
func (qm *QoSManager) CheckAdmission(appliesTo string, requiredBandwidth int64) (bool, string) {
	qm.mu.RLock()
	b, ok := qm.buckets[appliesTo]
	pol := QoSPolicy{}
	for _, v := range qm.policies {
		if v.AppliesTo == appliesTo {
			pol = v
			break
		}
	}
	qm.mu.RUnlock()
	if !ok {
		return false, "no_policy"
	}
	okConsume := b.consume(float64(requiredBandwidth))
	if okConsume {
		qm.mu.Lock()
		qm.usage[appliesTo] += float64(requiredBandwidth)
		qm.mu.Unlock()
		return true, "admitted"
	}
	if pol.EnforcementMode == "soft" {
		// allow but mark as throttled
		return true, "soft_throttle"
	}
	return false, "insufficient_tokens"
}

// EnqueueTaskWithQoS puts task into priority queue with policy enforcement
func (qm *QoSManager) EnqueueTaskWithQoS(t *QueuedTask, policyID string) (bool, string) {
	qm.mu.RLock()
	p, ok := qm.policies[policyID]
	qm.mu.RUnlock()
	if !ok {
		return false, "policy_not_found"
	}
	admit, reason := qm.CheckAdmission(p.AppliesTo, t.ReqBW)
	if !admit && p.EnforcementMode == "hard" {
		return false, reason
	}
	// choose queue by priority
	if t.Priority >= 8 {
		select {
		case qm.highQueue <- t:
		default:
			return false, "high_queue_full"
		}
	} else if t.Priority >= 4 {
		select {
		case qm.medQueue <- t:
		default:
			return false, "med_queue_full"
		}
	} else {
		select {
		case qm.lowQueue <- t:
		default:
			return false, "low_queue_full"
		}
	}
	return true, "enqueued"
}

// StartRefiller starts a background refiller that periodically refills buckets
func (qm *QoSManager) StartRefiller(parentCtx context.Context) {
	qm.mu.Lock()
	if qm.refillRunning {
		qm.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parentCtx)
	qm.refillCancel = cancel
	qm.refillRunning = true
	qm.mu.Unlock()
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				qm.mu.Lock()
				for _, b := range qm.buckets {
					_ = b.consume(0)
				}
				qm.mu.Unlock()
			}
		}
	}()
}

// StopRefiller stops background refill
func (qm *QoSManager) StopRefiller() {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	if qm.refillCancel != nil {
		qm.refillCancel()
		qm.refillRunning = false
	}
}

// persistUsageSnapshot writes daily usage as JSON
// NOTE: avoid performing IO while holding locks; copy state and then write outside lock.
// This implementation uses os.CreateTemp + fsync + rename to guarantee atomic replacement.
func (qm *QoSManager) persistUsageSnapshot() error {
	// copy necessary state while holding RLock, then release lock and perform IO
	qm.mu.RLock()
	baseDir := qm.baseDir
	if baseDir == "" {
		qm.mu.RUnlock()
		return nil
	}
	// shallow copy usage map to avoid holding lock during IO
	usageCopy := make(map[string]float64, len(qm.usage))
	for k, v := range qm.usage {
		usageCopy[k] = v
	}
	qm.mu.RUnlock()

	// ensure baseDir exists
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return err
	}

	now := time.Now().UTC()
	file := filepath.Join(baseDir, fmt.Sprintf("qos_usage_%s.json", now.Format("2006-01-02")))
	// create temp file in same dir to ensure atomic rename across filesystems
	tmpFile, err := os.CreateTemp(baseDir, "qos_usage_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()

	rep := map[string]any{"date": now.Format(time.RFC3339), "usage": usageCopy}
	enc := json.NewEncoder(tmpFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpName)
		return err
	}
	// sync and close
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// atomic rename
	if err := os.Rename(tmpName, file); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// GetUsage returns usage for appliesTo
func (qm *QoSManager) GetUsage(appliesTo string) UsageReport {
	qm.mu.RLock()
	defer qm.mu.RUnlock()
	return UsageReport{AppliesTo: appliesTo, Consumed: qm.usage[appliesTo], Period: time.Now().Format("2006-01-02")}
}

// RegisterAdaptationHook registers adaptation function
func (qm *QoSManager) RegisterAdaptationHook(fn func(report UsageReport) QoSPolicy) {
	qm.mu.Lock()
	qm.adaptFn = fn
	qm.mu.Unlock()
}

// RunAdaptation triggers adaptation once (could be scheduled)
// NOTE: avoid deadlock by copying appliesTo keys before calling SetPolicy
func (qm *QoSManager) RunAdaptation() error {
	qm.mu.RLock()
	fn := qm.adaptFn
	applies := make([]string, 0, len(qm.usage))
	for k := range qm.usage {
		applies = append(applies, k)
	}
	qm.mu.RUnlock()
	if fn == nil {
		return errors.New("no adapt hook")
	}
	for _, appliesTo := range applies {
		rep := qm.GetUsage(appliesTo)
		newPol := fn(rep)
		// SetPolicy will acquire locks itself
		_ = qm.SetPolicy(newPol)
	}
	return nil
}

// ModuleMeta
func (qm *QoSManager) ModuleMeta() ModuleInfo {
	return ModuleInfo{
		Name:         "qos",
		Version:      "v1.2",
		Capabilities: []string{"admission", "token_bucket", "queues", "usage"},
		Health:       "ok",
	}
}

// ExposeFunctions
func (qm *QoSManager) ExposeFunctions() map[string]any {
	return map[string]any{
		"set_policy":        qm.SetPolicy,
		"remove_policy":     qm.RemovePolicy,
		"check_admission":   qm.CheckAdmission,
		"enqueue_task":      qm.EnqueueTaskWithQoS,
		"get_usage":         qm.GetUsage,
		"register_adapt":    qm.RegisterAdaptationHook,
		"run_adaptation":    qm.RunAdaptation,
		"start_refiller":    qm.StartRefiller,
		"stop_refiller":     qm.StopRefiller,
	}
}