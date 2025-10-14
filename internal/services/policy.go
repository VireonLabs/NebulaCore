package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
)

/*
Production-ready Policy Engine for NebulaCore.

Features included:
- GORM models for quotas, TOS rules, sensitive actions, audit logs.
- In-memory caches with periodic reload from DB and on-demand invalidation.
- CheckQuota, CheckTOS, RequireApproval with logging, audit entries and Prometheus metrics.
- Simple per-account token-bucket rate limiter (in-memory) with pluggable TTL (can replace with Redis).
- Dynamic update helpers (Add/Update/Remove policies).
- Safe for concurrent use.
- Exported hooks for control-plane to call (ValidateBeforeAllocate / RequireApproval etc).
*/

// ----- GORM models (DB tables) -----

type AccountQuota struct {
	ID        uint `gorm:"primaryKey"`
	AccountID uint `gorm:"uniqueIndex"`
	CPU       int
	RAM       int
	GPU       int
	StorageMB int
	UpdatedAt time.Time
}

func (AccountQuota) TableName() string { return "policy_account_quotas" }

type TOSRule struct {
	ID        uint `gorm:"primaryKey"`
	Provider  string
	Action    string
	Allowed   bool
	MetaJSON  string // optional metadata as JSON
	UpdatedAt time.Time
}

func (TOSRule) TableName() string { return "policy_tos_rules" }

type SensitiveAction struct {
	ID        uint `gorm:"primaryKey"`
	Action    string `gorm:"uniqueIndex"`
	RequireBy string // e.g., "admin", "owner" or empty => system approval
	Notes     string
	UpdatedAt time.Time
}

func (SensitiveAction) TableName() string { return "policy_sensitive_actions" }

type PolicyAudit struct {
	ID         uint `gorm:"primaryKey"`
	AccountID  *uint
	Action     string
	Provider   *string
	Allowed    bool
	Reason     string
	Actor      string // who performed the check (service, userID, system)
	Details    string // optional JSON
	CreatedAt  time.Time
}

func (PolicyAudit) TableName() string { return "policy_audit" }

// ----- PolicyEngine (runtime) -----

type PolicyEngine struct {
	db *gorm.DB

	// caches
	mu             sync.RWMutex
	quotasCache    map[uint]AccountQuota              // accountID -> quota
	tosCache       map[string]map[string]bool         // provider -> action -> allowed
	sensitiveCache map[string]SensitiveAction         // action -> info
	lastReload     time.Time
	reloadInterval time.Duration
	stopCh         chan struct{}
	wg             sync.WaitGroup

	// rate limiter (simple token buckets per account)
	limMu       sync.Mutex
	limiters    map[uint]*tokenBucket
	limiterTTL  time.Duration
	limiterCap  int
	limiterRate int // tokens per second

	// Prometheus metrics
	metricChecks        prometheus.Counter
	metricDenied        prometheus.Counter
	metricQuotaMiss     prometheus.GaugeVec
	metricTOSChecks     prometheus.Counter
	metricSensitiveHits prometheus.Counter
}

// ----- token-bucket simple impl (in-memory) -----

type tokenBucket struct {
	tokens       int
	capacity     int
	ratePerSec   int
	lastRefill   time.Time
	lastAccess   time.Time
	mu           sync.Mutex
}

func newTokenBucket(cap, rate int) *tokenBucket {
	return &tokenBucket{
		tokens:     cap,
		capacity:   cap,
		ratePerSec: rate,
		lastRefill: time.Now(),
		lastAccess: time.Now(),
	}
}

func (tb *tokenBucket) Allow(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed > 0 {
		inc := int(elapsed * float64(tb.ratePerSec))
		if inc > 0 {
			tb.tokens += inc
			if tb.tokens > tb.capacity {
				tb.tokens = tb.capacity
			}
			tb.lastRefill = now
		}
	}
	tb.lastAccess = now
	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

// ----- Prometheus metrics registration -----

func initPolicyMetrics() (prometheus.Counter, prometheus.Counter, *prometheus.GaugeVec, prometheus.Counter, prometheus.Counter) {
	metricChecks := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "nebula",
		Subsystem: "policy",
		Name:      "checks_total",
		Help:      "Total number of policy checks performed",
	})
	metricDenied := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "nebula",
		Subsystem: "policy",
		Name:      "denied_total",
		Help:      "Total number of denied policy checks",
	})
	metricQuotaMiss := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "nebula",
		Subsystem: "policy",
		Name:      "quota_miss",
		Help:      "Quota remaining or negative for accounts (negative means over-request)",
	}, []string{"account"})
	metricTOSChecks := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "nebula",
		Subsystem: "policy",
		Name:      "tos_checks_total",
		Help:      "Total TOS checks",
	})
	metricSensitiveHits := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "nebula",
		Subsystem: "policy",
		Name:      "sensitive_hits_total",
		Help:      "Sensitive action hits requiring approval",
	})
	// Register but ignore errors (safe if already registered)
	_ = prometheus.Register(metricChecks)
	_ = prometheus.Register(metricDenied)
	_ = prometheus.Register(metricQuotaMiss)
	_ = prometheus.Register(metricTOSChecks)
	_ = prometheus.Register(metricSensitiveHits)
	return metricChecks, metricDenied, metricQuotaMiss, metricTOSChecks, metricSensitiveHits
}

// ----- Constructor -----

type PolicyEngineOptions struct {
	ReloadInterval  time.Duration
	LimiterTTL      time.Duration
	LimiterCapacity int
	LimiterRate     int
}

func NewPolicyEngine(db *gorm.DB, opts *PolicyEngineOptions) *PolicyEngine {
	if opts == nil {
		opts = &PolicyEngineOptions{
			ReloadInterval:  30 * time.Second,
			LimiterTTL:      10 * time.Minute,
			LimiterCapacity: 100,
			LimiterRate:     10,
		}
	}
	mChecks, mDenied, mQuotaMiss, mTOS, mSensitive := initPolicyMetrics()
	pe := &PolicyEngine{
		db:             db,
		quotasCache:    make(map[uint]AccountQuota),
		tosCache:       make(map[string]map[string]bool),
		sensitiveCache: make(map[string]SensitiveAction),
		reloadInterval: opts.ReloadInterval,
		stopCh:         make(chan struct{}),
		limiters:       make(map[uint]*tokenBucket),
		limiterTTL:     opts.LimiterTTL,
		limiterCap:     opts.LimiterCapacity,
		limiterRate:    opts.LimiterRate,

		metricChecks:        mChecks,
		metricDenied:        mDenied,
		metricQuotaMiss:     *mQuotaMiss,
		metricTOSChecks:     mTOS,
		metricSensitiveHits: mSensitive,
	}
	pe.reloadFromDB() // initial load
	pe.wg.Add(1)
	go pe.reloadLoop()
	return pe
}

// Stop cleanly stops background reload
func (p *PolicyEngine) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

// reloadLoop periodically reloads policy data from DB
func (p *PolicyEngine) reloadLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.reloadFromDB()
		case <-p.stopCh:
			return
		}
	}
}

// reloadFromDB loads quotas, tos rules and sensitive actions
func (p *PolicyEngine) reloadFromDB() {
	var quotas []AccountQuota
	var tos []TOSRule
	var sens []SensitiveAction

	if err := p.db.Find(&quotas).Error; err != nil {
		log.Printf("policy.reload: failed to load quotas: %v", err)
		return
	}
	if err := p.db.Find(&tos).Error; err != nil {
		log.Printf("policy.reload: failed to load tos rules: %v", err)
		return
	}
	if err := p.db.Find(&sens).Error; err != nil {
		log.Printf("policy.reload: failed to load sensitive actions: %v", err)
		return
	}

	// build caches
	qc := make(map[uint]AccountQuota, len(quotas))
	for _, q := range quotas {
		qc[q.AccountID] = q
	}
	tc := make(map[string]map[string]bool)
	for _, t := range tos {
		if _, ok := tc[t.Provider]; !ok {
			tc[t.Provider] = make(map[string]bool)
		}
		tc[t.Provider][t.Action] = t.Allowed
	}
	sc := make(map[string]SensitiveAction)
	for _, s := range sens {
		sc[s.Action] = s
	}

	p.mu.Lock()
	p.quotasCache = qc
	p.tosCache = tc
	p.sensitiveCache = sc
	p.lastReload = time.Now()
	p.mu.Unlock()
}

// ----- Core API -----

// CheckQuota validates requested cpu/ram/gpu against account quota.
// returns allowed(bool), reason string, error (on system failure).
func (p *PolicyEngine) CheckQuota(ctx context.Context, accountID uint, cpu, ram, gpu int) (bool, string, error) {
	p.metricChecks.Inc()
	// rate limiting (protect from abuse)
	if !p.allowTokens(accountID, 1) {
		p.metricDenied.Inc()
		reason := "rate_limit_exceeded"
		p.audit(accountID, "quota_check", nil, false, reason, "policy.rate_limiter")
		return false, reason, nil
	}

	p.mu.RLock()
	q, ok := p.quotasCache[accountID]
	p.mu.RUnlock()
	if !ok {
		// attempt DB fallback
		var quota AccountQuota
		if err := p.db.WithContext(ctx).Where("account_id = ?", accountID).First(&quota).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				p.metricDenied.Inc()
				reason := "quota_not_found"
				p.audit(&accountID, "quota_check", nil, false, reason, "policy")
				return false, reason, nil
			}
			return false, "", fmt.Errorf("db error: %w", err)
		}
		q = quota
		// update cache async
		go func() {
			p.mu.Lock()
			p.quotasCache[accountID] = quota
			p.mu.Unlock()
		}()
	}

	// check limits
	if cpu > q.CPU {
		p.metricDenied.Inc()
		reason := fmt.Sprintf("cpu_quota_exceeded: requested=%d,limit=%d", cpu, q.CPU)
		p.metricQuotaMiss.WithLabelValues(fmt.Sprintf("%d", accountID)).Set(float64(q.CPU - cpu))
		p.audit(&accountID, "quota_check", nil, false, reason, "policy")
		return false, reason, nil
	}
	if ram > q.RAM {
		p.metricDenied.Inc()
		reason := fmt.Sprintf("ram_quota_exceeded: requested=%d,limit=%d", ram, q.RAM)
		p.metricQuotaMiss.WithLabelValues(fmt.Sprintf("%d", accountID)).Set(float64(q.RAM - ram))
		p.audit(&accountID, "quota_check", nil, false, reason, "policy")
		return false, reason, nil
	}
	if gpu > q.GPU {
		p.metricDenied.Inc()
		reason := fmt.Sprintf("gpu_quota_exceeded: requested=%d,limit=%d", gpu, q.GPU)
		p.metricQuotaMiss.WithLabelValues(fmt.Sprintf("%d", accountID)).Set(float64(q.GPU - gpu))
		p.audit(&accountID, "quota_check", nil, false, reason, "policy")
		return false, reason, nil
	}

	// allowed
	p.audit(&accountID, "quota_check", nil, true, "ok", "policy")
	return true, "ok", nil
}

// CheckTOS checks provider-specific TOS rule for an action.
// returns allowed(bool), reason string, error
func (p *PolicyEngine) CheckTOS(ctx context.Context, provider string, action string) (bool, string, error) {
	p.metricTOSChecks.Inc()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if m, ok := p.tosCache[provider]; ok {
		if allowed, ok2 := m[action]; ok2 {
			if allowed {
				return true, "allowed_by_tos", nil
			}
			p.metricDenied.Inc()
			return false, "disallowed_by_tos", nil
		}
		// not specified -> default allow (policy decision); record as warning
		return true, "tos_not_specified", nil
	}
	// provider unknown -> default deny to be safe
	p.metricDenied.Inc()
	return false, "provider_unknown", nil
}

// RequireApproval returns whether action requires manual/system approval based on sensitive actions and optional roles.
// roles: slice of strings like "admin","owner","user"
func (p *PolicyEngine) RequireApproval(ctx context.Context, action string, roles []string) (bool, string, error) {
	p.metricChecks.Inc()
	p.mu.RLock()
	sa, ok := p.sensitiveCache[action]
	p.mu.RUnlock()
	if !ok {
		// not sensitive
		return false, "not_sensitive", nil
	}
	// if the action requires specific role, check role presence
	if sa.RequireBy != "" {
		for _, r := range roles {
			if r == sa.RequireBy {
				// role has authority -> no extra approval needed
				return false, "role_authorized", nil
			}
		}
		// else require approval
		p.metricSensitiveHits.Inc()
		p.audit(nil, action, nil, false, "requires_approval", "policy")
		return true, "requires_approval", nil
	}
	// generic sensitive action -> require approval
	p.metricSensitiveHits.Inc()
	p.audit(nil, action, nil, false, "requires_approval", "policy")
	return true, "requires_approval", nil
}

// ----- Admin / dynamic mutation APIs -----

func (p *PolicyEngine) UpdateQuota(ctx context.Context, q AccountQuota) error {
	if q.AccountID == 0 {
		return errors.New("account_id required")
	}
	q.UpdatedAt = time.Now()
	if err := p.db.WithContext(ctx).Save(&q).Error; err != nil {
		return err
	}
	// update cache
	p.mu.Lock()
	p.quotasCache[q.AccountID] = q
	p.mu.Unlock()
	p.audit(&q.AccountID, "update_quota", nil, true, "ok", "admin")
	return nil
}

func (p *PolicyEngine) AddOrUpdateTOS(ctx context.Context, rule TOSRule) error {
	rule.UpdatedAt = time.Now()
	if err := p.db.WithContext(ctx).Where("provider = ? AND action = ?", rule.Provider, rule.Action).Assign(rule).FirstOrCreate(&rule).Error; err != nil {
		return err
	}
	// update cache
	p.mu.Lock()
	if _, ok := p.tosCache[rule.Provider]; !ok {
		p.tosCache[rule.Provider] = make(map[string]bool)
	}
	p.tosCache[rule.Provider][rule.Action] = rule.Allowed
	p.mu.Unlock()
	p.audit(nil, fmt.Sprintf("tos:%s/%s", rule.Provider, rule.Action), nil, true, "ok", "admin")
	return nil
}

func (p *PolicyEngine) AddSensitiveAction(ctx context.Context, s SensitiveAction) error {
	s.UpdatedAt = time.Now()
	if err := p.db.WithContext(ctx).Save(&s).Error; err != nil {
		return err
	}
	p.mu.Lock()
	p.sensitiveCache[s.Action] = s
	p.mu.Unlock()
	p.audit(nil, s.Action, nil, true, "ok", "admin")
	return nil
}

func (p *PolicyEngine) RemoveSensitiveAction(ctx context.Context, action string) error {
	if err := p.db.WithContext(ctx).Where("action = ?", action).Delete(&SensitiveAction{}).Error; err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.sensitiveCache, action)
	p.mu.Unlock()
	p.audit(nil, action, nil, true, "removed", "admin")
	return nil
}

// ----- audit helper -----

func (p *PolicyEngine) audit(accountID *uint, action string, provider *string, allowed bool, reason string, actor string) {
	d := PolicyAudit{
		AccountID: accountID,
		Action:    action,
		Provider:  provider,
		Allowed:   allowed,
		Reason:    reason,
		Actor:     actor,
		Details:   "",
		CreatedAt: time.Now(),
	}
	if err := p.db.Create(&d).Error; err != nil {
		// don't fail the main flow; just log
		log.Printf("policy.audit: failed to store audit: %v", err)
	}
}

// ----- rate limiter helpers -----

func (p *PolicyEngine) allowTokens(accountID uint, tokens int) bool {
	p.limMu.Lock()
	tb, ok := p.limiters[accountID]
	if !ok {
		tb = newTokenBucket(p.limiterCap, p.limiterRate)
		p.limiters[accountID] = tb
	}
	p.limMu.Unlock()
	allowed := tb.Allow(tokens)
	// optional: cleanup stale limiters periodically (not implemented here)
	return allowed
}

// ----- Utilities -----

// Export current quota snapshot (safe copy)
func (p *PolicyEngine) SnapshotQuotas() map[uint]AccountQuota {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[uint]AccountQuota, len(p.quotasCache))
	for k, v := range p.quotasCache {
		out[k] = v
	}
	return out
}

// Export TOS rules snapshot
func (p *PolicyEngine) SnapshotTOS() map[string]map[string]bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]map[string]bool, len(p.tosCache))
	for prov, m := range p.tosCache {
		c := make(map[string]bool, len(m))
		for a, v := range m {
			c[a] = v
		}
		out[prov] = c
	}
	return out
}

// Export sensitive actions
func (p *PolicyEngine) SnapshotSensitive() map[string]SensitiveAction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]SensitiveAction, len(p.sensitiveCache))
	for k, v := range p.sensitiveCache {
		out[k] = v
	}
	return out
}

// For debugging: pretty print policy caches as JSON
func (p *PolicyEngine) DebugDump() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	all := struct {
		Quotas    map[uint]AccountQuota
		TOS       map[string]map[string]bool
		Sensitives map[string]SensitiveAction
	}{
		Quotas:    p.quotasCache,
		TOS:       p.tosCache,
		Sensitives: p.sensitiveCache,
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	return string(b)
}