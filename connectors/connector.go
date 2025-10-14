package connectors

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

/*
Enterprise-grade Connector core.

Responsibilities:
 - Provide unified GatewayRequest/GatewayResponse types
 - Manage Connectors registry and dispatch operations
 - Vault (file-backed AES-GCM) for credentials
 - Async job management with optional persistence (pluggable AsyncStore)
 - Policy engine hook (rate limits, geo)
 - Telemetry hook (OTel/Prometheus) via interface
 - Self-healing with failover support
 - Pluggable AdapterGenerator, AutomationService, Captcha/2FA solvers

Design note:
 - The file contains default/no-op implementations so it builds and runs
   out-of-the-box; production integrations (Redis, OTel, etc.) should be
   provided by passing custom implementations into NewConnectorManager.
*/

// ----------------------------- Basic types ----------------------------------

type Operation string

const (
	OpDiscover Operation = "discover"
	OpList     Operation = "list"
	OpManage   Operation = "manage"
	OpCustom   Operation = "custom"
)

// GatewayRequest: unified request passed from orchestration layer (model)
type GatewayRequest struct {
	RequestID    string                 `json:"request_id"`
	Ctx          context.Context        `json:"-"`
	TraceID      string                 `json:"trace_id,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	ServiceName  string                 `json:"service_name"`
	Credentials  map[string]interface{} `json:"credentials,omitempty"`
	Operation    Operation              `json:"operation"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceSpec map[string]interface{} `json:"resource_spec,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
	Policy       map[string]interface{} `json:"policy,omitempty"`
	Budget       float64                `json:"budget,omitempty"`
	Deadline     time.Time              `json:"deadline,omitempty"`
	Async        bool                   `json:"async,omitempty"`
	CallbackURL  string                 `json:"callback_url,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ResourceMetadata: normalized resource description
type ResourceMetadata struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Region    string                 `json:"region,omitempty"`
	Status    string                 `json:"status,omitempty"`
	Tags      map[string]string      `json:"tags,omitempty"`
	CreatedAt time.Time              `json:"created_at,omitempty"`
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	Meta      map[string]interface{} `json:"meta,omitempty"`
}

// GatewayResponse: unified response from connector
type GatewayResponse struct {
	Success    bool                   `json:"success"`
	StatusCode int                    `json:"status_code,omitempty"`
	ErrorCode  int                    `json:"error_code,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Message    string                 `json:"message,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Resources  []ResourceMetadata     `json:"resources,omitempty"`
	AsyncID    string                 `json:"async_id,omitempty"`
	TraceID    string                 `json:"trace_id,omitempty"`
	Metrics    map[string]interface{} `json:"metrics,omitempty"`
	Timestamp  time.Time              `json:"timestamp,omitempty"`
}

var (
	ErrNotFound       = errors.New("not found")
	ErrInvalidRequest = errors.New("invalid request")
	ErrAuthFailed     = errors.New("authentication failed")
)

const (
	ErrorAuthFailed      = 1001
	ErrorResourceMissing = 2001
	ErrorTimeout         = 3001
	ErrorInternal        = 9001
)

// ----------------------------- Hooks & Connectors ---------------------------

type BeforeRequestHook func(req *GatewayRequest) error
type AfterResponseHook func(req *GatewayRequest, res *GatewayResponse) error

type ConnectorGateway interface {
	Name() string
	SupportedOperations() []Operation
	DiscoverServices(req GatewayRequest) (GatewayResponse, error)
	ListResources(req GatewayRequest) (GatewayResponse, error)
	ManageResource(req GatewayRequest) (GatewayResponse, error)
	CustomOperation(req GatewayRequest) (GatewayResponse, error)
	PollAsync(req GatewayRequest, asyncID string) (GatewayResponse, error)
}

type HookableConnector interface {
	RegisterBeforeHook(h BeforeRequestHook)
	RegisterAfterHook(h AfterResponseHook)
}

type BaseConnector struct {
	beforeHooks []BeforeRequestHook
	afterHooks  []AfterResponseHook
	hooksMu     sync.RWMutex
	Async       AsyncStore
}

func NewBaseConnector() *BaseConnector {
	return &BaseConnector{
		beforeHooks: []BeforeRequestHook{},
		afterHooks:  []AfterResponseHook{},
		Async:       NewInMemoryAsyncStore(), // default
	}
}

func (b *BaseConnector) RegisterBeforeHook(h BeforeRequestHook) {
	b.hooksMu.Lock()
	b.beforeHooks = append(b.beforeHooks, h)
	b.hooksMu.Unlock()
}

func (b *BaseConnector) RegisterAfterHook(h AfterResponseHook) {
	b.hooksMu.Lock()
	b.afterHooks = append(b.afterHooks, h)
	b.hooksMu.Unlock()
}

func (b *BaseConnector) runBefore(req *GatewayRequest) error {
	b.hooksMu.RLock()
	hooks := append([]BeforeRequestHook(nil), b.beforeHooks...)
	b.hooksMu.RUnlock()
	for _, h := range hooks {
		if err := h(req); err != nil {
			return err
		}
	}
	return nil
}

func (b *BaseConnector) runAfter(req *GatewayRequest, res *GatewayResponse) error {
	b.hooksMu.RLock()
	hooks := append([]AfterResponseHook(nil), b.afterHooks...)
	b.hooksMu.RUnlock()
	for _, h := range hooks {
		if err := h(req, res); err != nil {
			return err
		}
	}
	return nil
}

// ----------------------------- Utilities -----------------------------------

func GenerateSecureID(prefix string) string {
	b := make([]byte, 12)
	_, _ = crand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

func GenerateRequestID() string { return GenerateSecureID("req") }

func MaskCredentials(creds map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range creds {
		switch x := v.(type) {
		case string:
			if len(x) > 8 {
				out[k] = x[:4] + "..." + x[len(x)-4:]
			} else {
				out[k] = "****"
			}
		default:
			out[k] = "REDACTED"
		}
	}
	return out
}

func SignRequestHMAC(secret string, req *GatewayRequest) (string, error) {
	if secret == "" || req == nil {
		return "", errors.New("missing secret or request")
	}
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ----------------------------- Async Store (pluggable) ----------------------

/*
 AsyncStore is the abstraction for starting/polling async jobs.
 Default implementation is in-memory + optional file persistence.

 For production (distributed) replace with Redis/Cassandra-backed implementation
 that conforms to AsyncStore.
*/
type AsyncStore interface {
	StartJob(op func() GatewayResponse) string
	PollJob(id string) (GatewayResponse, bool)
	Cleanup()
	Shutdown()
}

type inMemoryJob struct {
	Result GatewayResponse `json:"result"`
	Done   bool            `json:"done"`
	At     time.Time       `json:"at"`
	TTL    time.Time       `json:"ttl"`
}

// InMemoryAsyncStore is the default AsyncStore (file persistence optional)
type InMemoryAsyncStore struct {
	mu       sync.RWMutex
	store    map[string]*inMemoryJob
	dir      string
	ttl      time.Duration
	cleanup  chan struct{}
	shutdown chan struct{}
}

func NewInMemoryAsyncStore() *InMemoryAsyncStore {
	dir := os.Getenv("CONNECTOR_ASYNC_DIR")
	a := &InMemoryAsyncStore{
		store:    map[string]*inMemoryJob{},
		dir:      dir,
		ttl:      24 * time.Hour,
		cleanup:  make(chan struct{}),
		shutdown: make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

func (a *InMemoryAsyncStore) persist(id string, job *inMemoryJob) {
	if a.dir == "" || job == nil {
		return
	}
	data, _ := json.Marshal(job)
	_ = os.MkdirAll(a.dir, 0o700)
	tmp := filepath.Join(a.dir, id+".json.tmp")
	_ = os.WriteFile(tmp, data, 0o600)
	_ = os.Rename(tmp, filepath.Join(a.dir, id+".json"))
}

func (a *InMemoryAsyncStore) load(id string) (*inMemoryJob, bool) {
	if a.dir == "" {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(a.dir, id+".json"))
	if err != nil {
		return nil, false
	}
	var j inMemoryJob
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, false
	}
	return &j, true
}

func (a *InMemoryAsyncStore) StartJob(op func() GatewayResponse) string {
	id := GenerateSecureID("async")
	now := time.Now().UTC()
	job := &inMemoryJob{Done: false, At: now, TTL: now.Add(a.ttl)}
	a.mu.Lock()
	a.store[id] = job
	a.mu.Unlock()
	a.persist(id, job)

	go func() {
		res := op()
		a.mu.Lock()
		j, ok := a.store[id]
		if !ok {
			j = &inMemoryJob{}
			a.store[id] = j
		}
		j.Result = res
		j.Done = true
		j.At = time.Now().UTC()
		j.TTL = j.At.Add(a.ttl)
		a.persist(id, j)
		a.mu.Unlock()
	}()
	return id
}

func (a *InMemoryAsyncStore) PollJob(id string) (GatewayResponse, bool) {
	a.mu.RLock()
	j, ok := a.store[id]
	a.mu.RUnlock()
	if !ok && a.dir != "" {
		if jj, found := a.load(id); found {
			return jj.Result, jj.Done
		}
	}
	if !ok {
		return GatewayResponse{}, false
	}
	return j.Result, j.Done
}

func (a *InMemoryAsyncStore) Cleanup() {
	cut := time.Now().Add(-a.ttl)
	a.mu.Lock()
	for k, v := range a.store {
		if v.At.Before(cut) || time.Now().After(v.TTL) {
			delete(a.store, k)
			if a.dir != "" {
				_ = os.Remove(filepath.Join(a.dir, k+".json"))
			}
		}
	}
	a.mu.Unlock()
}

func (a *InMemoryAsyncStore) cleanupLoop() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.Cleanup()
		case <-a.shutdown:
			return
		}
	}
}

func (a *InMemoryAsyncStore) Shutdown() {
	close(a.shutdown)
}

/*
 NOTE: For production-scale distributed async job handling, implement AsyncStore backed by:
  - Redis (streams / hash storage) OR
  - Kafka / durable store + worker pool
 Provide an implementation and pass it into ConnectorManager (via constructor).
*/

// ----------------------------- Policy Engine --------------------------------

type PolicyEngine interface {
	// Allow returns (allowed, reason). Should be fast and thread-safe.
	Allow(req *GatewayRequest) (bool, string)
}

// Simple in-memory token-bucket + geo-rule engine (default)
type InMemoryPolicyEngine struct {
	mu          sync.Mutex
	ratePerMin  map[string]int           // service => allowed requests per minute
	tokens      map[string]float64       // service => current tokens
	lastRefill  map[string]time.Time     // service => last refill time
	geoBlacklist map[string]struct{}     // blacklisted geo codes
}

func NewInMemoryPolicyEngine() *InMemoryPolicyEngine {
	return &InMemoryPolicyEngine{
		ratePerMin:  map[string]int{},
		tokens:      map[string]float64{},
		lastRefill:  map[string]time.Time{},
		geoBlacklist: map[string]struct{}{},
	}
}

// SetRate allows configuring allowed QPS per service (per minute here)
func (p *InMemoryPolicyEngine) SetRate(service string, perMinute int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ratePerMin[service] = perMinute
	p.tokens[service] = float64(perMinute)
	p.lastRefill[service] = time.Now()
}

func (p *InMemoryPolicyEngine) BlacklistGeo(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.geoBlacklist[code] = struct{}{}
}

func (p *InMemoryPolicyEngine) Allow(req *GatewayRequest) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// geo check
	if req.Metadata != nil {
		if g, ok := req.Metadata["geo"].(string); ok && g != "" {
			if _, bad := p.geoBlacklist[g]; bad {
				return false, "geo-blocked"
			}
		}
	}
	// rate limit token-bucket per minute
	limit, ok := p.ratePerMin[req.ServiceName]
	if !ok || limit <= 0 {
		// no limit configured -> allow
		return true, ""
	}
	now := time.Now()
	last := p.lastRefill[req.ServiceName]
	if last.IsZero() {
		last = now
		p.lastRefill[req.ServiceName] = now
	}
	elapsed := now.Sub(last).Seconds()
	// refill tokens proportional to elapsed (per minute)
	refill := elapsed * (float64(limit) / 60.0)
	p.tokens[req.ServiceName] += refill
	if p.tokens[req.ServiceName] > float64(limit) {
		p.tokens[req.ServiceName] = float64(limit)
	}
	p.lastRefill[req.ServiceName] = now
	if p.tokens[req.ServiceName] >= 1.0 {
		p.tokens[req.ServiceName] -= 1.0
		return true, ""
	}
	return false, "rate-limited"
}

// ----------------------------- Telemetry (pluggable) -------------------------

type Telemetry interface {
	RecordMetric(name string, value float64, labels map[string]string)
	StartSpan(ctx context.Context, name string) Span
}

type Span interface {
	End()
	SetAttribute(k, v string)
}

// NoopTelemetry is default (does nothing). Replace with OTel/Prometheus impl.
type NoopTelemetry struct{}

func (n *NoopTelemetry) RecordMetric(name string, value float64, labels map[string]string) {
	// noop
}
func (n *NoopTelemetry) StartSpan(ctx context.Context, name string) Span { return &NoopSpan{} }

type NoopSpan struct{}

func (n *NoopSpan) End()                             {}
func (n *NoopSpan) SetAttribute(k, v string)         {}

// ----------------------------- Captcha / 2FA / Automation -------------------

type AdapterGenerator interface {
	GenerateAdapter(service string, sample map[string]interface{}) (ConnectorGateway, error)
}

type AIAdapterGenerator struct{}

func (a *AIAdapterGenerator) GenerateAdapter(service string, sample map[string]interface{}) (ConnectorGateway, error) {
	// placeholder — production should implement a real generator
	return NewGenericConnector(service), nil
}

type AutomationService interface {
	ExecuteUIFlow(ctx context.Context, creds map[string]interface{}, steps []map[string]interface{}) GatewayResponse
}

type DummyAutomation struct{}

func (d *DummyAutomation) ExecuteUIFlow(ctx context.Context, creds map[string]interface{}, steps []map[string]interface{}) GatewayResponse {
	return StandardizeResponse(GatewayResponse{
		Success: true,
		Message: "automation executed (dummy)",
		Data:    map[string]interface{}{"steps_executed": len(steps)},
	})
}

type CaptchaSolver interface {
	Solve(ctx context.Context, image []byte) (string, error)
}

type DummyCaptchaSolver struct{}

func (d *DummyCaptchaSolver) Solve(ctx context.Context, image []byte) (string, error) { return "solved-captcha-dummy", nil }

type TwoFASolver interface {
	Solve2FA(ctx context.Context, method string, challenge map[string]interface{}) (string, error)
}

type Dummy2FASolver struct{}

func (d *Dummy2FASolver) Solve2FA(ctx context.Context, method string, challenge map[string]interface{}) (string, error) {
	return "2fa-dummy-code", nil
}

// ----------------------------- Self-healing & Failover -----------------------

type SelfHealingManager struct {
	mu        sync.RWMutex
	failures  map[string]int
	lastFail  map[string]time.Time
	recoverCh chan string
	ttl       time.Duration
	// Failovers: map service -> list of alternative connector names (ordered)
	Failovers map[string][]string
}

func NewSelfHealingManager() *SelfHealingManager {
	m := &SelfHealingManager{
		failures:  map[string]int{},
		lastFail:  map[string]time.Time{},
		recoverCh: make(chan string, 100),
		ttl:       24 * time.Hour,
		Failovers: map[string][]string{},
	}
	go m.recoveryLoop()
	return m
}

// RegisterFailure increases failure count and may queue recovery actions.
func (s *SelfHealingManager) RegisterFailure(connectorName string) {
	s.mu.Lock()
	s.failures[connectorName]++
	s.lastFail[connectorName] = time.Now().UTC()
	if s.failures[connectorName] >= 3 {
		select {
		case s.recoverCh <- connectorName:
		default:
		}
	}
	s.mu.Unlock()
}

// Reset resets failure state for connectorName.
func (s *SelfHealingManager) Reset(connectorName string) {
	s.mu.Lock()
	delete(s.failures, connectorName)
	delete(s.lastFail, connectorName)
	s.mu.Unlock()
}

func (s *SelfHealingManager) recoveryLoop() {
	for name := range s.recoverCh {
		time.Sleep(2 * time.Second)
		s.attemptRecovery(name)
	}
}

// attemptRecovery implements a simple backoff and reset; production can
// trigger more advanced recovery (restart service, re-register connector, etc).
func (s *SelfHealingManager) attemptRecovery(name string) {
	s.mu.Lock()
	cnt := s.failures[name]
	last := s.lastFail[name]
	failover := s.Failovers[name]
	s.mu.Unlock()

	if cnt == 0 {
		return
	}
	// exponential-ish backoff (1 * cnt seconds)
	delay := time.Duration(cnt) * time.Second
	if time.Since(last) < delay {
		time.Sleep(delay - time.Since(last))
	}

	// Attempt failover if configured (move traffic to alternatives)
	if len(failover) > 0 {
		// in a real system: mark primary as degraded and update routing
		log.Printf("self-heal: connector %s failed; configured failovers: %v\n", name, failover)
	}

	// For now: Reset state
	s.Reset(name)
}

// ----------------------------- Core Manager --------------------------------

type ConnectorManager struct {
	mu           sync.RWMutex
	connectors   map[string]ConnectorGateway
	vault        Vault
	adapterGen   AdapterGenerator
	automation   AutomationService
	captcha      CaptchaSolver
	twofa        TwoFASolver
	asyncStore   AsyncStore
	policy       PolicyEngine
	telemetry    Telemetry
	selfHeal     *SelfHealingManager
}

// NewConnectorManager constructs the manager. Pass nil to use defaults.
func NewConnectorManager(
	v Vault,
	ag AdapterGenerator,
	auto AutomationService,
	c CaptchaSolver,
	two TwoFASolver,
	async AsyncStore,
	p PolicyEngine,
	tel Telemetry,
) *ConnectorManager {
	// Vault key: prefer base64 in env CONNECTOR_VAULT_KEY, otherwise generate ephemeral key (warning)
	var key []byte
	if ks := os.Getenv("CONNECTOR_VAULT_KEY"); ks != "" {
		if b, err := base64.StdEncoding.DecodeString(ks); err == nil && len(b) >= 16 {
			key = b
		} else {
			log.Println("CONNECTOR_VAULT_KEY present but invalid; generating ephemeral key")
		}
	}
	if key == nil {
		key = make([]byte, 32)
		_, _ = io.ReadFull(crand.Reader, key)
	}

	// defaults
	if v == nil {
		path := os.Getenv("CONNECTOR_VAULT_PATH")
		if path == "" {
			path = "./.connector_vault.json"
		}
		v = NewFileVault(path, key)
	}
	if ag == nil {
		ag = &AIAdapterGenerator{}
	}
	if auto == nil {
		auto = &DummyAutomation{}
	}
	if c == nil {
		c = &DummyCaptchaSolver{}
	}
	if two == nil {
		two = &Dummy2FASolver{}
	}
	if async == nil {
		async = NewInMemoryAsyncStore()
	}
	if p == nil {
		p = NewInMemoryPolicyEngine()
	}
	if tel == nil {
		tel = &NoopTelemetry{}
	}
	return &ConnectorManager{
		connectors:   map[string]ConnectorGateway{},
		vault:        v,
		adapterGen:   ag,
		automation:   auto,
		captcha:      c,
		twofa:        two,
		asyncStore:   async,
		policy:       p,
		telemetry:    tel,
		selfHeal:     NewSelfHealingManager(),
	}
}

// RegisterConnector registers a named connector into the registry.
func (m *ConnectorManager) RegisterConnector(c ConnectorGateway) {
	if c == nil {
		return
	}
	m.mu.Lock()
	m.connectors[c.Name()] = c
	m.mu.Unlock()
	m.telemetry.RecordMetric("connector.register", 1, map[string]string{"name": c.Name()})
}

// GetConnector returns a connector by name.
func (m *ConnectorManager) GetConnector(name string) (ConnectorGateway, bool) {
	m.mu.RLock()
	c, ok := m.connectors[name]
	m.mu.RUnlock()
	return c, ok
}

// Execute executes a GatewayRequest (sync or async).
func (m *ConnectorManager) Execute(req GatewayRequest) (GatewayResponse, error) {
	if req.Ctx == nil {
		req.Ctx = context.Background()
	}
	if req.RequestID == "" {
		req.RequestID = GenerateRequestID()
	}
	req.CreatedAt = time.Now().UTC()

	// Telemetry: request received
	m.telemetry.RecordMetric("request.received", 1, map[string]string{"service": req.ServiceName, "op": string(req.Operation)})

	// Policy check
	if ok, reason := m.policy.Allow(&req); !ok {
		m.telemetry.RecordMetric("request.blocked.policy", 1, map[string]string{"service": req.ServiceName, "reason": reason})
		return StandardizeResponse(GatewayResponse{Success: false, Error: "policy blocked: " + reason, ErrorCode: ErrorInternal}), ErrInvalidRequest
	}

	// basic validation
	if err := ValidateBasicRequest(&req); err != nil {
		m.telemetry.RecordMetric("request.invalid", 1, map[string]string{"service": req.ServiceName})
		return StandardizeResponse(GatewayResponse{Success: false, Error: err.Error(), ErrorCode: ErrorInternal}), err
	}

	// get connector or generate adapter dynamically
	c, ok := m.GetConnector(req.ServiceName)
	if !ok {
		m.telemetry.RecordMetric("connector.missing", 1, map[string]string{"service": req.ServiceName})
		adapter, err := m.adapterGen.GenerateAdapter(req.ServiceName, req.Extra)
		if err == nil && adapter != nil {
			m.RegisterConnector(adapter)
			c = adapter
			ok = true
			m.telemetry.RecordMetric("adapter.generated", 1, map[string]string{"service": req.ServiceName})
		}
	}

	if !ok {
		// fallback to UI automation for manage/custom operations
		if req.Operation == OpManage || req.Operation == OpCustom {
			steps := []map[string]interface{}{{"action": "open_ui", "service": req.ServiceName}}
			res := m.automation.ExecuteUIFlow(req.Ctx, req.Credentials, steps)
			m.telemetry.RecordMetric("automation.fallback", 1, map[string]string{"service": req.ServiceName})
			return StandardizeResponse(res), nil
		}
		// record failure and return not found
		m.selfHeal.RegisterFailure(req.ServiceName)
		m.telemetry.RecordMetric("connector.notfound", 1, map[string]string{"service": req.ServiceName})
		return StandardizeResponse(GatewayResponse{
			Success:   false,
			Error:     "connector not found",
			ErrorCode: ErrorResourceMissing,
		}), ErrNotFound
	}

	// Async support
	if req.Async {
		asyncID := m.asyncStore.StartJob(func() GatewayResponse { return m.dispatchToConnectorWithTelemetry(c, req) })
		m.telemetry.RecordMetric("async.started", 1, map[string]string{"service": req.ServiceName, "async_id": asyncID})
		return StandardizeResponse(GatewayResponse{Success: true, AsyncID: asyncID, Message: "operation started async"}), nil
	}

	// Sync dispatch
	res := m.dispatchToConnectorWithTelemetry(c, req)
	if !res.Success {
		// register failure and attempt failover if configured
		m.selfHeal.RegisterFailure(req.ServiceName)
		// if failovers configured, attempt to use alternative connector(s)
		m.mu.RLock()
		failovers := m.selfHeal.Failovers[req.ServiceName]
		m.mu.RUnlock()
		if len(failovers) > 0 {
			for _, alt := range failovers {
				if altC, ok := m.GetConnector(alt); ok {
					log.Printf("attempting failover: %s -> %s\n", req.ServiceName, alt)
					altReq := req
					altReq.ServiceName = alt
					altRes := m.dispatchToConnectorWithTelemetry(altC, altReq)
					if altRes.Success {
						m.telemetry.RecordMetric("failover.success", 1, map[string]string{"from": req.ServiceName, "to": alt})
						return StandardizeResponse(altRes), nil
					}
				}
			}
			m.telemetry.RecordMetric("failover.failed", 1, map[string]string{"service": req.ServiceName})
		}
	} else {
		// success: reset heal state
		m.selfHeal.Reset(req.ServiceName)
	}
	return StandardizeResponse(res), nil
}

func (m *ConnectorManager) PollAsync(asyncID string) (GatewayResponse, bool) {
	res, done := m.asyncStore.PollJob(asyncID)
	return res, done
}

func (m *ConnectorManager) dispatchToConnectorWithTelemetry(c ConnectorGateway, req GatewayRequest) GatewayResponse {
	start := time.Now()
	span := m.telemetry.StartSpan(req.Ctx, fmt.Sprintf("connector.%s.%s", c.Name(), req.Operation))
	span.SetAttribute("service", req.ServiceName)
	defer span.End()

	res := m.dispatchToConnector(c, req)
	lat := time.Since(start).Seconds()
	m.telemetry.RecordMetric("operation.duration_seconds", lat, map[string]string{"service": req.ServiceName, "op": string(req.Operation)})
	if !res.Success {
		m.telemetry.RecordMetric("operation.failure", 1, map[string]string{"service": req.ServiceName, "op": string(req.Operation)})
	} else {
		m.telemetry.RecordMetric("operation.success", 1, map[string]string{"service": req.ServiceName, "op": string(req.Operation)})
	}
	return res
}

func (m *ConnectorManager) dispatchToConnector(c ConnectorGateway, req GatewayRequest) GatewayResponse {
	// run connector hooks (if it implements HookableConnector)
	if hc, ok := c.(HookableConnector); ok {
		_ = hc // we rely on connector implementation to manage hooks internally
	}
	switch req.Operation {
	case OpDiscover:
		if r, err := c.DiscoverServices(req); err == nil {
			return r
		} else {
			return StandardizeResponse(GatewayResponse{Success: false, Error: err.Error(), ErrorCode: ErrorInternal})
		}
	case OpList:
		if r, err := c.ListResources(req); err == nil {
			return r
		} else {
			return StandardizeResponse(GatewayResponse{Success: false, Error: err.Error(), ErrorCode: ErrorInternal})
		}
	case OpManage:
		if r, err := c.ManageResource(req); err == nil {
			return r
		} else {
			return StandardizeResponse(GatewayResponse{Success: false, Error: err.Error(), ErrorCode: ErrorInternal})
		}
	case OpCustom:
		if r, err := c.CustomOperation(req); err == nil {
			return r
		} else {
			return StandardizeResponse(GatewayResponse{Success: false, Error: err.Error(), ErrorCode: ErrorInternal})
		}
	default:
		return StandardizeResponse(GatewayResponse{Success: false, Error: "unsupported operation", ErrorCode: ErrorInternal})
	}
}

// ----------------------------- File-backed Vault ----------------------------

type Vault interface {
	Store(key string, creds map[string]interface{}) error
	Retrieve(key string) (map[string]interface{}, error)
	Encrypt(data []byte) (string, error)
	Decrypt(enc string) ([]byte, error)
}

type FileVault struct {
	key  []byte
	path string
	mu   sync.RWMutex
	mem  map[string]string
}

func NewFileVault(path string, key []byte) *FileVault {
	v := &FileVault{
		key:  key,
		path: path,
		mem:  map[string]string{},
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = v.load()
	return v
}

func (v *FileVault) load() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := os.ReadFile(v.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			v.mem = map[string]string{}
			return nil
		}
		return err
	}
	var stored map[string]string
	if err := json.Unmarshal(b, &stored); err != nil {
		return err
	}
	v.mem = stored
	return nil
}

func (v *FileVault) persist() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	b, err := json.Marshal(v.mem)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func (v *FileVault) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ct := aesgcm.Seal(nil, nonce, data, nil)
	out := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (v *FileVault) Decrypt(enc string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, errors.New("invalid payload")
	}
	nonce := b[:12]
	ct := b[12:]
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ct, nil)
}

func (v *FileVault) Store(key string, creds map[string]interface{}) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	enc, err := v.Encrypt(b)
	if err != nil {
		return err
	}
	v.mem[key] = enc
	return v.persist()
}

func (v *FileVault) Retrieve(key string) (map[string]interface{}, error) {
	v.mu.RLock()
	enc, ok := v.mem[key]
	v.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	b, err := v.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ----------------------------- Generic connector fallback -------------------

type GenericConnector struct {
	*BaseConnector
	name string
}

func NewGenericConnector(name string) *GenericConnector {
	b := NewBaseConnector()
	// attach manager's async store by default? keep connector-local store
	return &GenericConnector{BaseConnector: b, name: name}
}

func (g *GenericConnector) Name() string { return g.name }

func (g *GenericConnector) SupportedOperations() []Operation { return []Operation{OpDiscover, OpList, OpManage, OpCustom} }

func (g *GenericConnector) DiscoverServices(req GatewayRequest) (GatewayResponse, error) {
	out := map[string]interface{}{"services": []string{"generic-resource"}}
	return StandardizeResponse(GatewayResponse{Success: true, Data: out}), nil
}

func (g *GenericConnector) ListResources(req GatewayRequest) (GatewayResponse, error) {
	rs := []ResourceMetadata{{ID: GenerateSecureID(g.name), Name: "generic", Type: req.ResourceType}}
	return StandardizeResponse(GatewayResponse{Success: true, Resources: rs}), nil
}

func (g *GenericConnector) ManageResource(req GatewayRequest) (GatewayResponse, error) {
	return StandardizeResponse(GatewayResponse{Success: true, Message: "managed", Data: map[string]interface{}{"spec": req.ResourceSpec}}), nil
}

func (g *GenericConnector) CustomOperation(req GatewayRequest) (GatewayResponse, error) {
	return StandardizeResponse(GatewayResponse{Success: true, Message: "custom executed", Data: req.Extra}), nil
}

func (g *GenericConnector) PollAsync(req GatewayRequest, asyncID string) (GatewayResponse, error) {
	// default connector uses its own Async store
	if g.Async == nil {
		g.Async = NewInMemoryAsyncStore()
	}
	if res, ok := g.Async.PollJob(asyncID); ok {
		return res, nil
	}
	return StandardizeResponse(GatewayResponse{Success: false, Error: "not found", ErrorCode: ErrorResourceMissing}), ErrNotFound
}