// internal/scaling/predictive_scaling.go
// Production-ready Predictive Scaling & Infra Preparation Engine (final hardened)
// - Safe defaults: DryRun=true, EnableAutoBootstrap=false
// - Pluggable leader election: File (flock) fallback + Redis-based leader election implemented here
// - Pluggable shared persistence Store: FileStore fallback + RedisStore implemented here
// - Zero-Trust verification: Noop (reject), AttestationVerifier, HMACVerifier (shared secret) implemented
// - AutoBootstrap must be routed to an external infra-controller (HTTP helper included)
// - Input validation, MaxAttempts enforcement, structured JSON logs, Prometheus metrics
// - Pluggable AnomalyDetector, Topology, PolicyAdjuster, ReinforcementLearner
//
// NOTE: This file is intended to be the final "library" artifact. To use in production you MUST:
//  - Provide a shared Store (Redis/DB) if running >1 replica
//  - Provide a robust LeaderElector (Redis/etcd/K8s) if running >1 replica
//  - Configure a real ZeroTrustVerifier (HMACVerifier/attestation service)
//  - Use an external infra-controller that performs cloud/k8s operations (AutoBootstrapHTTP helper included)
//  - Configure Prometheus scraping and Alertmanager rules for critical metrics
//
// External requirements (not embedded in code):
//  - Redis server if you enable RedisStore/RedisLeaderElector
//  - Infra-controller endpoint (secure) for AutoBootstrapHTTP
//
// Build: requires go modules for github.com/go-redis/redis/v8 and github.com/prometheus/client_golang/prometheus

package scaling

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
)

// -------------------- Types & Interfaces --------------------

type ScalingSignal struct {
	Service   string
	CPU       float64 // normalized (0..1 suggested)
	RAM       float64 // in MB
	Timestamp time.Time
}

type Predictor interface {
	Predict(ctx context.Context, history []ScalingSignal, horizon time.Duration) (cpu float64, ram float64, err error)
}

type BootstrapFunc func(ctx context.Context, targetNode string, requirements map[string]interface{}) error

type MetricHook interface {
	RecordPrediction(service string, cpu, ram float64)
	RecordBootstrapAttempt(service string, success bool, info string)
	RecordBackoff(service string, backoff time.Duration)
	RecordRateLimited(service string)
	RecordAnomaly(service string, score float64)
	RecordRLUpdate(service string, params map[string]float64)
}

// Node representation
type Node struct {
	ID           string
	CPUAvailable float64
	RAMAvailable float64
	Region       string
	Labels       map[string]string
}

type NodeSelector interface {
	SelectNode(requirements map[string]interface{}) (nodeID string, ok bool)
	RegisterNode(n Node)
	ListNodes() []Node
}

type CostEstimator interface {
	EstimateCost(requirements map[string]interface{}) float64
	EstimatePenalty(service string, cpu, ram float64) float64
}

// -------------------- Anomaly Detector (pluggable) --------------------

type AnomalyDetector interface {
	Detect(history []ScalingSignal) (isAnomaly bool, score float64)
	Feed(obs ScalingSignal)
}

type ZScoreDetector struct {
	mu        sync.Mutex
	window    int
	threshold float64
}

func NewZScoreDetector(window int, threshold float64) *ZScoreDetector {
	if window <= 0 {
		window = 50
	}
	if threshold <= 0 {
		threshold = 3.0
	}
	return &ZScoreDetector{window: window, threshold: threshold}
}

func (z *ZScoreDetector) Detect(history []ScalingSignal) (bool, float64) {
	if len(history) < 5 {
		return false, 0.0
	}
	cpus := make([]float64, 0, len(history))
	for _, s := range history {
		cpus = append(cpus, s.CPU)
	}
	mean := 0.0
	for _, v := range cpus {
		mean += v
	}
	mean /= float64(len(cpus))
	var sd float64
	for _, v := range cpus {
		sd += (v - mean) * (v - mean)
	}
	sd = math.Sqrt(sd / float64(len(cpus)))
	latest := cpus[len(cpus)-1]
	var zscore float64
	if sd == 0 {
		zscore = 0
	} else {
		zscore = math.Abs((latest - mean) / sd)
	}
	is := zscore > z.threshold
	return is, zscore
}

func (z *ZScoreDetector) Feed(obs ScalingSignal) {
	// stateless feed (no-op)
}

// -------------------- Topology Learning --------------------

type Topology struct {
	mu              sync.RWMutex
	serviceToNodes  map[string]map[string]int
	nodeLatencyHist map[string][]float64
}

func NewTopology() *Topology {
	return &Topology{
		serviceToNodes:  make(map[string]map[string]int),
		nodeLatencyHist: make(map[string][]float64),
	}
}

func (t *Topology) RecordPlacement(service, nodeID string, latencyMs float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.serviceToNodes[service]; !ok {
		t.serviceToNodes[service] = make(map[string]int)
	}
	t.serviceToNodes[service][nodeID]++
	if latencyMs >= 0 {
		t.nodeLatencyHist[nodeID] = append(t.nodeLatencyHist[nodeID], latencyMs)
		if len(t.nodeLatencyHist[nodeID]) > 500 {
			t.nodeLatencyHist[nodeID] = t.nodeLatencyHist[nodeID][len(t.nodeLatencyHist[nodeID])-500:]
		}
	}
}

func (t *Topology) ScoreNodeForService(service, nodeID string) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	if m, ok := t.serviceToNodes[service]; ok {
		count = m[nodeID]
	}
	lat := 1000.0
	if hist, ok := t.nodeLatencyHist[nodeID]; ok && len(hist) > 0 {
		sum := 0.0
		for _, v := range hist {
			sum += v
		}
		lat = sum / float64(len(hist))
	}
	return float64(count) / (math.Log(lat+2.0))
}

// -------------------- Policy Adjuster --------------------

type PolicyAdjuster interface {
	AdjustFor(service string, meta map[string]any, baseCfg *Config) (adjusted Config)
}

type DefaultPolicyAdjuster struct{}

func (d *DefaultPolicyAdjuster) AdjustFor(service string, meta map[string]any, baseCfg *Config) Config {
	out := *baseCfg
	now := time.Now().UTC()
	h := now.Hour()
	weekday := now.Weekday()
	if h >= 8 && h <= 18 && weekday >= 1 && weekday <= 5 {
		out.CPUCritical = math.Max(0.6, baseCfg.CPUCritical-0.1)
		out.RAMCritical = math.Max(1024, baseCfg.RAMCritical*0.9)
	} else {
		out.CPUCritical = math.Min(0.95, baseCfg.CPUCritical+0.05)
		out.RAMCritical = baseCfg.RAMCritical * 1.1
	}
	if ut, ok := meta["user_type"].(string); ok {
		if ut == "premium" {
			out.CPUCritical = math.Max(0.5, out.CPUCritical-0.15)
		}
	}
	return out
}

// -------------------- Zero-Trust Verifier --------------------

type ZeroTrustVerifier interface {
	Verify(ctx context.Context, targetNode string, evidence map[string]any) (bool, string)
}

// NoopVerifier now DENIES by default to force explicit configuration
type NoopVerifier struct{}

func (n *NoopVerifier) Verify(ctx context.Context, targetNode string, evidence map[string]any) (bool, string) {
	return false, "noop-verifier-not-allowed"
}

// AttestationVerifier checks presence in AcceptList (simple)
type AttestationVerifier struct {
	AcceptList map[string]bool
}

func (a *AttestationVerifier) Verify(ctx context.Context, targetNode string, evidence map[string]any) (bool, string) {
	if token, ok := evidence["attestation_token"].(string); ok && token != "" {
		if a.AcceptList != nil {
			if _, ok := a.AcceptList[targetNode]; !ok {
				return false, "node not in accept list"
			}
		}
		return true, "token-ok"
	}
	return false, "no-token"
}

// HMACVerifier validates attestation tokens produced by a trusted signer using shared secret.
// Token format expected: hex(HMAC_SHA256(nodeID + ":" + ts)) + ":" + ts
type HMACVerifier struct {
	Secret       []byte
	MaxTokenAge  time.Duration
	AllowSkew    time.Duration
	ExpectedHost string // optional expected node identifier pattern
}

func NewHMACVerifier(secret string) *HMACVerifier {
	return &HMACVerifier{Secret: []byte(secret), MaxTokenAge: 5 * time.Minute, AllowSkew: 1 * time.Minute}
}

func (h *HMACVerifier) Verify(ctx context.Context, targetNode string, evidence map[string]any) (bool, string) {
	raw, ok := evidence["attestation_token"].(string)
	if !ok || raw == "" {
		return false, "missing token"
	}
	parts := make([]string, 0)
	parts = append(parts, "")
	// token can be "hex:ts" or "hex:node:ts" - support both
	// split by ':'
	fields := splitN(raw, ":", 3)
	if len(fields) < 2 {
		return false, "token malformed"
	}
	var hexmac, tsStr string
	if len(fields) == 2 {
		hexmac = fields[0]
		tsStr = fields[1]
	} else {
		// fields[0]=hexmac, fields[1]=node, fields[2]=ts
		hexmac = fields[0]
		// optionally validate node matches targetNode
		if fields[1] != "" && targetNode != "" && fields[1] != targetNode {
			return false, "node mismatch"
		}
		tsStr = fields[2]
	}
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return false, "invalid timestamp"
	}
	if time.Since(ts) > h.MaxTokenAge+ h.AllowSkew {
		return false, "token expired"
	}
	// compute expected HMAC over targetNode + ":" + tsStr
	message := targetNode + ":" + tsStr
	m := hmac.New(sha256.New, h.Secret)
	_, _ = m.Write([]byte(message))
	expected := hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(hexmac)) {
		return false, "hmac mismatch"
	}
	return true, "hmac-ok"
}

func splitN(s, sep string, n int) []string {
	res := make([]string, 0, n)
	start := 0
	for i := 0; i < n-1; i++ {
		idx := indexOf(s, sep, start)
		if idx == -1 {
			res = append(res, s[start:])
			return res
		}
		res = append(res, s[start:idx])
		start = idx + len(sep)
	}
	res = append(res, s[start:])
	return res
}

func indexOf(s, sep string, start int) int {
	if start >= len(s) {
		return -1
	}
	idx := start + stringsIndex(s[start:], sep)
	if idx < start {
		return -1
	}
	return idx
}

// stringsIndex wrapper to avoid importing strings at many places; using standard library below:
func stringsIndex(s, sep string) int {
	return bytes.Index([]byte(s), []byte(sep))
}

// -------------------- Reinforcement Learner --------------------

type ReinforcementLearner struct {
	mu             sync.Mutex
	alpha          float64
	horizonSeconds float64
	learningRate   float64
	bestReward     float64
	epsilon        float64
	updates        []map[string]any
}

func NewReinforcementLearner(alpha float64, horizon time.Duration) *ReinforcementLearner {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.25
	}
	return &ReinforcementLearner{
		alpha:          alpha,
		horizonSeconds: horizon.Seconds(),
		learningRate:   0.05,
		bestReward:     -1e9,
		epsilon:        0.1,
	}
}

func (r *ReinforcementLearner) Suggest() (alpha float64, horizon time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.alpha, time.Duration(r.horizonSeconds) * time.Second
}

func (r *ReinforcementLearner) Update(service string, reward float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reward > r.bestReward {
		r.bestReward = reward
		r.alpha = r.alpha*(1-r.learningRate) + r.learningRate*(r.alpha*(1+0.02))
		r.horizonSeconds = r.horizonSeconds * (1 - r.learningRate*0.1)
	} else {
		if rand.Float64() < r.epsilon {
			r.alpha = clamp(r.alpha*(1+rand.NormFloat64()*0.02), 0.05, 0.95)
			r.horizonSeconds = clamp(r.horizonSeconds*(1+rand.NormFloat64()*0.05), 1, 3600)
		}
	}
	r.updates = append(r.updates, map[string]any{"ts": time.Now().UTC(), "service": service, "alpha": r.alpha, "horizon": r.horizonSeconds, "reward": reward})
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// -------------------- Store interface & FileStore implementation --------------------

type Store interface {
	Save(data []byte) error
	Load() ([]byte, error)
}

// FileStore (local) - safe atomic rename
type FileStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore { return &FileStore{Path: path} }

func (fs *FileStore) Save(data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	tmp := fs.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fs.Path)
}

func (fs *FileStore) Load() ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	b, err := os.ReadFile(fs.Path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// RedisStore - shared store for multi-replica environments
type RedisStore struct {
	Client *redis.Client
	Key    string
	Ctx    context.Context
}

func NewRedisStore(addr, password, key string, db int) *RedisStore {
	client := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	return &RedisStore{Client: client, Key: key, Ctx: context.Background()}
}

func (rs *RedisStore) Save(data []byte) error {
	return rs.Client.Set(rs.Ctx, rs.Key, data, 0).Err()
}

func (rs *RedisStore) Load() ([]byte, error) {
	val, err := rs.Client.Get(rs.Ctx, rs.Key).Bytes()
	if err != nil {
		return nil, err
	}
	return val, nil
}

// -------------------- Leader elector interface & implementations --------------------

type LeaderElector interface {
	Acquire(ctx context.Context) (bool, error)
	Release() error
	IsLeader() bool
}

// FileLeaderElector (flock) - single-host fallback
type FileLeaderElector struct {
	path   string
	f      *os.File
	isLead uint32
}

func NewFileLeaderElector(path string) *FileLeaderElector { return &FileLeaderElector{path: path} }

func (fe *FileLeaderElector) Acquire(ctx context.Context) (bool, error) {
	f, err := os.OpenFile(fe.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	// try flock exclusive non-blocking
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return false, nil
	}
	fe.f = f
	atomic.StoreUint32(&fe.isLead, 1)
	return true, nil
}

func (fe *FileLeaderElector) Release() error {
	if fe.f == nil {
		return nil
	}
	_ = syscall.Flock(int(fe.f.Fd()), syscall.LOCK_UN)
	err := fe.f.Close()
	fe.f = nil
	atomic.StoreUint32(&fe.isLead, 0)
	return err
}

func (fe *FileLeaderElector) IsLeader() bool { return atomic.LoadUint32(&fe.isLead) == 1 }

// RedisLeaderElector - distributed leader election using SET NX + TTL + renew
type RedisLeaderElector struct {
	Client    *redis.Client
	Key       string
	TTL       time.Duration
	ownerID   string
	cancel    context.CancelFunc
	isLeader  uint32
	ctx       context.Context
	lockMu    sync.Mutex
}

func NewRedisLeaderElector(redisAddr, redisPassword, key string, db int, ttl time.Duration) *RedisLeaderElector {
	client := redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPassword, DB: db})
	return &RedisLeaderElector{Client: client, Key: key, TTL: ttl, ownerID: fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())}
}

func (r *RedisLeaderElector) Acquire(ctx context.Context) (bool, error) {
	r.lockMu.Lock()
	defer r.lockMu.Unlock()
	cctx, cancel := context.WithCancel(context.Background())
	r.ctx = cctx
	ok, err := r.Client.SetNX(ctx, r.Key, r.ownerID, r.TTL).Result()
	if err != nil {
		cancel()
		return false, err
	}
	if !ok {
		cancel()
		return false, nil
	}
	atomic.StoreUint32(&r.isLeader, 1)
	// start renewer
	go r.renewer(cctx)
	r.cancel = cancel
	return true, nil
}

func (r *RedisLeaderElector) renewer(cctx context.Context) {
	ticker := time.NewTicker(r.TTL / 3)
	defer ticker.Stop()
	for {
		select {
		case <-cctx.Done():
			return
		case <-ticker.C:
			// refresh TTL only if we still own the key
			val, err := r.Client.Get(cctx, r.Key).Result()
			if err != nil {
				// lost leader or redis error; clear leadership
				atomic.StoreUint32(&r.isLeader, 0)
				return
			}
			if val != r.ownerID {
				atomic.StoreUint32(&r.isLeader, 0)
				return
			}
			_ = r.Client.Expire(cctx, r.Key, r.TTL).Err()
		}
	}
}

func (r *RedisLeaderElector) Release() error {
	r.lockMu.Lock()
	defer r.lockMu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	// delete key only if we own it (use Lua)
	script := redis.NewScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`)
	_, _ = script.Run(context.Background(), r.Client, []string{r.Key}, r.ownerID).Result()
	atomic.StoreUint32(&r.isLeader, 0)
	return nil
}

func (r *RedisLeaderElector) IsLeader() bool { return atomic.LoadUint32(&r.isLeader) == 1 }

// -------------------- Prometheus metrics --------------------

var (
	predCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "predictive_predictions_total",
		Help: "Predictions emitted",
	}, []string{"service"})
	bootstrapCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "predictive_bootstraps_total",
		Help: "Bootstrap attempts",
	}, []string{"service", "status"})
	anomalyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "predictive_anomalies_total",
		Help: "Anomalies detected",
	}, []string{"service"})
	backoffGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "predictive_backoff_seconds",
		Help: "Current backoff seconds for service",
	}, []string{"service"})
)

func init() {
	// safe to register multiple times in tests; guard by recover
	defer func() { _ = recover() }()
	prometheus.MustRegister(predCounter, bootstrapCounter, anomalyCounter, backoffGauge)
}

// -------------------- Config --------------------

type Config struct {
	WindowSize            int
	EMAAlpha              float64
	Horizon               time.Duration
	Cooldown              time.Duration
	CPUCritical           float64
	RAMCritical           float64
	MinCPU                float64
	MinRAM                float64
	PersistenceFile       string
	PersistInterval       time.Duration
	DryRun                bool
	Simulate              bool
	EnableAutoBootstrap   bool
	MaxBackoff            time.Duration
	BaseBackoff           time.Duration
	OutlierIQRFactor      float64
	MedianWindow          int
	CostThreshold         float64
	MaxAttempts           int
	BootstrapsPerHour     int
	LeaderLockFile        string
	RemotePredictorAPIKey string
	InfraControllerURL    string // HTTP infra-controller endpoint
	InfraControllerAPIKey string
	// Redis config (optional) for shared store / leader elector
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisStoreKey string
	RedisLeaderKey string
}

// -------------------- PredictiveScaler (single coherent definition) --------------------

type PredictiveScaler struct {
	mu              sync.Mutex
	history         map[string][]ScalingSignal
	inFlight        map[string]bool
	lastTriggered   map[string]time.Time
	attempts        map[string]int
	rateMu          sync.Mutex
	rateWindowStart map[string]time.Time
	rateCount       map[string]int

	autoBootstrap BootstrapFunc
	predictor     Predictor
	metrics       MetricHook
	cfg           Config

	nodeSelector  NodeSelector
	costEstimator CostEstimator

	stopPersist chan struct{}

	leaderElector LeaderElector
	store         Store

	// new components
	anomalyDetector AnomalyDetector
	topology        *Topology
	policyAdjuster  PolicyAdjuster
	zeroTrust       ZeroTrustVerifier
	rlLearner       *ReinforcementLearner

	ops uint64
}

// -------------------- Constructor --------------------

func NewPredictiveScaler(cfg Config, predictor Predictor, bf BootstrapFunc, metrics MetricHook, selector NodeSelector, costEstimator CostEstimator) *PredictiveScaler {
	// safe defaults and security defaults
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 200
	}
	if cfg.EMAAlpha <= 0 || cfg.EMAAlpha > 1 {
		cfg.EMAAlpha = 0.25
	}
	if cfg.Horizon == 0 {
		cfg.Horizon = time.Minute
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = 10 * time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 30 * time.Minute
	}
	if cfg.OutlierIQRFactor == 0 {
		cfg.OutlierIQRFactor = 1.5
	}
	if cfg.PersistInterval == 0 {
		cfg.PersistInterval = 30 * time.Second
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.BootstrapsPerHour == 0 {
		cfg.BootstrapsPerHour = 6
	}

	// enforce secure defaults
	if !cfg.EnableAutoBootstrap {
		cfg.DryRun = true
	}

	ps := &PredictiveScaler{
		history:          make(map[string][]ScalingSignal),
		inFlight:         make(map[string]bool),
		lastTriggered:    make(map[string]time.Time),
		attempts:         make(map[string]int),
		rateWindowStart:  make(map[string]time.Time),
		rateCount:        make(map[string]int),
		autoBootstrap:    bf,
		predictor:        predictor,
		metrics:          metrics,
		cfg:              cfg,
		nodeSelector:     selector,
		costEstimator:    costEstimator,
		stopPersist:      make(chan struct{}),
		anomalyDetector:  NewZScoreDetector(50, 3.0),
		topology:         NewTopology(),
		policyAdjuster:   &DefaultPolicyAdjuster{},
		zeroTrust:        &NoopVerifier{},
		rlLearner:        NewReinforcementLearner(cfg.EMAAlpha, cfg.Horizon),
		leaderElector:    nil,
		store:            nil,
	}

	// configure Redis-based store/leader if Redis args provided
	if cfg.RedisAddr != "" {
		// create redis client and attach store/leader
		rs := NewRedisStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisStoreKey, cfg.RedisDB)
		ps.store = rs
		if cfg.RedisLeaderKey != "" {
			// default TTL
			elector := NewRedisLeaderElector(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisLeaderKey, cfg.RedisDB, 15*time.Second)
			ps.leaderElector = elector
			// try acquire in background
			go func() {
				_, _ = elector.Acquire(context.Background())
			}()
		}
	} else {
		// fallback to file store if provided
		if cfg.PersistenceFile != "" {
			ps.store = NewFileStore(cfg.PersistenceFile)
			_ = ps.loadStateFromStore()
			go ps.periodicPersist(cfg.PersistenceFile, cfg.PersistInterval)
		}
		// fallback leader elector uses file lock if provided
		if cfg.LeaderLockFile != "" && ps.leaderElector == nil {
			ps.leaderElector = NewFileLeaderElector(cfg.LeaderLockFile)
			if ok, err := ps.leaderElector.Acquire(context.Background()); ok && err == nil {
				// acquired
			}
		}
	}
	return ps
}

// -------------------- Pluggable setters --------------------

func (ps *PredictiveScaler) SetAnomalyDetector(a AnomalyDetector)               { ps.anomalyDetector = a }
func (ps *PredictiveScaler) SetPolicyAdjuster(p PolicyAdjuster)               { ps.policyAdjuster = p }
func (ps *PredictiveScaler) SetZeroTrustVerifier(z ZeroTrustVerifier)         { ps.zeroTrust = z }
func (ps *PredictiveScaler) SetReinforcementLearner(r *ReinforcementLearner)  { ps.rlLearner = r }
func (ps *PredictiveScaler) SetLeaderElector(e LeaderElector)                 { ps.leaderElector = e }
func (ps *PredictiveScaler) SetStore(s Store)                                 { ps.store = s }
func (ps *PredictiveScaler) SetInfraController(url, apiKey string)           { ps.cfg.InfraControllerURL = url; ps.cfg.InfraControllerAPIKey = apiKey }
func (ps *PredictiveScaler) SetMetricsHook(m MetricHook)                      { ps.metrics = m }
func (ps *PredictiveScaler) SetPredictor(p Predictor)                         { ps.predictor = p }
func (ps *PredictiveScaler) SetAutoBootstrapFunc(b BootstrapFunc)             { ps.autoBootstrap = b }
func (ps *PredictiveScaler) PromoteToLeaderIfNeeded(ctx context.Context) bool { if ps.leaderElector==nil {return true}; ok,_:=ps.leaderElector.Acquire(ctx); return ok }

// -------------------- Recording --------------------

func (ps *PredictiveScaler) Record(sig ScalingSignal) {
	// basic input validation
	if sig.CPU < 0 {
		sig.CPU = 0
	}
	if sig.RAM < 0 {
		sig.RAM = 0
	}
	ps.mu.Lock()
	arr := ps.history[sig.Service]
	arr = append(arr, sig)
	if ps.cfg.WindowSize > 0 && len(arr) > ps.cfg.WindowSize {
		start := len(arr) - ps.cfg.WindowSize
		arr = arr[start:]
	}
	ps.history[sig.Service] = arr
	ps.mu.Unlock()
	atomic.AddUint64(&ps.ops, 1)
	if ps.anomalyDetector != nil {
		ps.anomalyDetector.Feed(sig)
	}
}

// -------------------- PredictAndScale (hardened) --------------------

func (ps *PredictiveScaler) PredictAndScale(ctx context.Context, service string) (cpu float64, ram float64, triggered bool, err error) {
	ps.mu.Lock()
	hist := append([]ScalingSignal(nil), ps.history[service]...)
	last := ps.lastTriggered[service]
	attempts := ps.attempts[service]
	baseCfg := ps.cfg
	ps.mu.Unlock()

	if len(hist) == 0 {
		return ps.cfg.MinCPU, ps.cfg.MinRAM, false, nil
	}

	adjustedCfg := ps.policyAdjuster.AdjustFor(service, nil, &baseCfg)

	// anomaly detection
	if ps.anomalyDetector != nil {
		if is, score := ps.anomalyDetector.Detect(hist); is {
			jsonLog("anomaly_detected", map[string]interface{}{"service": service, "score": score})
			if ps.metrics != nil {
				ps.metrics.RecordAnomaly(service, score)
			}
			anomalyCounter.WithLabelValues(service).Inc()
			if score > 6.0 {
				if ps.rlLearner != nil {
					ps.rlLearner.Update(service, -1.0*score)
				}
				return 0, 0, false, fmt.Errorf("anomaly detected (score %.2f) - aborting action", score)
			}
		}
	}

	// preprocessing
	cleaned := clipOutliers(hist, adjustedCfg.OutlierIQRFactor)
	if adjustedCfg.MedianWindow > 1 {
		cleaned = medianSmooth(cleaned, adjustedCfg.MedianWindow)
	}

	// RL suggested params
	if ps.rlLearner != nil {
		if a, h := ps.rlLearner.Suggest(); a > 0 {
			adjustedCfg.EMAAlpha = a
			adjustedCfg.Horizon = h
		}
	}

	// predictor
	if ps.predictor != nil {
		cpu, ram, err = ps.predictor.Predict(ctx, cleaned, adjustedCfg.Horizon)
		if err != nil {
			jsonLog("predictor_error", map[string]interface{}{"service": service, "err": err.Error()})
			err = fmt.Errorf("predictor: %w", err)
		}
	}

	// fallback predictor if remote failed
	if cpu == 0 && ram == 0 {
		cpu = fallbackPredictCPU(cleaned, adjustedCfg.EMAAlpha)
		ram = fallbackPredictRAM(cleaned, adjustedCfg.EMAAlpha)
		if cpu < adjustedCfg.MinCPU {
			cpu = adjustedCfg.MinCPU
		}
		if ram < adjustedCfg.MinRAM {
			ram = adjustedCfg.MinRAM
		}
	}

	// validation: reasonable ranges
	if cpu < 0 || cpu > 10000 || math.IsNaN(cpu) {
		return 0, 0, false, fmt.Errorf("invalid cpu prediction: %v", cpu)
	}
	if ram < 0 || ram > 1e9 || math.IsNaN(ram) {
		return 0, 0, false, fmt.Errorf("invalid ram prediction: %v", ram)
	}

	// metrics + prometheus
	if ps.metrics != nil {
		ps.metrics.RecordPrediction(service, cpu, ram)
	}
	predCounter.WithLabelValues(service).Inc()
	jsonLog("prediction", map[string]interface{}{"service": service, "cpu": cpu, "ram": ram, "alpha": adjustedCfg.EMAAlpha, "horizon": adjustedCfg.Horizon.Seconds()})

	thresholdHit := cpu > adjustedCfg.CPUCritical || ram > adjustedCfg.RAMCritical
	costGood := true
	if ps.costEstimator != nil {
		cost := ps.costEstimator.EstimateCost(map[string]interface{}{"cpu": cpu, "ram": ram})
		penalty := ps.costEstimator.EstimatePenalty(service, cpu, ram)
		if cost > penalty && cost > adjustedCfg.CostThreshold {
			costGood = false
		}
	}

	if !(thresholdHit && costGood) {
		return cpu, ram, false, nil
	}

	// rate limit
	if !ps.allowBootstrap(service) {
		if ps.metrics != nil {
			ps.metrics.RecordRateLimited(service)
		}
		return cpu, ram, false, fmt.Errorf("rate-limited for service %s", service)
	}

	// backoff attempt checks
	now := time.Now()
	if attempts > 0 {
		backoff := adjustedCfg.BaseBackoff * time.Duration(math.Pow(2, float64(attempts-1)))
		if backoff > adjustedCfg.MaxBackoff {
			backoff = adjustedCfg.MaxBackoff
		}
		if now.Sub(last) < backoff {
			remaining := backoff - now.Sub(last)
			if ps.metrics != nil {
				ps.metrics.RecordBackoff(service, remaining)
			}
			backoffGauge.WithLabelValues(service).Set(remaining.Seconds())
			return cpu, ram, false, fmt.Errorf("in backoff (%s remaining)", remaining)
		}
	}

	// attempts and leadership checks
	ps.mu.Lock()
	if ps.attempts[service] >= adjustedCfg.MaxAttempts {
		ps.mu.Unlock()
		// emit final alert metric / structured log
		jsonLog("bootstrap_disabled", map[string]interface{}{"service": service, "reason": "max_attempts_reached"})
		bootstrapCounter.WithLabelValues(service, "disabled").Inc()
		return cpu, ram, false, fmt.Errorf("max attempts reached for %s", service)
	}
	// if leader elector provided, check leadership
	if ps.leaderElector != nil && !ps.leaderElector.IsLeader() {
		ps.mu.Unlock()
		return cpu, ram, false, fmt.Errorf("not leader; won't bootstrap")
	}
	if ps.inFlight[service] {
		ps.mu.Unlock()
		return cpu, ram, false, errors.New("bootstrap already in flight")
	}
	ps.inFlight[service] = true
	ps.lastTriggered[service] = now
	ps.mu.Unlock()

	// async bootstrap flow with zero-trust verification
	go func() {
		defer func() {
			ps.mu.Lock()
			ps.inFlight[service] = false
			ps.mu.Unlock()
		}()

		ctx2, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		reqs := map[string]interface{}{"cpu": cpu, "ram": ram}
		var target string
		if ps.nodeSelector != nil {
			if nodeID, ok := ps.nodeSelector.SelectNode(reqs); ok {
				target = nodeID
			}
		}
		if target == "" {
			target = fmt.Sprintf("%s-scale-%s", service, time.Now().Format("20060102-150405"))
		}

		// Zero-Trust verification
		if ps.zeroTrust != nil {
			ok, reason := ps.zeroTrust.Verify(ctx2, target, map[string]any{"reason": "predictive-scaling"})
			if !ok {
				jsonLog("zerotrust_failed", map[string]interface{}{"service": service, "target": target, "reason": reason})
				if ps.metrics != nil {
					ps.metrics.RecordBootstrapAttempt(service, false, "zerotrust-failed")
				}
				bootstrapCounter.WithLabelValues(service, "failed_zerotrust").Inc()
				if ps.rlLearner != nil {
					ps.rlLearner.Update(service, -0.5)
					if ps.metrics != nil {
						ps.metrics.RecordRLUpdate(service, map[string]float64{"alpha": ps.rlLearner.alpha, "horizon": ps.rlLearner.horizonSeconds})
					}
				}
				return
			}
		}

		// Dry-run safety
		if ps.cfg.DryRun || !ps.cfg.EnableAutoBootstrap {
			if ps.metrics != nil {
				ps.metrics.RecordBootstrapAttempt(service, true, "dry-run")
			}
			jsonLog("bootstrap_simulated", map[string]interface{}{"service": service, "target": target})
			bootstrapCounter.WithLabelValues(service, "simulated").Inc()
			if ps.rlLearner != nil {
				ps.rlLearner.Update(service, 0.1)
				if ps.metrics != nil {
					ps.metrics.RecordRLUpdate(service, map[string]float64{"alpha": ps.rlLearner.alpha, "horizon": ps.rlLearner.horizonSeconds})
				}
			}
			ps.mu.Lock()
			ps.attempts[service] = 0
			ps.mu.Unlock()
			ps.topology.RecordPlacement(service, target, 1.0)
			return
		}

		// Enforce that autoBootstrap calls are routed to an infra-controller (recommended pattern).
		// If a direct BootstrapFunc is provided, we still prefer using the infra-controller helper if configured in cfg.
		var errb error
		startT := time.Now()
		if ps.cfg.InfraControllerURL != "" && ps.cfg.InfraControllerAPIKey != "" {
			errb = AutoBootstrapHTTP(ctx2, ps.cfg.InfraControllerURL, ps.cfg.InfraControllerAPIKey, target, reqs)
		} else if ps.autoBootstrap != nil {
			// final fallback: call provided bootstrap function (must be safe and audited)
			errb = ps.autoBootstrap(ctx2, target, reqs)
		} else {
			errb = errors.New("no infra controller or bootstrap function configured")
		}
		duration := time.Since(startT).Seconds()

		ps.mu.Lock()
		defer ps.mu.Unlock()
		if errb != nil {
			ps.attempts[service] = ps.attempts[service] + 1
			ps.lastTriggered[service] = time.Now()
			jsonLog("bootstrap_failed", map[string]interface{}{"service": service, "target": target, "err": errb.Error(), "attempts": ps.attempts[service]})
			bootstrapCounter.WithLabelValues(service, "failed").Inc()
			if ps.rlLearner != nil {
				ps.rlLearner.Update(service, -1.0-duration*0.1)
				if ps.metrics != nil {
					ps.metrics.RecordRLUpdate(service, map[string]float64{"alpha": ps.rlLearner.alpha, "horizon": ps.rlLearner.horizonSeconds})
				}
			}
		} else {
			ps.attempts[service] = 0
			ps.lastTriggered[service] = time.Now()
			jsonLog("bootstrap_success", map[string]interface{}{"service": service, "target": target, "duration_s": duration})
			bootstrapCounter.WithLabelValues(service, "success").Inc()
			if ps.rlLearner != nil {
				reward := math.Max(0.1, 10.0-duration*0.1)
				ps.rlLearner.Update(service, reward)
				if ps.metrics != nil {
					ps.metrics.RecordRLUpdate(service, map[string]float64{"alpha": ps.rlLearner.alpha, "horizon": ps.rlLearner.horizonSeconds})
				}
			}
			ps.topology.RecordPlacement(service, target, duration*1000.0)
		}
	}()

	return cpu, ram, true, nil
}

// -------------------- Rate limiting --------------------

func (ps *PredictiveScaler) allowBootstrap(service string) bool {
	ps.rateMoCheckInit()
	ps.rateMu.Lock()
	defer ps.rateMu.Unlock()
	start := ps.rateWindowStart[service]
	now := time.Now()
	if start.IsZero() || now.Sub(start) >= time.Hour {
		ps.rateWindowStart[service] = now
		ps.rateCount[service] = 0
	}
	if ps.rateCount[service] >= ps.cfg.BootstrapsPerHour {
		return false
	}
	ps.rateCount[service]++
	return true
}

func (ps *PredictiveScaler) rateMoCheckInit() {
	ps.rateMu.Lock()
	defer ps.rateMu.Unlock()
	if ps.rateWindowStart == nil {
		ps.rateWindowStart = make(map[string]time.Time)
		ps.rateCount = make(map[string]int)
	}
}

// -------------------- Helpers & persistence using Store --------------------

type persistedState struct {
	History            map[string][]ScalingSignal
	Attempts           map[string]int
	RateWindowStart    map[string]time.Time
	RateCount          map[string]int
	RLAlpha            float64
	RLHorizon          float64
	TopologySvcToNodes map[string]map[string]int
	NodeLatencyHist    map[string][]float64
}

func (ps *PredictiveScaler) saveStateToStore() error {
	if ps.store == nil {
		return errors.New("no store configured")
	}
	ps.mu.Lock()
	state := persistedState{
		History:            ps.history,
		Attempts:           ps.attempts,
		RateWindowStart:    ps.rateWindowStart,
		RateCount:          ps.rateCount,
		RLAlpha:            ps.rlLearner.alpha,
		RLHorizon:          ps.rlLearner.horizonSeconds,
		TopologySvcToNodes: make(map[string]map[string]int),
		NodeLatencyHist:    make(map[string][]float64),
	}
	if ps.topology != nil {
		ps.topology.mu.RLock()
		for k, v := range ps.topology.serviceToNodes {
			state.TopologySvcToNodes[k] = make(map[string]int)
			for n, cnt := range v {
				state.TopologySvcToNodes[k][n] = cnt
			}
		}
		for n, hist := range ps.topology.nodeLatencyHist {
			state.NodeLatencyHist[n] = append([]float64{}, hist...)
		}
		ps.topology.mu.RUnlock()
	}
	ps.mu.Unlock()
	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(state); err != nil {
		return err
	}
	return ps.store.Save(buf.Bytes())
}

func (ps *PredictiveScaler) loadStateFromStore() error {
	if ps.store == nil {
		return errors.New("no store configured")
	}
	data, err := ps.store.Load()
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	var state persistedState
	if err := dec.Decode(&state); err != nil {
		return err
	}
	ps.mu.Lock()
	if state.History != nil {
		ps.history = state.History
	}
	if state.Attempts != nil {
		ps.attempts = state.Attempts
	}
	if state.RateWindowStart != nil {
		ps.rateWindowStart = state.RateWindowStart
	}
	if state.RateCount != nil {
		ps.rateCount = state.RateCount
	}
	if ps.rlLearner != nil {
		ps.rlLearner.mu.Lock()
		if state.RLAlpha > 0 {
			ps.rlLearner.alpha = state.RLAlpha
		}
		if state.RLHorizon > 0 {
			ps.rlLearner.horizonSeconds = state.RLHorizon
		}
		ps.rlLearner.mu.Unlock()
	}
	if ps.topology != nil {
		ps.topology.mu.Lock()
		ps.topology.serviceToNodes = make(map[string]map[string]int)
		for s, m := range state.TopologySvcToNodes {
			ps.topology.serviceToNodes[s] = make(map[string]int)
			for n, cnt := range m {
				ps.topology.serviceToNodes[s][n] = cnt
			}
		}
		ps.topology.nodeLatencyHist = make(map[string][]float64)
		for n, hist := range state.NodeLatencyHist {
			ps.topology.nodeLatencyHist[n] = append([]float64{}, hist...)
		}
		ps.topology.mu.Unlock()
	}
	ps.mu.Unlock()
	return nil
}

func (ps *PredictiveScaler) periodicPersist(path string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := ps.saveStateToStore(); err != nil {
				jsonLog("persist_error", map[string]interface{}{"err": err.Error()})
			}
		case <-ps.stopPersist:
			return
		}
	}
}

func (ps *PredictiveScaler) Stop() {
	select {
	case <-ps.stopPersist:
	default:
		close(ps.stopPersist)
	}
	if ps.leaderElector != nil {
		_ = ps.leaderElector.Release()
	}
}

// -------------------- AutoBootstrap HTTP helper (safe pattern) --------------------

func AutoBootstrapHTTP(ctx context.Context, controllerURL, apiKey, targetNode string, reqs map[string]interface{}) error {
	if controllerURL == "" {
		return errors.New("no infra controller configured")
	}
	body := map[string]interface{}{
		"target": targetNode,
		"reqs":   reqs,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", controllerURL+"/api/v1/bootstrap", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	// Use short timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller: %d %s", resp.StatusCode, string(bb))
	}
	return nil
}

// -------------------- RemotePredictor (improved) --------------------

type RemotePredictor struct {
	Endpoint   string
	APIKey     string
	Client     *http.Client
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	Timeout    time.Duration
}

func (r *RemotePredictor) Predict(ctx context.Context, history []ScalingSignal, horizon time.Duration) (cpu float64, ram float64, err error) {
	if r.Client == nil {
		r.Client = &http.Client{Timeout: 15 * time.Second}
	}
	reqBody := map[string]interface{}{"history": history, "horizon": int(horizon.Seconds())}
	b, _ := json.Marshal(reqBody)
	var lastErr error
	max := r.MaxRetries
	if max <= 0 {
		max = 3
	}
	base := r.BaseDelay
	if base == 0 {
		base = 500 * time.Millisecond
	}
	maxd := r.MaxDelay
	if maxd == 0 {
		maxd = 5 * time.Second
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	for attempt := 0; attempt <= max; attempt++ {
		ctxReq, cancel := context.WithTimeout(ctx, timeout)
		req, _ := http.NewRequestWithContext(ctxReq, "POST", r.Endpoint, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if r.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+r.APIKey)
		}
		resp, err := r.Client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					lastErr = fmt.Errorf("remote predictor status %d", resp.StatusCode)
					return
				}
				var out struct {
					CPU float64 `json:"cpu"`
					RAM float64 `json:"ram"`
				}
				dec := json.NewDecoder(resp.Body)
				if err := dec.Decode(&out); err != nil {
					lastErr = err
					return
				}
				cpu = out.CPU
				ram = out.RAM
				lastErr = nil
			}()
			if lastErr == nil {
				return cpu, ram, nil
			}
		}
		sleep := time.Duration(float64(base) * math.Pow(2, float64(attempt)))
		if sleep > maxd {
			sleep = maxd
		}
		jitter := time.Duration(rand.Int63n(int64(sleep / 4)))
		time.Sleep(sleep + jitter)
	}
	return 0, 0, fmt.Errorf("remote predictor failed: %v", lastErr)
}

// -------------------- Utilities & NodeRegistry & SimpleMetrics --------------------

func toFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	default:
		return 0
	}
}

type NodeRegistry struct {
	mu    sync.Mutex
	nodes []Node
}

func NewNodeRegistry() *NodeRegistry { return &NodeRegistry{} }

func (r *NodeRegistry) RegisterNode(n Node) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes = append(r.nodes, n)
}

func (r *NodeRegistry) ListNodes() []Node {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Node, len(r.nodes))
	copy(out, r.nodes)
	return out
}

func (r *NodeRegistry) SelectNode(requirements map[string]interface{}) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reqCPU := toFloat(requirements["cpu"])
	reqRAM := toFloat(requirements["ram"])
	for _, n := range r.nodes {
		if n.CPUAvailable >= reqCPU && n.RAMAvailable >= reqRAM {
			return n.ID, true
		}
	}
	return "", false
}

type SimpleMetrics struct{}

func (s *SimpleMetrics) RecordPrediction(service string, cpu, ram float64) {
	jsonLog("metrics.prediction", map[string]interface{}{"service": service, "cpu": cpu, "ram": ram})
}
func (s *SimpleMetrics) RecordBootstrapAttempt(service string, success bool, info string) {
	jsonLog("metrics.bootstrap", map[string]interface{}{"service": service, "success": success, "info": info})
}
func (s *SimpleMetrics) RecordBackoff(service string, backoff time.Duration) {
	jsonLog("metrics.backoff", map[string]interface{}{"service": service, "backoff": backoff.String()})
}
func (s *SimpleMetrics) RecordRateLimited(service string) {
	jsonLog("metrics.ratelimit", map[string]interface{}{"service": service})
}
func (s *SimpleMetrics) RecordAnomaly(service string, score float64) {
	jsonLog("metrics.anomaly", map[string]interface{}{"service": service, "score": score})
}
func (s *SimpleMetrics) RecordRLUpdate(service string, params map[string]float64) {
	jsonLog("metrics.rlupdate", map[string]interface{}{"service": service, "params": params})
}

// -------------------- Backtest helper --------------------

func (ps *PredictiveScaler) RunBacktest(service string, signals []ScalingSignal) (triggers int, lastCPU, lastRAM float64) {
	ps.mu.Lock()
	orig := ps.history[service]
	ps.history[service] = nil
	ps.mu.Unlock()
	defer func() {
		ps.mu.Lock()
		ps.history[service] = orig
		ps.mu.Unlock()
	}()
	for _, sig := range signals {
		ps.Record(sig)
		cpu, ram, triggered, _ := ps.PredictAndScale(context.Background(), service)
		if triggered {
			triggers++
		}
		lastCPU = cpu
		lastRAM = ram
		time.Sleep(1 * time.Millisecond)
	}
	return
}

// -------------------- Fallback predictors & helpers --------------------

func fallbackPredictCPU(history []ScalingSignal, alpha float64) float64 {
	if len(history) == 0 {
		return 0.1
	}
	if alpha <= 0 || alpha > 1 {
		alpha = 0.25
	}
	ema := history[len(history)-1].CPU
	for i := len(history) - 2; i >= 0; i-- {
		v := history[i].CPU
		ema = alpha*v + (1-alpha)*ema
	}
	trend := simpleLinearSlope(history, func(s ScalingSignal) float64 { return s.CPU })
	forecast := ema + trend*float64(1)
	if math.IsNaN(forecast) || forecast < 0 {
		forecast = 0
	}
	if forecast > 4.0 {
		forecast = 4.0
	}
	return forecast
}

func fallbackPredictRAM(history []ScalingSignal, alpha float64) float64 {
	if len(history) == 0 {
		return 128.0
	}
	if alpha <= 0 || alpha > 1 {
		alpha = 0.25
	}
	ema := history[len(history)-1].RAM
	for i := len(history) - 2; i >= 0; i-- {
		v := history[i].RAM
		ema = alpha*v + (1-alpha)*ema
	}
	trend := simpleLinearSlope(history, func(s ScalingSignal) float64 { return s.RAM })
	forecast := ema + trend*float64(1)
	if math.IsNaN(forecast) || forecast < 0 {
		forecast = 0
	}
	if forecast > 1e7 {
		forecast = 1e7
	}
	return forecast
}

func simpleLinearSlope(history []ScalingSignal, val func(ScalingSignal) float64) float64 {
	n := len(history)
	if n < 2 {
		return 0
	}
	var sumX, sumY, sumXY, sumXX float64
	for i := 0; i < n; i++ {
		x := float64(i)
		y := val(history[i])
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	den := float64(n)*sumXX - sumX*sumX
	if den == 0 {
		return 0
	}
	m := (float64(n)*sumXY - sumX*sumY) / den
	return m
}

func clipOutliers(history []ScalingSignal, factor float64) []ScalingSignal {
	if len(history) < 4 {
		return history
	}
	cpus := make([]float64, 0, len(history))
	rams := make([]float64, 0, len(history))
	for _, s := range history {
		cpus = append(cpus, s.CPU)
		rams = append(rams, s.RAM)
	}
	lowCPU, highCPU := iqrBounds(cpus, factor)
	lowRAM, highRAM := iqrBounds(rams, factor)
	res := make([]ScalingSignal, 0, len(history))
	for _, s := range history {
		c := s.CPU
		r := s.RAM
		if c < lowCPU {
			c = lowCPU
		} else if c > highCPU {
			c = highCPU
		}
		if r < lowRAM {
			r = lowRAM
		} else if r > highRAM {
			r = highRAM
		}
		res = append(res, ScalingSignal{Service: s.Service, CPU: c, RAM: r, Timestamp: s.Timestamp})
	}
	return res
}

func iqrBounds(vals []float64, factor float64) (low, high float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	q1 := percentile(s, 25)
	q3 := percentile(s, 75)
	iqr := q3 - q1
	low = q1 - factor*iqr
	high = q3 + factor*iqr
	return
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	pos := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(pos))
	upper := int(math.Ceil(pos))
	if lower == upper {
		return sorted[lower]
	}
	frac := pos - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func medianSmooth(history []ScalingSignal, window int) []ScalingSignal {
	if window <= 1 || len(history) <= window {
		return history
	}
	out := make([]ScalingSignal, 0, len(history))
	for i := 0; i < len(history); i++ {
		start := i - window + 1
		if start < 0 {
			start = 0
		}
		win := history[start : i+1]
		cpus := make([]float64, 0, len(win))
		rams := make([]float64, 0, len(win))
		for _, s := range win {
			cpus = append(cpus, s.CPU)
			rams = append(rams, s.RAM)
		}
		out = append(out, ScalingSignal{Service: history[i].Service, CPU: median(cpus), RAM: median(rams), Timestamp: history[i].Timestamp})
	}
	return out
}

func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// -------------------- Structured logging helper --------------------

func jsonLog(event string, data map[string]interface{}) {
	obj := make(map[string]interface{}, len(data)+3)
	obj["ts"] = time.Now().UTC().Format(time.RFC3339)
	obj["event"] = event
	for k, v := range data {
		obj[k] = v
	}
	// easy place to inject trace-id if provided via data["_trace"]
	if _, ok := obj["_trace"]; !ok {
		// no-op
	}
	b, _ := json.Marshal(obj)
	log.Println(string(b))
}