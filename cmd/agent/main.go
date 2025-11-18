package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
    
	"github.com/Aurionex/NebulaCore/internal/ai"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// 🔹 Firecracker Helper Tool
const firecrackerRunner = "fc-run"

// RegisterReq sent to control-plane
type RegisterReq struct {
	AgentID  string `json:"agent_id"`
	Address  string `json:"address"`
	Capacity int    `json:"capacity"`
	Labels   string `json:"labels"`
	Version  string `json:"version"`
	Key      string `json:"key,omitempty"` // project key (optional)
}

// Job payload
type Job struct {
	ID      string                 `json:"id"`
	Image   string                 `json:"image,omitempty"`
	Kernel  string                 `json:"kernel,omitempty"`
	Initrd  string                 `json:"initrd,omitempty"`
	Rootfs  string                 `json:"rootfs,omitempty"`
	Cmdline []string               `json:"cmdline,omitempty"`
	Env     map[string]string      `json:"env,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
	Timeout int                    `json:"timeout_seconds,omitempty"`
}

// JobResult back to control-plane
type JobResult struct {
	JobID    string `json:"job_id"`
	AgentID  string `json:"agent_id"`
	Success  bool   `json:"success"`
	ExitCode int    `json:"exit_code"`
	Logs     string `json:"logs,omitempty"`
	Duration int64  `json:"duration_ms"`
	Error    string `json:"error,omitempty"`
}

// Globals
var (
	controlURL    string
	agentID       string
	agentLabels   string
	capacity      int
	sandbox       string
	address       string // resolved address used for registration
	agentVersion  = "agent-v1.1.0-firecracker"
	registerFreq  = 10 * time.Second
	requestLimit  = int64(10 << 20) // 10MB
	httpTimeout   = 30 * time.Second
	shutdownGrace = 20 * time.Second
	// identity that can be generated per-project
	projectKey     string
	projectAddress string
	modelGenURL    string
)

// Agent runtime
type Agent struct {
	id        string
	capacity  int
	labels    string
	control   string
	sandbox   string
	client    *http.Client
	jobQueue  chan Job
	wg        sync.WaitGroup
	shutdown  chan struct{}
	metrics   *AgentMetrics
	reportMux sync.Mutex
	// identity
	projectKey     string
	projectAddress string
}

type AgentMetrics struct {
	registerAttempts prometheus.Counter
	registerSuccess  prometheus.Counter
	jobsReceived     prometheus.Counter
	jobsAccepted     prometheus.Counter
	jobsSuccess      prometheus.Counter
	jobsFailed       prometheus.Counter
	jobDuration      prometheus.Histogram
	authFailures     prometheus.Counter
}

// ================= METRICS ==================
func NewMetrics() *AgentMetrics {
	m := &AgentMetrics{
		registerAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_register_attempts_total",
			Help: "Total register attempts to control-plane",
		}),
		registerSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_register_success_total",
			Help: "Successful register attempts",
		}),
		jobsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_received_total",
			Help: "Jobs received",
		}),
		jobsAccepted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_accepted_total",
			Help: "Jobs accepted",
		}),
		jobsSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_success_total",
			Help: "Jobs executed successfully",
		}),
		jobsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_failed_total",
			Help: "Jobs failed",
		}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_auth_failures_total",
			Help: "Unauthorized requests received",
		}),
		jobDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "agent_job_duration_seconds",
			Help:    "Job execution duration",
			Buckets: prometheus.ExponentialBuckets(0.5, 2.0, 8),
		}),
	}
	prometheus.MustRegister(
		m.registerAttempts,
		m.registerSuccess,
		m.jobsReceived,
		m.jobsAccepted,
		m.jobsSuccess,
		m.jobsFailed,
		m.authFailures,
		m.jobDuration,
	)
	return m
}

// ================= CORE AGENT ==================
func NewAgent(id, control, addr, labels string, cap int, sandbox string, pKey, pAddr string) *Agent {
	return &Agent{
		id:             id,
		capacity:       cap,
		labels:         labels,
		control:        control,
		sandbox:        sandbox,
		client:         &http.Client{Timeout: httpTimeout},
		jobQueue:       make(chan Job, cap*4),
		shutdown:       make(chan struct{}),
		metrics:        NewMetrics(),
		projectKey:     pKey,
		projectAddress: pAddr,
	}
}

// ================= FIRECRACKER RUNNER ==================
func (a *Agent) runFirecrackerTask(ctx context.Context, job Job) (int, string, string) {
	if job.Kernel == "" || job.Rootfs == "" {
		return a.simulateAndReturn(job)
	}

	args := []string{job.Kernel, job.Rootfs}
	args = append(args, job.Cmdline...)
	cmd := exec.CommandContext(ctx, firecrackerRunner, args...)

	// set env
	if job.Env != nil {
		env := os.Environ()
		for k, v := range job.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	out, err := cmd.CombinedOutput()
	logOutput := string(out)
	if err != nil {
		return 1, truncate(logOutput), err.Error()
	}
	return 0, truncate(logOutput), ""
}

// ================== HELPERS ==================
func (a *Agent) simulateAndReturn(job Job) (int, string, string) {
	time.Sleep(time.Duration(500+rand.Intn(2000)) * time.Millisecond)
	if rand.Float64() < 0.05 {
		return 1, "simulated-exec job=" + job.ID, "simulated error"
	}
	return 0, "simulated-exec job=" + job.ID, ""
}

func truncate(s string) string {
	if len(s) > 64*1024 {
		return s[:64*1024] + "...(truncated)"
	}
	return s
}

func detectLocalAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

// initIdentityFromModel: try external endpoint, then internal AI orchestrator, then fallback
func initIdentityFromModel(projectID string, aiOrch *ai.AIOrchestrator, modelGenURL string) (string, string, error) {
	// 1) external model endpoint if provided (fast path)
	if modelGenURL != "" {
		client := &http.Client{Timeout: 8 * time.Second}
		type respT struct {
			Address string `json:"address"`
			Key     string `json:"key"`
		}
		// build URL with project param
		url := fmt.Sprintf("%s?project=%s", strings.TrimRight(modelGenURL, "/"), projectID)
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var body respT
				if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
					if body.Address != "" && body.Key != "" {
						return body.Address, body.Key, nil
					}
				}
			}
		}
	}

	// 2) ask internal AI orchestrator (if provided)
	if aiOrch != nil {
		id := aiOrch.GetProjectIdentity(projectID)
		if id.Address != "" && id.Key != "" {
			return id.Address, id.Key, nil
		}
	}

	// 3) fallback: local address + random key
	addr := "http://" + detectLocalAddress() + ":9000"
	key := generateRandomKey(32)
	return addr, key, nil
}

func generateRandomKey(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// ================= HTTP / Handlers / Run ==================
func (a *Agent) Run(port string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/register", a.handleRegister)
	mux.HandleFunc("/job", a.handleJob)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: limitBodyMiddleware(mux, requestLimit),
	}

	// start registration ticker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.registrationLoop(ctx)

	// graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutdown signal received, shutting down...")
		// stop registration
		cancel()
		// give graceful window
		tctx, tcancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer tcancel()
		srv.Shutdown(tctx)
		close(a.shutdown)
	}()

	log.Printf("Agent listening on :%s (address=%s)", port, a.projectAddress)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server error: %v", err)
	}

	// wait for running jobs to finish
	log.Println("waiting for running jobs to complete...")
	a.wg.Wait()
	log.Println("agent stopped")
}

// limitBodyMiddleware prevents large requests
func limitBodyMiddleware(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// registrationLoop periodically registers agent to control-plane
func (a *Agent) registrationLoop(ctx context.Context) {
	ticker := time.NewTicker(registerFreq)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.registerOnce()
		}
	}
}

func (a *Agent) registerOnce() {
	a.metrics.registerAttempts.Inc()
	req := RegisterReq{
		AgentID:  a.id,
		Address:  a.projectAddress,
		Capacity: a.capacity,
		Labels:   a.labels,
		Version:  agentVersion,
		Key:      a.projectKey,
	}
	b, _ := json.Marshal(req)
	resp, err := a.client.Post(a.control+"/agents/register", "application/json", strings.NewReader(string(b)))
	if err != nil {
		log.Printf("register error: %v", err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		a.metrics.registerSuccess.Inc()
		log.Printf("registered to control-plane (status=%d)", resp.StatusCode)
	} else {
		log.Printf("register failed (status=%d)", resp.StatusCode)
	}
}

// handleRegister allows manual registration (protected by key)
func (a *Agent) handleRegister(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-PROJECT-KEY")
	if key == "" || key != a.projectKey {
		a.metrics.authFailures.Inc()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// respond with current identity
	resp := map[string]string{"address": a.projectAddress, "key": a.projectKey}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleJob accepts job submissions protected by project key
func (a *Agent) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := r.Header.Get("X-PROJECT-KEY")
	if key == "" || key != a.projectKey {
		a.metrics.authFailures.Inc()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var job Job
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&job); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	a.metrics.jobsReceived.Inc()
	select {
	case a.jobQueue <- job:
		a.metrics.jobsAccepted.Inc()
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("accepted"))
	default:
		http.Error(w, "agent busy", http.StatusTooManyRequests)
	}
}

// workerLoop processes jobs from the queue
func (a *Agent) workerLoop() {
	for job := range a.jobQueue {
		a.wg.Add(1)
		func(j Job) {
			defer a.wg.Done()
			start := time.Now()
			code, logs, errStr := a.runFirecrackerTask(context.Background(), j)
			dur := time.Since(start).Milliseconds()
			res := JobResult{
				JobID:    j.ID,
				AgentID:  a.id,
				Success:  code == 0,
				ExitCode: code,
				Logs:     logs,
				Duration: dur,
				Error:    errStr,
			}
			if res.Success {
				a.metrics.jobsSuccess.Inc()
			} else {
				a.metrics.jobsFailed.Inc()
			}
			// TODO: report back to control-plane (POST /agents/job/result)
			_ = res
		}(job)
	}
}

// helper: start workers
func (a *Agent) startWorkers() {
	for i := 0; i < a.capacity; i++ {
		go a.workerLoop()
	}
}

// ================== MAIN ==================
func main() {
	var projectID string

	flag.StringVar(&controlURL, "control", getenv("CONTROL_URL", "http://localhost:8080"), "control plane URL")
	flag.StringVar(&agentID, "id", getenv("AGENT_ID", ""), "agent id")
	flag.IntVar(&capacity, "capacity", getenvInt("AGENT_CAPACITY", 2), "tasks capacity")
	flag.StringVar(&sandbox, "sandbox", getenv("AGENT_SANDBOX", "firecracker"), "sandbox: firecracker|docker|simulate")
	flag.StringVar(&agentLabels, "labels", getenv("AGENT_LABELS", "local,default"), "labels")
	flag.StringVar(&projectID, "project", getenv("PROJECT_ID", "default"), "project id")
	flag.StringVar(&projectKey, "key", getenv("PROJECT_KEY", ""), "project access key (optional)")
	flag.StringVar(&projectAddress, "address", getenv("PROJECT_ADDRESS", ""), "project address (optional)")
	flag.StringVar(&modelGenURL, "model-gen", getenv("MODEL_GEN_URL", ""), "model endpoint to generate address+key")
	flag.Parse()

	if agentID == "" {
		agentID = "agent-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}

	// create AI orchestrator and configure external endpoint if provided
	aiOrch := ai.NewAIOrchestrator()
	if modelGenURL != "" {
		aiOrch.SetExternalIdentityEndpoint(modelGenURL)
	}

	// use model/orchestrator to init identity if not provided
	if projectAddress == "" || projectKey == "" {
		addr, key, err := initIdentityFromModel(projectID, aiOrch, modelGenURL)
		if err != nil {
			log.Fatalf("failed to init identity: %v", err)
		}
		projectAddress = addr
		projectKey = key
	}
	if projectAddress == "" {
		ip := detectLocalAddress()
		port := getenv("AGENT_PORT", "9000")
		projectAddress = "http://" + ip + ":" + port
	}

	if capacity < 1 {
		capacity = 1
	}

	// use projectAddress as the address the control-plane should use
	address = projectAddress

	agent := NewAgent(agentID, controlURL, address, agentLabels, capacity, sandbox, projectKey, projectAddress)

	// start workers
	agent.startWorkers()

	port := getenv("AGENT_PORT", "9000")
	agent.Run(port)
}

// env helpers
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if iv, err := strconv.Atoi(v); err == nil {
			return iv
		}
	}
	return def
}
  
