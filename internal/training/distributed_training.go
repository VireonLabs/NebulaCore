// internal/training/distributed_training.go
// Workload manager: supports training/serving/experiment/batch jobs,
// lifecycle operations (start/pause/resume/cancel), checkpointing,
// microtask generation hooks, synchronizers, autoscaler hooks, and ExposeFunctions.
package training

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

// ModuleInfo for registry
type ModuleInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	Health       string   `json:"health"`
}

// WorkloadJob is a superset of training job to support multiple kinds
type WorkloadJob struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"` // training|serving|experiment|batch
	Spec           map[string]any    `json:"spec"`
	Status         string            `json:"status"` // created/staging/running/preempted/failed/completed
	Nodes          []string          `json:"nodes"`
	ResourceHints  map[string]any    `json:"resource_hints"`
	CheckpointPath string            `json:"checkpoint_path"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Meta           map[string]any    `json:"meta"`
}

// Synchronizer interface for AllReduce/Barrier
type Synchronizer interface {
	AllReduce(ctx context.Context, shards [][]byte) ([]byte, error)
	Barrier(ctx context.Context) error
}

// AutoscalerHook signature
type AutoscalerHook func(jobID string, metrics map[string]any) (scaleUp bool, scaleDown bool)

type MicrotaskSubmitter func(jobID string, mtSpec map[string]any) error

// DistributedTrainer manages jobs
type DistributedTrainer struct {
	mu             sync.RWMutex
	jobs           map[string]*WorkloadJob
	baseDir        string
	sync           Synchronizer
	autoscaler     AutoscalerHook
	submitter      MicrotaskSubmitter
	telemetry      func(event string, meta map[string]any)
	stopCh         chan struct{}
	jobCancel      map[string]context.CancelFunc // per-job cancel
}

// NewDistributedTrainer constructs trainer with baseDir for job data
func NewDistributedTrainer(baseDir string) *DistributedTrainer {
	_ = os.MkdirAll(baseDir, 0o750)
	dt := &DistributedTrainer{
		jobs:      map[string]*WorkloadJob{},
		baseDir:   baseDir,
		stopCh:    make(chan struct{}),
		jobCancel: map[string]context.CancelFunc{},
	}
	return dt
}

// CreateJob registers a new job
func (dt *DistributedTrainer) CreateJob(job *WorkloadJob) error {
	if job == nil || job.ID == "" {
		return errors.New("invalid job")
	}
	// validate kind (basic)
	if job.Kind == "" {
		job.Kind = "training"
	}
	allowed := map[string]bool{"training": true, "serving": true, "experiment": true, "batch": true}
	if !allowed[job.Kind] {
		return errors.New("invalid job kind")
	}
	job.Status = "created"
	job.CreatedAt = time.Now()
	job.UpdatedAt = time.Now()
	if job.CheckpointPath == "" {
		job.CheckpointPath = filepath.Join(dt.baseDir, job.ID, "checkpoints")
	}
	_ = os.MkdirAll(filepath.Join(dt.baseDir, job.ID), 0o750)
	_ = os.MkdirAll(job.CheckpointPath, 0o750)
	dt.mu.Lock()
	dt.jobs[job.ID] = job
	dt.mu.Unlock()
	return dt.saveJobMeta(job.ID)
}

// saveJobMeta persists job metadata atomically
func (dt *DistributedTrainer) saveJobMeta(jobID string) error {
	dt.mu.RLock()
	j, ok := dt.jobs[jobID]
	dt.mu.RUnlock()
	if !ok {
		return errors.New("job not found")
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(dt.baseDir, jobID)
	_ = os.MkdirAll(dir, 0o750)
	tmp := filepath.Join(dir, "meta.json.tmp")
	path := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StartJob starts job orchestration (non-blocking)
func (dt *DistributedTrainer) StartJob(ctx context.Context, jobID string) error {
	dt.mu.Lock()
	job, ok := dt.jobs[jobID]
	if !ok {
		dt.mu.Unlock()
		return errors.New("job not found")
	}
	if job.Status == "running" {
		dt.mu.Unlock()
		return errors.New("already running")
	}
	job.Status = "running"
	job.UpdatedAt = time.Now()
	cancelCtx, cancel := context.WithCancel(ctx)
	dt.jobCancel[jobID] = cancel
	dt.mu.Unlock()
	_ = dt.saveJobMeta(jobID)
	// run orchestration
	go dt.runJob(cancelCtx, jobID)
	return nil
}

func (dt *DistributedTrainer) runJob(ctx context.Context, jobID string) {
	// orchestration loop: for demo, periodic telemetry and autoscaler checks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			dt.mu.Lock()
			if j, ok := dt.jobs[jobID]; ok {
				j.Status = "preempted"
				j.UpdatedAt = time.Now()
			}
			// cleanup cancel
			if c, ok := dt.jobCancel[jobID]; ok && c != nil {
				delete(dt.jobCancel, jobID)
			}
			dt.mu.Unlock()
			_ = dt.saveJobMeta(jobID)
			return
		case <-dt.stopCh:
			return
		case <-ticker.C:
			// sample telemetry hook if any
			if dt.telemetry != nil {
				dt.telemetry("job_heartbeat", map[string]any{"job": jobID})
			}
			// autoscaler hook
			if dt.autoscaler != nil {
				metrics := map[string]any{"sample": 1}
				_, _ = dt.autoscaler(jobID, metrics)
			}
		}
	}
}

// PauseJob pauses a running job (logical)
func (dt *DistributedTrainer) PauseJob(jobID string) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if j, ok := dt.jobs[jobID]; ok {
		j.Status = "staging"
		j.UpdatedAt = time.Now()
		_ = dt.saveJobMeta(jobID)
		return nil
	}
	return errors.New("job not found")
}

func (dt *DistributedTrainer) ResumeJob(jobID string) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if j, ok := dt.jobs[jobID]; ok {
		j.Status = "running"
		j.UpdatedAt = time.Now()
		_ = dt.saveJobMeta(jobID)
		return nil
	}
	return errors.New("job not found")
}

func (dt *DistributedTrainer) CancelJob(jobID string) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if j, ok := dt.jobs[jobID]; ok {
		// cancel running context if exists
		if c, okc := dt.jobCancel[jobID]; okc && c != nil {
			c()
			delete(dt.jobCancel, jobID)
		}
		j.Status = "failed"
		j.UpdatedAt = time.Now()
		_ = dt.saveJobMeta(jobID)
		return nil
	}
	return errors.New("job not found")
}

func (dt *DistributedTrainer) GetJobStatus(jobID string) (*WorkloadJob, error) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	if j, ok := dt.jobs[jobID]; ok {
		// shallow copy
		cp := *j
		return &cp, nil
	}
	return nil, errors.New("job not found")
}

func (dt *DistributedTrainer) ListJobs() []*WorkloadJob {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	out := make([]*WorkloadJob, 0, len(dt.jobs))
	for _, j := range dt.jobs {
		out = append(out, j)
	}
	return out
}

// GenerateTasksForJob splits job into microtasks via submitter callback
func (dt *DistributedTrainer) GenerateTasksForJob(jobID string, sliceSpec map[string]any) error {
	dt.mu.RLock()
	job, ok := dt.jobs[jobID]
	dt.mu.RUnlock()
	if !ok {
		return errors.New("job not found")
	}
	if dt.submitter == nil {
		return errors.New("no microtask submitter registered")
	}
	// Example simple splitting using sliceSpec["num"]
	num := 4
	if raw, ok := sliceSpec["num"]; ok {
		switch v := raw.(type) {
		case int:
			if v > 0 {
				num = v
			}
		case int64:
			if v > 0 {
				num = int(v)
			}
		case float64:
			if int(v) > 0 {
				num = int(v)
			}
		}
	}
	for i := 0; i < num; i++ {
		mt := map[string]any{
			"job":     jobID,
			"shard":   i,
			"payload": job.Spec,
		}
		if err := dt.submitter(jobID, mt); err != nil {
			return err
		}
	}
	return nil
}

// OnTaskFailure default behavior: resubmit or mark job failed
func (dt *DistributedTrainer) OnTaskFailure(taskID string) error {
	// best-effort: emit telemetry and mark job for inspection
	if dt.telemetry != nil {
		dt.telemetry("task_failure", map[string]any{"task": taskID})
	}
	return nil
}

// Checkpoint management

func (dt *DistributedTrainer) SaveCheckpoint(jobID string) (map[string]any, error) {
	path := filepath.Join(dt.baseDir, jobID, "checkpoints")
	_ = os.MkdirAll(path, 0o750)
	id := fmt.Sprintf("ckpt-%d", time.Now().Unix())
	meta := map[string]any{"id": id, "time": time.Now().UTC().String()}
	b, _ := json.Marshal(meta)
	tmp := filepath.Join(path, id+".json.tmp")
	final := filepath.Join(path, id+".json")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return nil, err
	}
	_ = os.Rename(tmp, final)
	return meta, nil
}

func (dt *DistributedTrainer) ListCheckpoints(jobID string) ([]string, error) {
	path := filepath.Join(dt.baseDir, jobID, "checkpoints")
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, f := range files {
		out = append(out, f.Name())
	}
	return out, nil
}

func (dt *DistributedTrainer) RestoreCheckpoint(jobID, checkpointFile string) error {
	// Simulate restore by checking file exists
	path := filepath.Join(dt.baseDir, jobID, "checkpoints", checkpointFile)
	_, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// in real system we'd instruct workers to restore state
	return nil
}

// RegisterSynchronizer sets synchronizer (e.g., RDMA AllReduce optimized)
func (dt *DistributedTrainer) RegisterSynchronizer(s Synchronizer) {
	dt.mu.Lock()
	dt.sync = s
	dt.mu.Unlock()
}

// RegisterAutoscaler registers autoscaler hook
func (dt *DistributedTrainer) RegisterAutoscaler(h AutoscalerHook) {
	dt.mu.Lock()
	dt.autoscaler = h
	dt.mu.Unlock()
}

// SetResourceHints stores hints for job scheduling/routing
func (dt *DistributedTrainer) SetResourceHints(jobID string, hints map[string]any) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if j, ok := dt.jobs[jobID]; ok {
		j.ResourceHints = hints
		j.UpdatedAt = time.Now()
		_ = dt.saveJobMeta(jobID)
		return nil
	}
	return errors.New("job not found")
}

// RegisterMicrotaskSubmitter registers callback to submit microtasks (usually microtasking.ExposeFunctions)
func (dt *DistributedTrainer) RegisterMicrotaskSubmitter(s MicrotaskSubmitter) {
	dt.mu.Lock()
	dt.submitter = s
	dt.mu.Unlock()
}

// SetTelemetry sets telemetry sink
func (dt *DistributedTrainer) SetTelemetry(fn func(event string, meta map[string]any)) {
	dt.mu.Lock()
	dt.telemetry = fn
	dt.mu.Unlock()
}

// SetPreemptionPolicy sets preemption policy metadata
func (dt *DistributedTrainer) SetPreemptionPolicy(jobID string, policy string) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if j, ok := dt.jobs[jobID]; ok {
		if j.Meta == nil {
			j.Meta = map[string]any{}
		}
		j.Meta["preemption_policy"] = policy
		j.UpdatedAt = time.Now()
		_ = dt.saveJobMeta(jobID)
		return nil
	}
	return errors.New("job not found")
}

// ModuleMeta
func (dt *DistributedTrainer) ModuleMeta() ModuleInfo {
	return ModuleInfo{
		Name:         "training",
		Version:      "v1.1",
		Capabilities: []string{"create_job", "start_job", "checkpoint", "generate_tasks", "preempt"},
		Health:       "ok",
	}
}

// ExposeFunctions for orchestrator/model
func (dt *DistributedTrainer) ExposeFunctions() map[string]any {
	return map[string]any{
		"create_job":            dt.CreateJob,
		"start_job":             dt.StartJob,
		"pause_job":             dt.PauseJob,
		"resume_job":            dt.ResumeJob,
		"cancel_job":            dt.CancelJob,
		"get_job_status":        dt.GetJobStatus,
		"list_jobs":             dt.ListJobs,
		"generate_tasks":        dt.GenerateTasksForJob,
		"save_checkpoint":       dt.SaveCheckpoint,
		"list_checkpoints":      dt.ListCheckpoints,
		"restore_checkpoint":    dt.RestoreCheckpoint,
		"register_synchronizer": dt.RegisterSynchronizer,
		"register_autoscaler":   dt.RegisterAutoscaler,
		"set_resource_hints":    dt.SetResourceHints,
		"register_submitter":    dt.RegisterMicrotaskSubmitter,
	}
}