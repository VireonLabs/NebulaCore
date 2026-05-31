// internal/selfhealing/self_healing.go
// Self-Healing Manager: incident registry, RCA plugins, playbooks, tool builder,
// patch manager, sandbox-aware Build/Run/Deploy with telemetry and audit hooks.
//
// Security note (critical):
// - BuildTool/RunTool support metadata["use_container"]=true to build inside Docker.
//   For production, ensure a secure build runner or dedicated build service; don't expose
//   docker socket to untrusted processes. Scanner support limited to known scanners (trivy/syft).
package selfhealing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Models
type FailureEvent struct {
	Timestamp time.Time        `json:"timestamp"`
	NodeID    string           `json:"node_id"`
	Type      string           `json:"type"`
	Severity  int              `json:"severity"`
	Details   string           `json:"details"`
	Meta      map[string]any   `json:"meta,omitempty"`
}

type RepairAction struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Actor     string         `json:"actor"`
	Command   string         `json:"command"`
	Success   bool           `json:"success"`
	Log       string         `json:"log,omitempty"`
	AppliedAt *time.Time     `json:"applied_at,omitempty"`
}

type Incident struct {
	ID              string         `json:"id"`
	Events          []FailureEvent `json:"events"`
	State           string         `json:"state"`
	SuggestedAction []string       `json:"suggested_action"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type RepairPlan struct {
	Command     string   `json:"command"`
	DryRunSteps []string `json:"dry_run_steps"`
	ApplySteps  []string `json:"apply_steps"`
	Confidence  float64  `json:"confidence"`
	GeneratedBy string   `json:"generated_by,omitempty"`
	GeneratedAt time.Time `json:"generated_at,omitempty"`
}

type Playbook struct {
	ID              string   `json:"id"`
	IncidentID      string   `json:"incident_id"`
	Steps           []string `json:"steps"`
	ApprovalsNeeded int      `json:"approvals_needed"`
	AutoApply       bool     `json:"auto_apply"`
	CreatedAt       time.Time `json:"created_at"`
	Status          string   `json:"status"`
}

type RCAHook func(ev FailureEvent) (RepairPlan, error)

type ToolMeta struct {
	ID        string            `json:"id"`
	Source    string            `json:"source"`
	Metadata  map[string]any    `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
	Built     bool              `json:"built"`
	Binary    string            `json:"binary,omitempty"`
}

type BuildResult struct {
	ToolID string `json:"tool_id"`
	OK     bool   `json:"ok"`
	Log    string `json:"log"`
}
type DeployResult struct {
	ToolID  string `json:"tool_id"`
	Target  string `json:"target"`
	DryRun  bool   `json:"dry_run"`
	Success bool   `json:"success"`
	Log     string `json:"log"`
}
type RunResult struct {
	ToolID string `json:"tool_id"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	OK     bool   `json:"ok"`
}

type PatchProposal struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Patch     string    `json:"patch"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
	Applied   bool      `json:"applied"`
}

type SelfHealSafetyPolicy struct {
	MaxAutoRepairsPerWindow int  `json:"max_auto_repairs_per_window"`
	MaxToolDeployPerHour    int  `json:"max_tool_deploy_per_hour"`
	RequireApprovalForProd  bool `json:"require_approval_for_prod"`
}

// SelfHealingManager main struct
type SelfHealingManager struct {
	mu               sync.RWMutex
	events           []FailureEvent
	actions          []RepairAction
	incidents        map[string]*Incident
	patches          map[string]*PatchProposal
	tools            map[string]*ToolMeta
	rcaHook          RCAHook
	repairPlugins    map[string]func(ev FailureEvent) (RepairAction, error)
	telemetry        func(evt string, meta map[string]any)
	storeDir         string
	approvalCh       chan string
	approvals        map[string]time.Time // keyed by "toolID:target" -> expiry
	safety           SelfHealSafetyPolicy
	actionMu         sync.Mutex
	toolDeployCounts map[string]int // per-hour counter keyed by hour string

	// build locks per tool
	toolBuildLocks map[string]*sync.Mutex
	toolBuildMu    sync.Mutex

	// background control
	stopBg    chan struct{}
	stopBgMux sync.Mutex
	wg        sync.WaitGroup
}

// NewSelfHealingManager constructs manager
func NewSelfHealingManager(storeDir string) *SelfHealingManager {
	_ = os.MkdirAll(storeDir, 0o750)
	sh := &SelfHealingManager{
		events:           []FailureEvent{},
		actions:          []RepairAction{},
		incidents:        map[string]*Incident{},
		patches:          map[string]*PatchProposal{},
		tools:            map[string]*ToolMeta{},
		repairPlugins:    map[string]func(ev FailureEvent) (RepairAction, error){},
		storeDir:         storeDir,
		approvalCh:       make(chan string, 100),
		approvals:        map[string]time.Time{},
		safety:           SelfHealSafetyPolicy{MaxAutoRepairsPerWindow: 5, MaxToolDeployPerHour: 5, RequireApprovalForProd: true},
		toolDeployCounts: map[string]int{},
		toolBuildLocks:   map[string]*sync.Mutex{},
		stopBg:           make(chan struct{}),
	}
	// start background cleanup for hourly counters
	sh.wg.Add(1)
	go func() {
		defer sh.wg.Done()
		sh.deployCountsCleaner()
	}()
	// start approval cleanup
	sh.wg.Add(1)
	go func() {
		defer sh.wg.Done()
		sh.approvalCleaner()
	}()
	return sh
}

// Shutdown gracefully stops background workers
func (s *SelfHealingManager) Shutdown(ctx context.Context) error {
	s.stopBgMux.Lock()
	select {
	case <-s.stopBg:
		// already closed
	default:
		close(s.stopBg)
	}
	s.stopBgMux.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deployCountsCleaner periodically cleans outdated hourly counters
func (s *SelfHealingManager) deployCountsCleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			nowHour := time.Now().Format("2006-01-02T15")
			s.mu.Lock()
			for k := range s.toolDeployCounts {
				if k != nowHour {
					delete(s.toolDeployCounts, k)
				}
			}
			s.mu.Unlock()
		case <-s.stopBg:
			return
		}
	}
}

// approvalCleaner removes expired approvals
func (s *SelfHealingManager) approvalCleaner() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, t := range s.approvals {
				if now.After(t) {
					delete(s.approvals, k)
				}
			}
			s.mu.Unlock()
		case <-s.stopBg:
			return
		}
	}
}

// ReportFailure ingests a failure and creates/updates incident
func (s *SelfHealingManager) ReportFailure(ev FailureEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev.Timestamp = time.Now()
	s.events = append(s.events, ev)
	incID := fmt.Sprintf("inc-%s-%d", ev.NodeID, time.Now().Unix())
	inc := &Incident{
		ID:        incID,
		Events:    []FailureEvent{ev},
		State:     "open",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	s.incidents[inc.ID] = inc
	if s.telemetry != nil {
		s.telemetry("failure_reported", map[string]any{"incident": inc.ID})
	}
}

// RegisterRCAHook registers RCA function
func (s *SelfHealingManager) RegisterRCAHook(fn RCAHook) {
	s.mu.Lock()
	s.rcaHook = fn
	s.mu.Unlock()
}

// SuggestRepair uses RCA hook or fallback heuristics
func (s *SelfHealingManager) SuggestRepair(ev FailureEvent) (RepairPlan, error) {
	if s.rcaHook != nil {
		plan, err := s.rcaHook(ev)
		if err == nil {
			return plan, nil
		}
	}
	switch ev.Type {
	case "node_down":
		return RepairPlan{
			Command:     fmt.Sprintf("reboot-node --node=%s", ev.NodeID),
			DryRunSteps: []string{"notify", "simulate_reboot"},
			ApplySteps:  []string{"drain", "reboot", "verify"},
			Confidence:  0.6,
			GeneratedAt: time.Now(),
		}, nil
	case "job_failed":
		return RepairPlan{
			Command:     "reschedule-job",
			DryRunSteps: []string{"gather_logs", "simulate_reschedule"},
			ApplySteps:  []string{"reschedule", "verify"},
			Confidence:  0.5,
			GeneratedAt: time.Now(),
		}, nil
	default:
		return RepairPlan{Command: "noop", DryRunSteps: []string{"noop"}, ApplySteps: []string{"noop"}, Confidence: 0.1, GeneratedAt: time.Now()}, nil
	}
}

// ApplyRepair executes a RepairPlan (supports dryRun). It returns RepairAction result.
func (s *SelfHealingManager) ApplyRepair(ctx context.Context, plan RepairPlan, actor string, dryRun bool) (RepairAction, error) {
	action := RepairAction{
		ID:        fmt.Sprintf("act-%d", time.Now().UnixNano()),
		CreatedAt: time.Now(),
		Actor:     actor,
		Command:   plan.Command,
		Success:   false,
	}
	s.actionMu.Lock()
	s.actions = append(s.actions, action)
	s.actionMu.Unlock()
	if s.telemetry != nil {
		s.telemetry("repair_apply", map[string]any{"action": action.ID, "dry_run": dryRun})
	}
	if dryRun {
		action.Log = "dry-run simulated"
		action.Success = true
		t := time.Now()
		action.AppliedAt = &t
		s.actionMu.Lock()
		for i := range s.actions {
			if s.actions[i].ID == action.ID {
				s.actions[i] = action
				break
			}
		}
		s.actionMu.Unlock()
		return action, nil
	}
	select {
	case <-ctx.Done():
		return action, ctx.Err()
	case <-time.After(500 * time.Millisecond):
		action.Success = true
		action.Log = "executed simulated"
		t := time.Now()
		action.AppliedAt = &t
		s.actionMu.Lock()
		for i := range s.actions {
			if s.actions[i].ID == action.ID {
				s.actions[i] = action
				break
			}
		}
		s.actionMu.Unlock()
		return action, nil
	}
}

// GeneratePlaybook builds a Playbook from incident using SuggestRepair
func (s *SelfHealingManager) GeneratePlaybook(incidentID string) (Playbook, error) {
	s.mu.RLock()
	_, ok := s.incidents[incidentID]
	s.mu.RUnlock()
	if !ok {
		return Playbook{}, errors.New("incident not found")
	}
	pb := Playbook{
		ID:              fmt.Sprintf("pb-%d", time.Now().UnixNano()),
		IncidentID:      incidentID,
		Steps:           []string{"notify_oncall", "dry_run_repair", "apply_repair", "verify_health"},
		ApprovalsNeeded: 1,
		AutoApply:       false,
		CreatedAt:       time.Now(),
		Status:          "pending",
	}
	return pb, nil
}

// ApplyPlaybook applies playbook (requires approvals if safety policy requires)
func (s *SelfHealingManager) ApplyPlaybook(ctx context.Context, pb Playbook, autoApprove bool, dryRun bool, actor string) ([]RepairAction, error) {
	if s.safety.RequireApprovalForProd && !autoApprove && !dryRun {
		return nil, errors.New("approval required for prod actions")
	}
	actions := []RepairAction{}
	for i, step := range pb.Steps {
		act := RepairAction{
			ID:        fmt.Sprintf("%s-step-%d", pb.ID, i),
			CreatedAt: time.Now(),
			Actor:     actor,
			Command:   step,
			Success:   false,
		}
		if dryRun {
			act.Log = "dry-run " + step
			act.Success = true
		} else {
			act.Log = "executed " + step
			act.Success = true
			t := time.Now()
			act.AppliedAt = &t
		}
		s.actionMu.Lock()
		s.actions = append(s.actions, act)
		s.actionMu.Unlock()
		actions = append(actions, act)
	}
	pb.Status = "applied"
	return actions, nil
}

// --- Tool management (workspace under storeDir/tools/<toolID>) ---

func (s *SelfHealingManager) toolsDir() string {
	return filepath.Join(s.storeDir, "tools")
}

func (s *SelfHealingManager) CreateTool(toolID string, source string, metadata map[string]any) error {
	dir := filepath.Join(s.toolsDir(), toolID)
	_ = os.MkdirAll(dir, 0o750)
	srcPath := filepath.Join(dir, "src.txt")
	tmp := srcPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(source), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, srcPath); err != nil {
		return err
	}
	meta := &ToolMeta{ID: toolID, Source: source, Metadata: metadata, CreatedAt: time.Now(), Built: false, Binary: ""}
	s.mu.Lock()
	s.tools[toolID] = meta
	s.mu.Unlock()
	return nil
}

func (s *SelfHealingManager) ValidateTool(toolID string) (map[string]any, error) {
	s.mu.RLock()
	meta, ok := s.tools[toolID]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("tool not found")
	}
	if len(meta.Source) > 1024*200 {
		return map[string]any{"ok": false, "reason": "source too large"}, nil
	}
	dangerous := []string{"rm -rf", ":(){:|:&};:", "dd if=", "mkfs.", "forkbomb", "wget ", "curl "}
	for _, d := range dangerous {
		if strings.Contains(meta.Source, d) {
			return map[string]any{"ok": false, "reason": "contains dangerous patterns"}, nil
		}
	}
	return map[string]any{"ok": true}, nil
}

// ApproveDeploy records an approval for a specific toolID:target by approver (with expiry).
// expiryDuration if zero defaults to 24h.
func (s *SelfHealingManager) ApproveDeploy(toolID, target, approver string, expiryDuration time.Duration) {
	if expiryDuration <= 0 {
		expiryDuration = 24 * time.Hour
	}
	key := fmt.Sprintf("%s:%s", toolID, target)
	exp := time.Now().Add(expiryDuration)
	s.mu.Lock()
	s.approvals[key] = exp
	s.mu.Unlock()
	if s.telemetry != nil {
		s.telemetry("deploy_approved", map[string]any{"tool_id": toolID, "target": target, "approver": approver, "expiry": exp.Format(time.RFC3339), "ts": time.Now().Format(time.RFC3339)})
	}
}

// isApproved checks whether the deploy is approved and not expired.
func (s *SelfHealingManager) isApproved(toolID, target string) bool {
	key := fmt.Sprintf("%s:%s", toolID, target)
	s.mu.RLock()
	exp, ok := s.approvals[key]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(exp)
}

// copyFileAtomic copies src->dst via tmp file and rename, preserving mode and syncing.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	fi, err := in.Stat()
	if err != nil {
		return err
	}

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	// flush to disk
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// atomically replace target
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// computeFileSHA256 returns hex string or error
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runExternalScanner runs a scanner command (limited set) and returns output and error.
func runExternalScanner(ctx context.Context, scannerCmd string, workingDir string) (string, error) {
	if scannerCmd == "" {
		return "", nil
	}
	// Restrict scanner commands to known scanners to avoid arbitrary command execution.
	lower := strings.ToLower(scannerCmd)
	if !(strings.Contains(lower, "trivy") || strings.Contains(lower, "syft")) {
		return "", fmt.Errorf("scanner not allowed: %s", scannerCmd)
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", scannerCmd)
	cmd.Dir = workingDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// lockTool returns an unlock function to protect building the same tool concurrently.
func (s *SelfHealingManager) lockTool(toolID string) func() {
	s.toolBuildMu.Lock()
	m, ok := s.toolBuildLocks[toolID]
	if !ok {
		m = &sync.Mutex{}
		s.toolBuildLocks[toolID] = m
	}
	s.toolBuildMu.Unlock()
	m.Lock()
	return func() { m.Unlock() }
}

// BuildTool attempts to build the tool practically.
// Supports metadata["use_container"]=true to build inside Docker (if available).
// Supports metadata["scanner_cmd"] limited to known scanners (trivy/syft).
func (s *SelfHealingManager) BuildTool(toolID string, timeoutSeconds int) (BuildResult, error) {
	// ensure single build per toolID
	unlock := s.lockTool(toolID)
	defer unlock()

	if s.telemetry != nil {
		s.telemetry("build_requested", map[string]any{"tool_id": toolID, "ts": time.Now().Format(time.RFC3339)})
	}

	s.mu.RLock()
	meta, ok := s.tools[toolID]
	s.mu.RUnlock()
	if !ok {
		return BuildResult{}, errors.New("tool not found")
	}
	val, _ := s.ValidateTool(toolID)
	if okv, _ := val["ok"].(bool); !okv {
		if s.telemetry != nil {
			s.telemetry("build_finished", map[string]any{"tool_id": toolID, "ok": false, "reason": val})
		}
		return BuildResult{ToolID: toolID, OK: false, Log: fmt.Sprintf("validation failed: %v", val)}, nil
	}

	dir := filepath.Join(s.toolsDir(), toolID)
	_ = os.MkdirAll(dir, 0o750)
	ts := time.Now().Unix()
	binDir := filepath.Join(dir, "bin")
	_ = os.MkdirAll(binDir, 0o750)
	tmpDir, err := os.MkdirTemp(dir, "buildtmp-")
	if err != nil {
		return BuildResult{ToolID: toolID, OK: false, Log: err.Error()}, err
	}
	defer os.RemoveAll(tmpDir)

	// Write source correctly: write main.go only if Go package main detected.
	if strings.Contains(meta.Source, "package main") {
		_ = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(meta.Source), 0o640)
	} else {
		_ = os.WriteFile(filepath.Join(tmpDir, "src.txt"), []byte(meta.Source), 0o640)
	}

	buildCmd := ""
	if meta.Metadata != nil {
		if v, ok := meta.Metadata["build_cmd"].(string); ok && v != "" {
			buildCmd = v
		}
	}
	// scanner support
	scannerCmd := ""
	if meta.Metadata != nil {
		if v, ok := meta.Metadata["scanner_cmd"].(string); ok && v != "" {
			scannerCmd = v
		}
	}

	useContainer := false
	if meta.Metadata != nil {
		if v, ok := meta.Metadata["use_container"].(bool); ok && v {
			useContainer = true
		}
	}

	// optional container resource limits
	containerArgs := []string{}
	if meta.Metadata != nil {
		if mem, ok := meta.Metadata["container_memory"].(string); ok && mem != "" {
			containerArgs = append(containerArgs, "--memory", mem)
		}
		if cpus, ok := meta.Metadata["container_cpus"].(string); ok && cpus != "" {
			// docker uses --cpus
			containerArgs = append(containerArgs, "--cpus", cpus)
		}
	}

	timeout := 60 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	if s.telemetry != nil {
		s.telemetry("build_started", map[string]any{"tool_id": toolID, "use_container": useContainer, "ts": time.Now().Format(time.RFC3339)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var out []byte
	var cmdErr error
	expectedBin := filepath.Join(binDir, fmt.Sprintf("%s-%d", toolID, ts))

	if useContainer {
		// Build inside Docker (requires docker available). Respect build_cmd if provided.
		_ = os.MkdirAll(filepath.Join(tmpDir, "bin"), 0o750)
		var innerCmd string
		if buildCmd != "" {
			innerCmd = buildCmd
		} else if strings.Contains(meta.Source, "package main") {
			innerCmd = fmt.Sprintf("mkdir -p /work/bin && cd /work && go build -o /work/bin/%s .", filepath.Base(expectedBin))
		} else {
			innerCmd = "sh /work/script.sh || true"
		}
		img := "golang:1.21"
		if meta.Metadata != nil {
			if v, ok := meta.Metadata["build_image"].(string); ok && v != "" {
				img = v
			}
		}
		// Build docker args slice to avoid shell injection and quoting issues.
		args := []string{"run", "--rm", "-v", tmpDir + ":/work", "-w", "/work", "--network", "none", "--user", "1000:1000"}
		// append optional resource limits
		if len(containerArgs) > 0 {
			args = append(args, containerArgs...)
		}
		args = append(args, img, "/bin/sh", "-c", innerCmd)
		c := exec.CommandContext(ctx, "docker", args...)
		out, cmdErr = c.CombinedOutput()
		// After run, try to move produced files from tmpDir/bin to expectedBin
		if cmdErr == nil {
			srcBinDir := filepath.Join(tmpDir, "bin")
			files, _ := os.ReadDir(srcBinDir)
			for _, f := range files {
				src := filepath.Join(srcBinDir, f.Name())
				dst := expectedBin
				if err := copyFileAtomic(src, dst); err != nil {
					continue
				}
				_ = os.Chmod(dst, 0o750)
				expectedBin = dst
				break
			}
		}
	} else {
		// host build path
		if buildCmd != "" {
			c := exec.CommandContext(ctx, "/bin/sh", "-c", buildCmd)
			c.Dir = tmpDir
			out, cmdErr = c.CombinedOutput()
		} else if strings.Contains(meta.Source, "package main") {
			c := exec.CommandContext(ctx, "go", "build", "-o", expectedBin, ".")
			c.Dir = tmpDir
			out, cmdErr = c.CombinedOutput()
		} else {
			scriptPath := filepath.Join(tmpDir, "script.sh")
			_ = os.WriteFile(scriptPath, []byte(meta.Source), 0o640)
			_ = os.Chmod(scriptPath, 0o750)
			c := exec.CommandContext(ctx, "/bin/sh", scriptPath)
			c.Dir = tmpDir
			out, cmdErr = c.CombinedOutput()
			// copy any produced files
			files, _ := os.ReadDir(tmpDir)
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				src := filepath.Join(tmpDir, f.Name())
				dst := filepath.Join(binDir, f.Name())
				_ = copyFileAtomic(src, dst)
				info, _ := os.Stat(dst)
				if info != nil && info.Mode()&0111 != 0 {
					expectedBin = dst
					break
				}
			}
		}
	}

	log := string(out)

	// scanner: only allow known scanners
	if cmdErr == nil && scannerCmd != "" {
		scannerOut, scanErr := runExternalScanner(ctx, scannerCmd, tmpDir)
		if s.telemetry != nil {
			s.telemetry("scanner_finished", map[string]any{"tool_id": toolID, "ok": scanErr == nil, "log": scannerOut, "ts": time.Now().Format(time.RFC3339)})
		}
		if scanErr != nil {
			log = log + "\n\nscanner:\n" + scannerOut
			if s.telemetry != nil {
				s.telemetry("build_finished", map[string]any{"tool_id": toolID, "ok": false, "log": log, "scanner_err": scanErr.Error(), "ts": time.Now().Format(time.RFC3339)})
			}
			return BuildResult{ToolID: toolID, OK: false, Log: log}, fmt.Errorf("scanner failed: %w", scanErr)
		}
	}

	// finalize: check expectedBin exists
	built := false
	sha := ""
	if fi, e := os.Stat(expectedBin); e == nil {
		_ = os.Chmod(expectedBin, fi.Mode()|0111)
		if h, e2 := computeFileSHA256(expectedBin); e2 == nil {
			sha = h
		}
		s.mu.Lock()
		meta.Built = true
		meta.Binary = expectedBin
		s.tools[toolID] = meta
		s.mu.Unlock()
		built = true
	} else {
		files, _ := os.ReadDir(binDir)
		for _, f := range files {
			dst := filepath.Join(binDir, f.Name())
			info, _ := os.Stat(dst)
			if info != nil && info.Mode()&0111 != 0 {
				if h, e2 := computeFileSHA256(dst); e2 == nil {
					sha = h
				}
				s.mu.Lock()
				meta.Built = true
				meta.Binary = dst
				s.tools[toolID] = meta
				s.mu.Unlock()
				expectedBin = dst
				built = true
				break
			}
		}
	}

	if cmdErr != nil && !built {
		if s.telemetry != nil {
			s.telemetry("build_finished", map[string]any{"tool_id": toolID, "ok": false, "log": log, "error": cmdErr.Error(), "ts": time.Now().Format(time.RFC3339)})
		}
		return BuildResult{ToolID: toolID, OK: false, Log: fmt.Sprintf("build error: %v\n%s", cmdErr, log)}, cmdErr
	}

	// telemetry: build finished
	if s.telemetry != nil {
		s.telemetry("build_finished", map[string]any{
			"tool_id": toolID,
			"ok":      built,
			"log":     log,
			"binary":  meta.Binary,
			"sha256":  sha,
			"ts":      time.Now().Format(time.RFC3339),
		})
	}

	if !built {
		s.mu.Lock()
		meta.Built = false
		meta.Binary = ""
		s.tools[toolID] = meta
		s.mu.Unlock()
	}

	return BuildResult{ToolID: toolID, OK: built, Log: log}, nil
}

// DeployTool deploys built binary to a target inside the sandboxed storeDir.
// If dryRun=true it only validates and returns the plan.
// Deploy to 'prod' target requires prior approval (ApproveDeploy).
func (s *SelfHealingManager) DeployTool(toolID string, target string, dryRun bool) (DeployResult, error) {
	s.mu.RLock()
	meta, ok := s.tools[toolID]
	s.mu.RUnlock()
	if !ok {
		return DeployResult{}, errors.New("tool not found")
	}
	if meta.Binary == "" {
		return DeployResult{}, errors.New("tool not built")
	}
	if s.telemetry != nil {
		s.telemetry("deploy_requested", map[string]any{"tool_id": toolID, "target": target, "dry_run": dryRun, "ts": time.Now().Format(time.RFC3339)})
	}
	lowerTarget := strings.ToLower(target)
	if s.safety.RequireApprovalForProd && (strings.Contains(lowerTarget, "prod") || strings.Contains(lowerTarget, "/prod/")) {
		if !s.isApproved(toolID, target) {
			return DeployResult{}, errors.New("deploy to prod target requires approval")
		}
	}

	nowHour := time.Now().Format("2006-01-02T15")
	s.mu.Lock()
	count := s.toolDeployCounts[nowHour]
	if count >= s.safety.MaxToolDeployPerHour {
		s.mu.Unlock()
		return DeployResult{}, errors.New("deploy quota exceeded")
	}
	s.toolDeployCounts[nowHour] = count + 1
	s.mu.Unlock()

	targetPath := filepath.Join(s.storeDir, filepath.Clean(target))
	absBase := filepath.Clean(s.storeDir)
	if targetPath != absBase && !strings.HasPrefix(targetPath, absBase+string(os.PathSeparator)) {
		return DeployResult{}, errors.New("target outside sandbox")
	}
	if dryRun {
		res := DeployResult{ToolID: toolID, Target: targetPath, DryRun: true, Success: true, Log: "dry-run ok"}
		if s.telemetry != nil {
			s.telemetry("deploy_finished", map[string]any{"tool_id": toolID, "target": targetPath, "success": res.Success, "dry_run": true, "ts": time.Now().Format(time.RFC3339)})
		}
		return res, nil
	}
	tmp := targetPath + ".tmp"
	if err := copyFileAtomic(meta.Binary, tmp); err != nil {
		res := DeployResult{ToolID: toolID, Target: targetPath, DryRun: false, Success: false, Log: err.Error()}
		if s.telemetry != nil {
			s.telemetry("deploy_finished", map[string]any{"tool_id": toolID, "target": targetPath, "success": false, "log": err.Error(), "ts": time.Now().Format(time.RFC3339)})
		}
		return res, err
	}
	if err := os.Rename(tmp, targetPath); err != nil {
		res := DeployResult{ToolID: toolID, Target: targetPath, DryRun: false, Success: false, Log: err.Error()}
		if s.telemetry != nil {
			s.telemetry("deploy_finished", map[string]any{"tool_id": toolID, "target": targetPath, "success": false, "log": err.Error(), "ts": time.Now().Format(time.RFC3339)})
		}
		return res, err
	}

	sha := ""
	if h, e := computeFileSHA256(targetPath); e == nil {
		sha = h
	}

	res := DeployResult{ToolID: toolID, Target: targetPath, DryRun: false, Success: true, Log: "deployed"}
	if s.telemetry != nil {
		s.telemetry("deploy_finished", map[string]any{
			"tool_id": toolID,
			"target":  targetPath,
			"success": true,
			"log":     "deployed",
			"sha256":  sha,
			"ts":      time.Now().Format(time.RFC3339),
		})
	}
	return res, nil
}

// RunTool executes tool (actual execution) with timeout and returns outputs
// IMPORTANT: Execute inside sandbox in production.
func (s *SelfHealingManager) RunTool(ctx context.Context, toolID string, args []string, timeout time.Duration, dryRun bool) (RunResult, error) {
	s.mu.RLock()
	meta, ok := s.tools[toolID]
	s.mu.RUnlock()
	if !ok {
		return RunResult{}, errors.New("tool not found")
	}
	if dryRun {
		if s.telemetry != nil {
			s.telemetry("run_finished", map[string]any{"tool_id": toolID, "ok": true, "dry_run": true, "ts": time.Now().Format(time.RFC3339)})
		}
		return RunResult{ToolID: toolID, Stdout: "dry-run stdout", Stderr: "", OK: true}, nil
	}
	if meta.Binary == "" {
		return RunResult{}, errors.New("no binary to run")
	}
	if s.telemetry != nil {
		s.telemetry("run_started", map[string]any{"tool_id": toolID, "binary": meta.Binary, "args": args, "ts": time.Now().Format(time.RFC3339)})
	}

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx2, meta.Binary)
	if len(args) > 0 {
		cmd = exec.CommandContext(ctx2, meta.Binary, args...)
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return RunResult{}, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return RunResult{}, err
	}
	if err := cmd.Start(); err != nil {
		return RunResult{}, err
	}

	outCh := make(chan []byte)
	errCh := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(stdoutPipe)
		outCh <- b
	}()
	go func() {
		b, _ := io.ReadAll(stderrPipe)
		errCh <- b
	}()

	outB := <-outCh
	errB := <-errCh

	err = cmd.Wait()
	res := RunResult{ToolID: toolID, Stdout: string(outB), Stderr: string(errB), OK: err == nil}

	if s.telemetry != nil {
		s.telemetry("run_finished", map[string]any{
			"tool_id": toolID,
			"ok":      res.OK,
			"stdout":  res.Stdout,
			"stderr":  res.Stderr,
			"ts":      time.Now().Format(time.RFC3339),
		})
	}
	return res, err
}

// ProposePatch writes patch proposal atomically
func (s *SelfHealingManager) ProposePatch(path string, patch string, author string) (string, error) {
	id := fmt.Sprintf("patch-%d", time.Now().UnixNano())
	pp := &PatchProposal{ID: id, Path: path, Patch: patch, Author: author, CreatedAt: time.Now(), Applied: false}
	s.mu.Lock()
	s.patches[id] = pp
	s.mu.Unlock()
	dir := filepath.Join(s.storeDir, "patches")
	_ = os.MkdirAll(dir, 0o750)
	b, _ := json.MarshalIndent(pp, "", "  ")
	tmp := filepath.Join(dir, id+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(dir, id+".json")); err != nil {
		return "", err
	}
	return id, nil
}

func (s *SelfHealingManager) ValidatePatch(patchID string) (bool, map[string]any, error) {
	s.mu.RLock()
	pp, ok := s.patches[patchID]
	s.mu.RUnlock()
	if !ok {
		return false, nil, errors.New("patch not found")
	}
	if len(pp.Patch) > 1024*500 {
		return false, map[string]any{"reason": "patch too large"}, nil
	}
	if strings.Contains(pp.Path, "..") || filepath.IsAbs(pp.Path) {
		return false, map[string]any{"reason": "invalid target path"}, nil
	}
	return true, map[string]any{"ok": true}, nil
}

// ApplyPatch applies patch (atomic write) optionally dryRun
func (s *SelfHealingManager) ApplyPatch(patchID string, dryRun bool) (string, error) {
	s.mu.RLock()
	pp, ok := s.patches[patchID]
	s.mu.RUnlock()
	if !ok {
		return "", errors.New("patch not found")
	}
	if dryRun {
		return "dry-run applied (simulated)", nil
	}
	absBase := filepath.Clean(s.storeDir)
	target := filepath.Clean(filepath.Join(absBase, pp.Path))
	if target != absBase && !strings.HasPrefix(target, absBase+string(os.PathSeparator)) {
		return "", errors.New("patch target outside sandbox")
	}
	tmp := target + ".tmp"
	_ = os.MkdirAll(filepath.Dir(target), 0o750)
	if err := os.WriteFile(tmp, []byte(pp.Patch), 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", err
	}
	pp.Applied = true
	s.mu.Lock()
	s.patches[patchID] = pp
	s.mu.Unlock()
	return "applied", nil
}

// RegisterRepairPlugin allows dynamic registration of fix strategies
func (s *SelfHealingManager) RegisterRepairPlugin(pluginID string, impl func(ev FailureEvent) (RepairAction, error)) {
	s.mu.Lock()
	s.repairPlugins[pluginID] = impl
	s.mu.Unlock()
}

// SetSafetyPolicy sets runtime safety policy
func (s *SelfHealingManager) SetSafetyPolicy(p SelfHealSafetyPolicy) {
	s.mu.Lock()
	s.safety = p
	s.mu.Unlock()
}

// ListActions and GetActionLog
func (s *SelfHealingManager) ListActions() []RepairAction {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	cp := make([]RepairAction, len(s.actions))
	copy(cp, s.actions)
	return cp
}

func (s *SelfHealingManager) GetActionLog(actionID string) (RepairAction, bool) {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	for _, a := range s.actions {
		if a.ID == actionID {
			return a, true
		}
	}
	return RepairAction{}, false
}

// ExportReport for incident
func (s *SelfHealingManager) ExportReport(incidentID string) ([]byte, error) {
	s.mu.RLock()
	inc, ok := s.incidents[incidentID]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("incident not found")
	}
	return json.MarshalIndent(inc, "", "  ")
}

// RegisterTelemetry
func (s *SelfHealingManager) RegisterTelemetry(fn func(evt string, meta map[string]any)) {
	s.mu.Lock()
	s.telemetry = fn
	s.mu.Unlock()
}

// ModuleMeta
func (s *SelfHealingManager) ModuleMeta() ModuleInfo {
	return ModuleInfo{
		Name:         "selfhealing",
		Version:      "v1.4",
		Capabilities: []string{"rca", "playbooks", "tool_builder", "patches", "approval", "build", "deploy", "run", "shutdown"},
		Health:       "ok",
	}
}

// ExposeFunctions
func (s *SelfHealingManager) ExposeFunctions() map[string]any {
	return map[string]any{
		"report_failure":     s.ReportFailure,
		"suggest_repair":     s.SuggestRepair,
		"apply_repair":       s.ApplyRepair,
		"generate_playbook":  s.GeneratePlaybook,
		"apply_playbook":     s.ApplyPlaybook,
		"create_tool":        s.CreateTool,
		"validate_tool":      s.ValidateTool,
		"build_tool":         s.BuildTool,
		"deploy_tool":        s.DeployTool,
		"run_tool":           s.RunTool,
		"propose_patch":      s.ProposePatch,
		"validate_patch":     s.ValidatePatch,
		"apply_patch":        s.ApplyPatch,
		"register_rca":       s.RegisterRCAHook,
		"register_plugin":    s.RegisterRepairPlugin,
		"list_events":        s.ListEvents,
		"list_actions":       s.ListActions,
		"get_action_log":     s.GetActionLog,
		"export_report":      s.ExportReport,
		"set_safety_policy":  s.SetSafetyPolicy,
		"register_telemetry": s.RegisterTelemetry,
		"approve_deploy":     s.ApproveDeploy,
		"shutdown":           s.Shutdown,
	}
}

// ListEvents returns recent events snapshot
func (s *SelfHealingManager) ListEvents() []FailureEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]FailureEvent, len(s.events))
	copy(cp, s.events)
	return cp
}