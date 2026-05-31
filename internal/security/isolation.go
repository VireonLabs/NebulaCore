// internal/security/isolation.go
// Adaptive Isolation Manager with policy CRUD, persistence (atomic JSON),
// simulation vs enforce modes, audit log and ExposeFunctions for AI Orchestrator.
package security

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

// IsolationType and Policy
type IsolationType string

const (
	IsolateContainer IsolationType = "container"
	IsolateVM        IsolationType = "vm"
	IsolateTEE       IsolationType = "tee"
)

type IsolationPolicy struct {
	ID         string        `json:"id"`
	Type       IsolationType `json:"type"`
	UserID     string        `json:"user_id,omitempty"`
	ProjectID  string        `json:"project_id,omitempty"`
	Strictness int           `json:"strictness,omitempty"` // 0..10
	EnforceAt  time.Time     `json:"enforce_at,omitempty"`
	ExpiresAt  time.Time     `json:"expires_at,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// SimulationReport returned by EvaluatePolicy
type SimulationReport struct {
	TargetID string   `json:"target_id"`
	PolicyID string   `json:"policy_id"`
	Effects  []string `json:"effects"`
	Warnings []string `json:"warnings"`
	OK       bool     `json:"ok"`
}

// IsolationAuditEvent for policy changes and applications
type IsolationAuditEvent struct {
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor,omitempty"`
	Action   string    `json:"action"`
	TargetID string    `json:"target_id,omitempty"`
	PolicyID string    `json:"policy_id,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Enforcer signature for applying a policy (context-aware)
type Enforcer func(ctx context.Context, policy IsolationPolicy) error

// IsolationManager central manager
type IsolationManager struct {
	mu        sync.RWMutex
	policies  map[string]IsolationPolicy // policyID -> policy
	mode      string                    // "simulate" or "enforce"
	enforcers map[IsolationType]Enforcer
	audit     []IsolationAuditEvent
	auditMu   sync.RWMutex
	storeDir  string
}

// NewIsolationManager creates manager and loads persisted policies if available.
func NewIsolationManager(storeDir string) *IsolationManager {
	im := &IsolationManager{
		policies:  map[string]IsolationPolicy{},
		mode:      "simulate",
		enforcers: map[IsolationType]Enforcer{},
		audit:     []IsolationAuditEvent{},
		storeDir:  storeDir,
	}
	// create dir
	_ = os.MkdirAll(storeDir, 0o750)
	// default enforcers (placeholders)
	im.enforcers[IsolateContainer] = func(ctx context.Context, p IsolationPolicy) error { return nil }
	im.enforcers[IsolateVM] = func(ctx context.Context, p IsolationPolicy) error { return nil }
	im.enforcers[IsolateTEE] = func(ctx context.Context, p IsolationPolicy) error { return nil }

	// try load file (non-fatal)
	_ = im.loadPoliciesFromDisk()
	return im
}

// ---- Persistence helpers (atomic write) ----

func (im *IsolationManager) policyFilePath() string {
	return filepath.Join(im.storeDir, "isolation_policies.json")
}

func (im *IsolationManager) persistPoliciesToDisk() error {
	im.mu.RLock()
	defer im.mu.RUnlock()
	tmp := im.policyFilePath() + ".tmp"
	b, err := json.MarshalIndent(im.policies, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, im.policyFilePath())
}

func (im *IsolationManager) loadPoliciesFromDisk() error {
	path := im.policyFilePath()
	b, err := os.ReadFile(path)
	if err != nil {
		// return error to caller; constructor ignores non-fatal
		return err
	}
	var data map[string]IsolationPolicy
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	im.mu.Lock()
	for k, v := range data {
		im.policies[k] = v
	}
	im.mu.Unlock()
	return nil
}

// ---- Audit helpers ----

func (im *IsolationManager) addAudit(a IsolationAuditEvent) {
	im.auditMu.Lock()
	im.audit = append(im.audit, a)
	im.auditMu.Unlock()
}

// ListAudit returns audit events for a target (empty target returns all)
func (im *IsolationManager) ListAudit(targetID string) []IsolationAuditEvent {
	im.auditMu.RLock()
	defer im.auditMu.RUnlock()
	if targetID == "" {
		cp := make([]IsolationAuditEvent, len(im.audit))
		copy(cp, im.audit)
		return cp
	}
	out := []IsolationAuditEvent{}
	for _, e := range im.audit {
		if e.TargetID == targetID {
			out = append(out, e)
		}
	}
	return out
}

// ---- ValidatePolicy ----

// ValidatePolicy ensures basic constraints
func (im *IsolationManager) ValidatePolicy(p IsolationPolicy) error {
	if p.Strictness < 0 || p.Strictness > 10 {
		return errors.New("strictness out of range (0..10)")
	}
	if p.Type != IsolateContainer && p.Type != IsolateVM && p.Type != IsolateTEE {
		return errors.New("unknown isolation type")
	}
	if p.ID == "" {
		return errors.New("policy id required")
	}
	// optional: ensure meta types are sensible (example)
	if p.Meta != nil {
		// example: ensure "require_attestation" if present is boolean
		if v, ok := p.Meta["require_attestation"]; ok {
			if _, ok2 := v.(bool); !ok2 {
				return errors.New("meta.require_attestation must be boolean")
			}
		}
	}
	return nil
}

// ---- CRUD operations ----

func (im *IsolationManager) CreatePolicy(p IsolationPolicy, actor string) error {
	if p.ID == "" {
		return errors.New("policy id required")
	}
	if err := im.ValidatePolicy(p); err != nil {
		return err
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	im.mu.Lock()
	defer im.mu.Unlock()
	if _, exists := im.policies[p.ID]; exists {
		return errors.New("policy already exists")
	}
	im.policies[p.ID] = p
	_ = im.persistPoliciesToDisk()
	im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "create_policy", PolicyID: p.ID, Detail: "created"})
	return nil
}

func (im *IsolationManager) UpdatePolicy(id string, p IsolationPolicy, actor string) error {
	if err := im.ValidatePolicy(p); err != nil {
		return err
	}
	im.mu.Lock()
	defer im.mu.Unlock()
	if _, ok := im.policies[id]; !ok {
		return errors.New("policy not found")
	}
	p.UpdatedAt = time.Now()
	im.policies[id] = p
	_ = im.persistPoliciesToDisk()
	im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "update_policy", PolicyID: id})
	return nil
}

func (im *IsolationManager) GetPolicy(id string) (IsolationPolicy, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	p, ok := im.policies[id]
	return p, ok
}

func (im *IsolationManager) ListPolicies() []IsolationPolicy {
	im.mu.RLock()
	defer im.mu.RUnlock()
	out := make([]IsolationPolicy, 0, len(im.policies))
	for _, p := range im.policies {
		out = append(out, p)
	}
	return out
}

func (im *IsolationManager) DeletePolicy(id string, actor string) error {
	im.mu.Lock()
	defer im.mu.Unlock()
	if _, ok := im.policies[id]; !ok {
		return errors.New("policy not found")
	}
	delete(im.policies, id)
	_ = im.persistPoliciesToDisk()
	im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "delete_policy", PolicyID: id})
	return nil
}

// ---- Mode and Evaluate ----

func (im *IsolationManager) SetMode(mode string) error {
	if mode != "simulate" && mode != "enforce" {
		return errors.New("invalid mode")
	}
	im.mu.Lock()
	im.mode = mode
	im.mu.Unlock()
	im.addAudit(IsolationAuditEvent{Time: time.Now(), Action: "set_mode", Detail: mode})
	return nil
}

func (im *IsolationManager) EvaluatePolicy(targetID string, p IsolationPolicy) (SimulationReport, error) {
	// Lightweight simulation: create hints of what would change
	report := SimulationReport{
		TargetID: targetID,
		PolicyID: p.ID,
		Effects:  []string{},
		Warnings: []string{},
		OK:       true,
	}
	// example checks
	if p.Strictness > 8 && p.Type == IsolateContainer {
		report.Warnings = append(report.Warnings, "high strictness on container may require VM-level isolation")
	}
	// check enforcer availability
	if _, ok := im.enforcers[p.Type]; !ok {
		report.Warnings = append(report.Warnings, "no enforcer registered for this isolation type; simulation only")
		report.OK = false
	}
	return report, nil
}

// ---- Application of policies ----

func (im *IsolationManager) ApplyPolicy(ctx context.Context, targetID string, policyID string, actor string) error {
	im.mu.RLock()
	p, ok := im.policies[policyID]
	mode := im.mode
	enf := im.enforcers[p.Type]
	im.mu.RUnlock()
	if !ok {
		return errors.New("policy not found")
	}
	// simulate first if mode is simulate
	if mode == "simulate" {
		rep, _ := im.EvaluatePolicy(targetID, p)
		im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "apply_policy_simulate", TargetID: targetID, PolicyID: policyID, Detail: fmt.Sprintf("%+v", rep)})
		return nil
	}
	// enforce path uses enforcer and waits for completion
	if enf == nil {
		return errors.New("no enforcer for type")
	}
	errCh := make(chan error, 1)
	go func() {
		err := enf(ctx, p)
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "apply_policy_failed", TargetID: targetID, PolicyID: policyID, Detail: err.Error()})
			return err
		}
		im.addAudit(IsolationAuditEvent{Time: time.Now(), Actor: actor, Action: "apply_policy_enforced", TargetID: targetID, PolicyID: policyID})
		return nil
	}
}

// RegisterEnforcer allows runtime enforcers to be registered
func (im *IsolationManager) RegisterEnforcer(itype IsolationType, f Enforcer) {
	im.mu.Lock()
	im.enforcers[itype] = f
	im.mu.Unlock()
	im.addAudit(IsolationAuditEvent{Time: time.Now(), Action: "register_enforcer", Detail: string(itype)})
}

// SnapshotPolicies returns JSON snapshot of policies
func (im *IsolationManager) SnapshotPolicies() ([]byte, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return json.MarshalIndent(im.policies, "", "  ")
}

// Module meta and expose

func (im *IsolationManager) ModuleMeta() ModuleInfo {
	return ModuleInfo{
		Name:         "isolation",
		Version:      "v1.1",
		Capabilities: []string{"policy_crud", "simulate", "enforce", "audit", "validate"},
		Health:       "ok",
	}
}

func (im *IsolationManager) ExposeFunctions() map[string]any {
	return map[string]any{
		"create_policy":     im.CreatePolicy,
		"update_policy":     im.UpdatePolicy,
		"delete_policy":     im.DeletePolicy,
		"get_policy":        im.GetPolicy,
		"list_policies":     im.ListPolicies,
		"apply_policy":      im.ApplyPolicy,
		"evaluate_policy":   im.EvaluatePolicy,
		"set_mode":          im.SetMode,
		"register_enforcer": im.RegisterEnforcer,
		"list_audit":        im.ListAudit,
		"snapshot_policies": im.SnapshotPolicies,
		"validate_policy":   im.ValidatePolicy,
	}
}