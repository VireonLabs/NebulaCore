package security

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"
)

// Alert represents an enforcement alert.
type Alert struct {
	Timestamp time.Time
	Source    string
	Severity  string
	Message   string
	Meta      map[string]string
}

// AlertStore interface for persistent alerts.
type AlertStore interface {
	Save(a Alert) error
}

// PolicyStore holds allow/deny maps with RW locking.
type PolicyStore struct {
	allowPaths map[string]bool
	denyPaths  map[string]bool
	mu         sync.RWMutex
}

// EnforcementManager orchestrates enforcement with async verification pipeline.
type EnforcementManager struct {
	ks             KeystoreGetter
	auditor        AuditorIface
	cosignVerifier *InternalCosignVerifier
	attestor       Attestor
	policy         *PolicyStore
	alertStore     AlertStore
	FailClosed     bool
}

// AuditorIface small subset for enforcement to append events.
type AuditorIface interface {
	AppendEvent(ctx context.Context, ev *AuditEvent) error
}

func NewEnforcementManagerWithDeps(ks KeystoreGetter, auditor AuditorIface, cosign *InternalCosignVerifier, att Attestor, alertStore AlertStore) *EnforcementManager {
	return &EnforcementManager{
		ks:             ks,
		auditor:        auditor,
		cosignVerifier: cosign,
		attestor:       att,
		policy:         &PolicyStore{allowPaths: make(map[string]bool), denyPaths: make(map[string]bool)},
		alertStore:     alertStore,
		FailClosed:     true,
	}
}

// VetPolicy is a quick static vet; real implementation is richer.
func (e *EnforcementManager) VetPolicy(p interface{}) error {
	// placeholder: reject overly broad deny rules
	return nil
}

// EnforceExecution enforces policy on attempted exec; returns true to allow, false to block.
// Uses canonicalization and a bounded timeout for signature verification to avoid blocking startup.
func (e *EnforcementManager) EnforceExecution(ctx context.Context, path string, pid int) bool {
	path = filepath.Clean(path)
	e.policy.mu.RLock()
	if e.policy.allowPaths[path] {
		e.policy.mu.RUnlock()
		return true
	}
	if e.policy.denyPaths[path] {
		e.policy.mu.RUnlock()
		e.recordExecutionDenied(path, pid, "denylist")
		return false
	}
	e.policy.mu.RUnlock()

	// Attestation check
	if e.attestor != nil {
		if !e.attestor.VerifyLocalNode() {
			e.recordExecutionDenied(path, pid, "attestation_failed")
			return false
		}
	}

	// Cosign verification with timeout to avoid blocking.
	if e.cosignVerifier == nil {
		if e.FailClosed {
			e.recordExecutionDenied(path, pid, "no_cosign_verifier")
			return false
		}
		return true
	}
	verCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	okCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		ok, err := e.cosignVerifier.VerifyArtifact(path, path+".sig", "cosign_pub_default")
		if err != nil {
			errCh <- err
			return
		}
		okCh <- ok
	}()
	select {
	case <-verCtx.Done():
		if e.FailClosed {
			e.recordExecutionDenied(path, pid, "signature_timeout")
			return false
		}
		e.reportExecutionWarning(path, pid, "signature_timeout_but_allowed")
		return true
	case err := <-errCh:
		if e.FailClosed {
			e.recordExecutionDenied(path, pid, "signature_error")
			log.Printf("cosign verify error: %v", err)
			return false
		}
		e.reportExecutionWarning(path, pid, "signature_error_but_allowed")
		return true
	case ok := <-okCh:
		if !ok {
			if e.FailClosed {
				e.recordExecutionDenied(path, pid, "signature_invalid")
				return false
			}
			e.reportExecutionWarning(path, pid, "signature_invalid_but_allowed_dev")
			return true
		}
	}
	return true
}

func (e *EnforcementManager) recordExecutionDenied(path string, pid int, reason string) {
	msg := fmt.Sprintf("blocked exec %s pid=%d reason=%s", path, pid, reason)
	log.Println("[enforce]", msg)
	a := Alert{
		Timestamp: time.Now(),
		Source:    "enforcement",
		Severity:  "CRITICAL",
		Message:   msg,
		Meta:      map[string]string{"path": path, "pid": fmt.Sprintf("%d", pid), "reason": reason},
	}
	_ = e.pushAlert(a)
	if e.auditor != nil {
		ev := &AuditEvent{
			Timestamp: time.Now(),
			Source:    "enforcement",
			Action:    "block_exec",
			Details:   map[string]interface{}{"path": path, "pid": pid, "reason": reason},
		}
		_ = e.auditor.AppendEvent(context.Background(), ev)
	}
}

func (e *EnforcementManager) reportExecutionWarning(path string, pid int, reason string) {
	msg := fmt.Sprintf("warn exec %s pid=%d reason=%s", path, pid, reason)
	log.Println("[enforce-warn]", msg)
	a := Alert{
		Timestamp: time.Now(),
		Source:    "enforcement",
		Severity:  "WARN",
		Message:   msg,
		Meta:      map[string]string{"path": path, "pid": fmt.Sprintf("%d", pid), "reason": reason},
	}
	_ = e.pushAlert(a)
}

func (e *EnforcementManager) pushAlert(a Alert) error {
	if e.alertStore != nil {
		return e.alertStore.Save(a)
	}
	log.Printf("[alert-store-fallback] %v", a)
	return nil
}

// Shutdown called on coordinator stop
func (e *EnforcementManager) Shutdown() {
	// flush persistent queues if any
}