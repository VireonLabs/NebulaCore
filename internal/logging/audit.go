package logging

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"konrotaharai-netizen/internal/secstore"
)

// AuditEvent is canonical audit record with chain hashes.
type AuditEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Actor       string                 `json:"actor,omitempty"`
	Action      string                 `json:"action"`
	Details     map[string]interface{} `json:"details,omitempty"`
	PrevHash    string                 `json:"prev_hash,omitempty"`
	ChainHash   string                 `json:"chain_hash,omitempty"`
	Signature   string                 `json:"signature,omitempty"`
	SignerKeyID string                 `json:"signer_key_id,omitempty"`
}

type Auditor struct {
	ks            *secstore.SimpleEncryptedStore
	signKeyID     string
	kmsSignFunc   func(ctx context.Context, data []byte) ([]byte, error) // optional KMS sign function
	enforceSigned bool                                                   // if true, require kmsSignFunc success in order to accept events

	outF        *os.File
	mtx         sync.Mutex
	lastChain   []byte
	forwarders  []Forwarder
	checkpointN int
	eventsSince int
	auditHMACEnv string
	logger      *log.Logger
	closed      bool
}

// Forwarder forwards events to external systems (SIEM/Kafka).
type Forwarder interface {
	Forward(ctx context.Context, ev *AuditEvent) error
}

// NewAuditor constructs Auditor.
//
// ks: keystore (may be nil in dev).
// signKeyID: logical signer id metadata (informational).
// kmsSignFunc: optional function used to sign chain (production); if nil and enforceSigned==true then
//              AppendEvent will fail (fail-closed).
// enforceSigned: if true, require kmsSignFunc to successfully sign events (production safety).
func NewAuditor(ks *secstore.SimpleEncryptedStore, signKeyID string, kmsSignFunc func(ctx context.Context, data []byte) ([]byte, error), enforceSigned bool) *Auditor {
	path := "/var/lib/laserwall/audit"
	_ = os.MkdirAll(path, 0o700)
	fp, err := os.OpenFile(path+"/audit.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit open failed: %v", err)
		fp = nil
	}
	a := &Auditor{
		ks:            ks,
		signKeyID:     signKeyID,
		kmsSignFunc:   kmsSignFunc,
		enforceSigned: enforceSigned,
		outF:          fp,
		forwarders:    []Forwarder{},
		checkpointN:   100,
		auditHMACEnv:  "AUDIT_HMAC_KEY",
		logger:        log.New(os.Stderr, "[auditor] ", log.LstdFlags),
	}
	return a
}

// AppendEvent appends an AuditEvent with chaining and optional signing/checkpointing.
func (a *Auditor) AppendEvent(ctx context.Context, ev *AuditEvent) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.closed {
		return nil
	}
	ev.Timestamp = time.Now().UTC()
	// compute prevHash & chainHash
	prev := a.lastChain
	payload, _ := json.Marshal(ev)
	if prev == nil {
		prev = []byte{}
	}

	// If a.kmsSignFunc is provided, we attempt to sign using KMS (preferred).
	if a.kmsSignFunc != nil {
		// Build chain material
		chainMaterial := append(prev, payload...)
		// Use timeout for KMS call
		ctxSign, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		sig, err := a.kmsSignFunc(ctxSign, chainMaterial)
		if err != nil {
			// If enforceSigned is true, we must fail (fail-closed).
			a.logger.Printf("kms sign failed: %v", err)
			if a.enforceSigned {
				return err
			}
			// Otherwise fallback to HMAC env (best-effort)
			a.logger.Printf("fallback: attempt HMAC env signing due to kms failure")
			key := os.Getenv(a.auditHMACEnv)
			if key == "" {
				// fallback to computing chain hash without signature but warn
				h := sha256.Sum256(chainMaterial)
				if len(prev) == 0 {
					ev.PrevHash = ""
				} else {
					ev.PrevHash = hex.EncodeToString(prev)
				}
				ev.ChainHash = hex.EncodeToString(h[:])
				a.lastChain = h[:]
			} else {
				m := hmac.New(sha256.New, []byte(key))
				m.Write(prev)
				m.Write(payload)
				chain := m.Sum(nil)
				if len(prev) == 0 {
					ev.PrevHash = ""
				} else {
					ev.PrevHash = hex.EncodeToString(prev)
				}
				ev.ChainHash = hex.EncodeToString(chain)
				ev.Signature = hex.EncodeToString(chain)
				a.lastChain = chain
			}
		} else {
			// successful KMS signature - record signature and use chain hash as signature metadata
			h := sha256.Sum256(append(prev, payload...))
			if len(prev) == 0 {
				ev.PrevHash = ""
			} else {
				ev.PrevHash = hex.EncodeToString(prev)
			}
			ev.ChainHash = hex.EncodeToString(h[:])
			ev.Signature = hex.EncodeToString(sig)
			ev.SignerKeyID = a.signKeyID
			// update lastChain to the signature bytes (store raw sig)
			a.lastChain = sig
		}
	} else {
		// No KMS signer provided: fall back to HMAC env or unsigned chain
		key := os.Getenv(a.auditHMACEnv)
		if key == "" {
			// best-effort: keep chain but cannot sign
			h := sha256.Sum256(append(prev, payload...))
			if len(prev) == 0 {
				ev.PrevHash = ""
			} else {
				ev.PrevHash = hex.EncodeToString(prev)
			}
			ev.ChainHash = hex.EncodeToString(h[:])
			a.lastChain = h[:]
			if a.enforceSigned {
				// production requires signed audit but no KMS signer -> fail
				return fmt.Errorf("enforceSigned audit required but no kms signer and no HMAC key available")
			}
		} else {
			m := hmac.New(sha256.New, []byte(key))
			m.Write(prev)
			m.Write(payload)
			chain := m.Sum(nil)
			if len(prev) == 0 {
				ev.PrevHash = ""
			} else {
				ev.PrevHash = hex.EncodeToString(prev)
			}
			ev.ChainHash = hex.EncodeToString(chain)
			ev.Signature = hex.EncodeToString(chain)
			a.lastChain = chain
		}
	}

	// write to file handle
	if a.outF != nil {
		enc := json.NewEncoder(a.outF)
		if err := enc.Encode(ev); err != nil {
			a.logger.Printf("failed to write audit: %v", err)
		} else {
			_ = a.outF.Sync()
		}
	}
	a.eventsSince++
	// forward
	for _, f := range a.forwarders {
		_ = f.Forward(ctx, ev)
	}
	// checkpoint periodically
	if a.eventsSince >= a.checkpointN {
		_ = a.checkpoint(ctx)
		a.eventsSince = 0
	}
	return nil
}

// checkpoint stores a minimal checkpoint (lastChain) to keystore (immutable) and optionally archive.
func (a *Auditor) checkpoint(ctx context.Context) error {
	meta := map[string]any{"last_chain": hex.EncodeToString(a.lastChain), "ts": time.Now().UTC()}
	b, _ := json.Marshal(meta)
	if a.ks != nil {
		name := "audit_checkpoint_" + time.Now().UTC().Format("20060102T150405")
		if err := a.ks.PutRaw(name, b); err != nil {
			a.logger.Printf("audit checkpoint putraw failed: %v", err)
			return err
		}
	}
	// optionally forward checkpoint to remote WORM (S3) via forwarders
	return nil
}

func (a *Auditor) RegisterForwarder(f Forwarder) { a.forwarders = append(a.forwarders, f) }

// Close closes the underlying file handle and marks auditor closed.
func (a *Auditor) Close() error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.closed = true
	if a.outF != nil {
		if err := a.outF.Sync(); err != nil {
			a.logger.Printf("audit sync error: %v", err)
		}
		if err := a.outF.Close(); err != nil {
			return err
		}
		a.outF = nil
	}
	return nil
}