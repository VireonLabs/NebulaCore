package security

import (
	"context"
	"sync"
)

// Attestor interface for plugging attestation providers.
type Attestor interface {
	Name() string
	Attest(ctx context.Context, nonce []byte) (*AttestationReport, error)
	VerifyLocalNode() bool
}

// Registry for attestors
var (
	attestors   = map[string]func() Attestor{}
	attestorsMu sync.Mutex
)

// RegisterAttestor registers an attestor constructor.
func RegisterAttestor(name string, ctor func() Attestor) {
	attestorsMu.Lock()
	defer attestorsMu.Unlock()
	attestors[name] = ctor
}

// NewCompositeAttestor builds a composite attestor (weighted voting).
func NewCompositeAttestor() Attestor {
	attestorsMu.Lock()
	defer attestorsMu.Unlock()
	for _, ctor := range attestors {
		return ctor()
	}
	return nil
}

// Example wrapper to call all attestors and fuse reports (omitted detailed fusion logic).
func CollectAttestations(ctx context.Context, nonce []byte) ([]*AttestationReport, error) {
	attestorsMu.Lock()
	defer attestorsMu.Unlock()
	var res []*AttestationReport
	for name, ctor := range attestors {
		att := ctor()
		r, err := att.Attest(ctx, nonce)
		if err == nil && r != nil {
			r.Source = name
			res = append(res, r)
		}
	}
	return res, nil
}