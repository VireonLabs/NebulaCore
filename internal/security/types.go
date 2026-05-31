package security

import (
	"context"
	"sync"
)

// AIEntropyProvider defines the interface for an AI-based entropy source.
type AIEntropyProvider interface {
	Name() string
	GetEntropy(ctx context.Context, size int) ([]byte, float64, error)
}

// AttestationProvider defines the interface for hardware/remote attestation.
type AttestationProvider interface {
	Name() string
	Attest(ctx context.Context, nonce []byte) ([]byte, error)
}

// EntropyAggregator collects and mixes entropy from multiple sources.
type EntropyAggregator struct {
	Mu      sync.RWMutex
	Entropy []byte
}

func NewEntropyAggregator() *EntropyAggregator {
	return &EntropyAggregator{
		Entropy: make([]byte, 0),
	}
}

func (a *EntropyAggregator) Mix(sources ...[]byte) []byte {
	// Implementation of entropy mixing
	return nil
}

func (a *EntropyAggregator) Collect() []byte {
	a.Mu.RLock()
	defer a.Mu.RUnlock()
	return a.Entropy
}

// KeystoreGetter is used for accessing the keystore.
type KeystoreGetter interface {
	GetKeystore() any
}
