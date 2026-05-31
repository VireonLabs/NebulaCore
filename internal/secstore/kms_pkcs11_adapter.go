package secstore

import (
	"context"
	"fmt"

	"github.com/Aurionex/NebulaCore/transit/pkg/transit"
)
type KMSWrapper interface {
	Wrap(ctx context.Context, kekID string, dek []byte) ([]byte, string, error)
	Unwrap(ctx context.Context, kekID string, wrapped []byte) ([]byte, error)
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)
	Verify(ctx context.Context, keyID string, data []byte, sig []byte) (bool, error)
	Info() map[string]string
}

// PKCS11KMSAdapter adapts transit.PKCS11 provider to secstore.KMSWrapper interface.
type PKCS11KMSAdapter struct {
	prov transit.CryptoProvider
}

// NewPKCS11KMSAdapter constructs a PKCS#11 backed adapter.
// modulePath: path to PKCS#11 shared library
// tokenLabel, pin, aesLabel, signLabel: provider-specific identifiers (may be empty for defaults)
func NewPKCS11KMSAdapter(modulePath, tokenLabel, pin, aesLabel, signLabel string) (KMSWrapper, error) {
	prov, err := transit.NewPKCS11ProviderFull(modulePath, tokenLabel, pin, aesLabel, signLabel)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 provider init: %w", err)
	}
	return &PKCS11KMSAdapter{prov: prov}, nil
}

// Wrap uses provider.SealWithRoot to wrap a DEK.
func (a *PKCS11KMSAdapter) Wrap(ctx context.Context, kekID string, dek []byte) ([]byte, string, error) {
	// Use underlying provider.SealWithRoot; meta returned is HSM-specific; include kekID hint
	ct, err := a.prov.SealWithRoot(dek)
	if err != nil {
		return nil, "", err
	}
	meta := "pkcs11:wrapped"
	return ct, meta, nil
}

// Unwrap uses provider.UnsealWithRoot to recover the DEK.
func (a *PKCS11KMSAdapter) Unwrap(ctx context.Context, kekID string, wrapped []byte) ([]byte, error) {
	return a.prov.UnsealWithRoot(wrapped)
}

// Sign uses provider.Sign to produce a signature.
func (a *PKCS11KMSAdapter) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	return a.prov.Sign(data)
}

// Verify uses provider.Verify to validate a signature.
func (a *PKCS11KMSAdapter) Verify(ctx context.Context, keyID string, data []byte, sig []byte) (bool, error) {
	return a.prov.Verify(data, sig)
}

// Info returns adapter metadata
func (a *PKCS11KMSAdapter) Info() map[string]string {
	return map[string]string{"type": "pkcs11_adapter"}
}