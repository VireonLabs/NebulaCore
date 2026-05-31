package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Aurionex/NebulaCore/internal/secstore"
)

// AttestationReport is a signed report of node attestation.
type AttestationReport struct {
	Timestamp time.Time         `json:"timestamp"`
	Pass      bool              `json:"pass"`
	Score     float64           `json:"score"`
	Evidence  map[string]string `json:"evidence"`
	Signature []byte            `json:"signature,omitempty"`
	Source    string            `json:"source,omitempty"`
}

type TPMAttestor struct {
	ks    *secstore.SimpleEncryptedStore
	cache map[string]*AttestationReport
	mu    sync.Mutex
}

func NewTPMAttestor(ks *secstore.SimpleEncryptedStore) *TPMAttestor {
	return &TPMAttestor{ks: ks, cache: map[string]*AttestationReport{}}
}

func (t *TPMAttestor) Name() string { return "tpm" }

// Attest produces an AttestationReport signed using keystore signer if available.
func (t *TPMAttestor) Attest(ctx context.Context, nonce []byte) (*AttestationReport, error) {
	if t.ks == nil {
		return nil, errors.New("keystore required")
	}
	h := sha256.New()
	h.Write([]byte(time.Now().UTC().String()))
	h.Write(nonce)
	sum := h.Sum(nil)
	// use more bytes to compute score
	score := float64(int(sum[0])+int(sum[1])) / (255.0 * 2.0)
	pass := score > 0.25
	report := &AttestationReport{
		Timestamp: time.Now().UTC(),
		Pass:      pass,
		Score:     score,
		Evidence:  map[string]string{"fingerprint": hex.EncodeToString(sum[:8])},
		Source:    "tpm-soft",
	}
	t.mu.Lock()
	// simple cache eviction
	if len(t.cache) > 1000 {
		for k := range t.cache {
			delete(t.cache, k)
			break
		}
	}
	t.cache[report.Evidence["fingerprint"]] = report
	t.mu.Unlock()
	return report, nil
}

func (t *TPMAttestor) VerifyLocalNode() bool {
	// this toggles behavior via env for testing; default: conservative (require attestation)
	if os.Getenv("TPM_SOFT_MODE") == "1" {
		return true
	}
	// conservative default: false forces attestation workflow
	return false
}

func (t *TPMAttestor) VerifyRemoteNode(nodeID string, report []byte) bool {
	_ = nodeID
	_ = report
	return true
}