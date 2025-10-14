package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

// InternalCosignVerifier verifies detached signatures over artifact digest.
type InternalCosignVerifier struct {
	ks KeystoreGetter
}

func NewInternalCosignVerifier(ks KeystoreGetter) *InternalCosignVerifier {
	return &InternalCosignVerifier{ks: ks}
}

// VerifyArtifact computes sha256 in a streaming manner and verifies signature (supports base64 encoded sig file or raw).
func (v *InternalCosignVerifier) VerifyArtifact(artifactPath, sigPath, pubKeyName string) (bool, error) {
	f, err := os.Open(artifactPath)
	if err != nil {
		return false, fmt.Errorf("artifact open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("artifact hash: %w", err)
	}
	hash := h.Sum(nil)

	sigB, err := os.ReadFile(sigPath)
	if err != nil {
		return false, fmt.Errorf("sig read: %w", err)
	}
	sigStr := strings.TrimSpace(string(sigB))
	var sig []byte
	if dec, derr := base64.StdEncoding.DecodeString(sigStr); derr == nil {
		sig = dec
	} else {
		sig = sigB
	}
	pubPEM, err := v.ks.GetRaw(pubKeyName)
	if err != nil {
		return false, fmt.Errorf("pubkey not found: %w", err)
	}
	ok, err := VerifySignature(pubPEM, "ed25519", hash, sig)
	if err != nil {
		return false, err
	}
	return ok, nil
}