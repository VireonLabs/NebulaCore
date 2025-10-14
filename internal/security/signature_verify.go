package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidPubKey = errors.New("invalid public key")
	ErrSignatureBad  = errors.New("signature verification failed")
	ErrCertExpired   = errors.New("certificate not currently valid")
)

// VerifySignature verifies signature over message using a public PEM or certificate.
// algo: "ed25519","rsa","ecdsa".
func VerifySignature(pubPEM []byte, algo string, message, signature []byte) (bool, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return false, ErrInvalidPubKey
	}
	var pubI interface{}
	// try parse as certificate
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return false, ErrCertExpired
		}
		pubI = cert.PublicKey
		// optional: check key usage
	} else {
		pi, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, ErrInvalidPubKey
		}
		pubI = pi
	}
	switch algo {
	case "ed25519":
		ed, ok := pubI.(ed25519.PublicKey)
		if !ok {
			return false, ErrInvalidPubKey
		}
		if !ed25519.Verify(ed, message, signature) {
			return false, ErrSignatureBad
		}
		return true, nil
	case "rsa":
		rk, ok := pubI.(*rsa.PublicKey)
		if !ok {
			return false, ErrInvalidPubKey
		}
		h := sha256.Sum256(message)
		if err := rsa.VerifyPSS(rk, crypto.SHA256, h[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return false, ErrSignatureBad
		}
		return true, nil
	case "ecdsa":
		ek, ok := pubI.(*ecdsa.PublicKey)
		if !ok {
			return false, ErrInvalidPubKey
		}
		h := sha256.Sum256(message)
		if ok := ecdsa.VerifyASN1(ek, h[:], signature); !ok {
			return false, ErrSignatureBad
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported alg: %s", algo)
	}
}