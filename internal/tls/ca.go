package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"konrotaharai-netizen/internal/secstore"
)

const (
	localCAKeyName  = "local_ca_key"
	localCACertName = "local_ca_cert"
)

// LocalCA holder for convenience
type LocalCA struct {
	Cert *x509.Certificate
	Priv crypto.PrivateKey
}

// LoadOrCreateLocalCA loads CA from keystore or creates one.
func LoadOrCreateLocalCA(ks *secstore.SimpleEncryptedStore) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if ks == nil {
		return nil, nil, fmt.Errorf("keystore required")
	}
	keyPEM, _ := ks.GetRaw(localCAKeyName)
	certPEM, _ := ks.GetRaw(localCACertName)
	if keyPEM != nil && certPEM != nil {
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, nil, fmt.Errorf("invalid private key PEM")
		}
		priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return nil, nil, fmt.Errorf("invalid cert PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return cert, priv, nil
	}
	priv, cert, err := createLocalCA()
	if err != nil {
		return nil, nil, err
	}
	// store
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := ks.PutRaw(localCAKeyName, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("failed store key: %w", err)
	}
	if err := ks.PutRaw(localCACertName, certPEM); err != nil {
		return nil, nil, fmt.Errorf("failed store cert: %w", err)
	}
	return cert, priv, nil
}

func createLocalCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"laserwall-local-ca"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return priv, cert, nil
}

// RotateCA rotates the CA and archives old CA into keystore with timestamped keys.
func RotateCA(ks *secstore.SimpleEncryptedStore) error {
	oldKey, _ := ks.GetRaw(localCAKeyName)
	oldCert, _ := ks.GetRaw(localCACertName)
	priv, cert, err := createLocalCA()
	if err != nil {
		return err
	}
	if oldKey != nil && oldCert != nil {
		ts := time.Now().UTC().Format("20060102T150405")
		if err := ks.PutRaw(localCAKeyName+"."+ts, oldKey); err != nil {
			return fmt.Errorf("archive old key failed: %w", err)
		}
		if err := ks.PutRaw(localCACertName+"."+ts, oldCert); err != nil {
			return fmt.Errorf("archive old cert failed: %w", err)
		}
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := ks.PutRaw(localCAKeyName, keyPEM); err != nil {
		return fmt.Errorf("store new key failed: %w", err)
	}
	if err := ks.PutRaw(localCACertName, certPEM); err != nil {
		return fmt.Errorf("store new cert failed: %w", err)
	}
	return nil
}