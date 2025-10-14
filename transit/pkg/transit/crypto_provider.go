package transit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/curve25519"
)

// CryptoProvider defines operations needed by transit
type CryptoProvider interface {
	SealWithRoot(plaintext []byte) ([]byte, error)
	UnsealWithRoot(ciphertext []byte) ([]byte, error)
	Sign(msg []byte) ([]byte, error)
	Verify(msg, sig []byte) (bool, error)
	HybridEncrypt(recipientPub []byte, plaintext []byte) (ct []byte, meta []byte, err error)
	HybridDecrypt(priv []byte, ct []byte, meta []byte) ([]byte, error)
}

// SimpleSoftwareProvider is a fallback provider (for dev). In prod bind to TPM/HSM via PKCS#11
type SimpleSoftwareProvider struct {
	// root private key (for signing/wrapping) - in prod do NOT keep in memory; use TPM
	rootPriv []byte
	rootPub  []byte
}

func NewDefaultProvider(cfg Config) (CryptoProvider, error) {
	// for prototype: generate ephemeral root key (NOT for production)
	root := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, root); err != nil {
		return nil, err
	}
	pub, _ := curve25519.X25519(root, curve25519.Basepoint)
	return &SimpleSoftwareProvider{rootPriv: root, rootPub: pub}, nil
}

func (p *SimpleSoftwareProvider) SealWithRoot(plaintext []byte) ([]byte, error) {
	h := sha256.Sum256(p.rootPriv)
	key := h[:32]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return ct, nil
}

func (p *SimpleSoftwareProvider) UnsealWithRoot(ciphertext []byte) ([]byte, error) {
	h := sha256.Sum256(p.rootPriv)
	key := h[:32]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (p *SimpleSoftwareProvider) Sign(msg []byte) ([]byte, error) {
	h := sha256.Sum256(append(p.rootPriv, msg...))
	return h[:], nil
}

func (p *SimpleSoftwareProvider) Verify(msg, sig []byte) (bool, error) {
	exp, _ := p.Sign(msg)
	return bytes.Equal(exp, sig), nil
}

func (p *SimpleSoftwareProvider) HybridEncrypt(recipientPub []byte, plaintext []byte) (ct []byte, meta []byte, err error) {
	eph := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, eph); err != nil {
		return nil, nil, err
	}
	ephPub, _ := curve25519.X25519(eph, curve25519.Basepoint)
	shared, _ := curve25519.X25519(eph, recipientPub)
	key := sha256.Sum256(shared)
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	ct = gcm.Seal(nil, nonce, plaintext, nil)
	meta = append(ephPub, nonce...)
	return
}

func (p *SimpleSoftwareProvider) HybridDecrypt(priv []byte, ct []byte, meta []byte) ([]byte, error) {
	if len(meta) < 32 {
		return nil, errors.New("meta too short")
	}
	ephPub := meta[:32]
	nonce := meta[32:]
	shared, _ := curve25519.X25519(priv, ephPub)
	key := sha256.Sum256(shared)
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, nonce, ct, nil)
	return pt, err
}

// PKCS11Provider is a thin wrapper around a PKCS#11 module (SoftHSM) — example only.
type PKCS11Provider struct {
	ctx    *pkcs11.Ctx
	slot   uint
	session pkcs11.SessionHandle
	rootKeyHandle pkcs11.ObjectHandle
}

func NewPKCS11Provider(modulePath, tokenLabel string) (*PKCS11Provider, error) {
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: module init failed")
	}
	if err := ctx.Initialize(); err != nil {
		return nil, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: no slots")
	}
	// pick first slot for demo
	slot := slots[0]
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	// NOTE: login and object lookup left to integrator; we keep a stub
	return &PKCS11Provider{ctx: ctx, slot: slot, session: session}, nil
}

func (p *PKCS11Provider) SealWithRoot(plaintext []byte) ([]byte, error) {
	// Stub: production should call Sealing with wrapped key handle.
	return nil, fmt.Errorf("pkcs11 provider sealing not implemented in stub")
}
func (p *PKCS11Provider) UnsealWithRoot(ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("pkcs11 provider unsealing not implemented in stub")
}
func (p *PKCS11Provider) Sign(msg []byte) ([]byte, error) {
	return nil, fmt.Errorf("pkcs11 provider sign not implemented in stub")
}
func (p *PKCS11Provider) Verify(msg, sig []byte) (bool, error) {
	return false, fmt.Errorf("pkcs11 provider verify not implemented in stub")
}
func (p *PKCS11Provider) HybridEncrypt(recipientPub []byte, plaintext []byte) (ct []byte, meta []byte, err error) {
	return nil, nil, fmt.Errorf("pkcs11 hybrid not implemented")
}
func (p *PKCS11Provider) HybridDecrypt(priv []byte, ct []byte, meta []byte) ([]byte, error) {
	return nil, fmt.Errorf("pkcs11 hybrid not implemented")
}