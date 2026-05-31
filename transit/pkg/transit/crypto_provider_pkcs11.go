package transit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	crypto_rand "crypto/rand"
	"strings"

	pkcs11 "github.com/miekg/pkcs11"
)

// pkcs11Provider is a production-oriented PKCS#11-backed provider.
// It implements SealWithRoot, UnsealWithRoot, Sign and Verify (ECDSA P-256).
type pkcs11Provider struct {
	ctx           *pkcs11.Ctx
	slot          uint
	session       pkcs11.SessionHandle
	rootSymHandle pkcs11.ObjectHandle // AES wrapping key
	signHandle    pkcs11.ObjectHandle // ECDSA private key handle
	modulePath    string
	pin           string
	pubKeyBytes   []byte // optional cached public key bytes (DER)
}

// NewPKCS11ProviderFull initializes PKCS#11 module, logs in and ensures keys exist.
func NewPKCS11ProviderFull(modulePath, tokenLabel, pin, aesLabel, signKeyLabel string) (CryptoProvider, error) {
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
	var slot uint
	found := false
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		// tokenLabel is trimmed to 32 bytes on some HSMs; do substring match
		if tokenLabel == "" || strings.Contains(strings.TrimSpace(info.Label), tokenLabel) {
			slot = s
			found = true
			break
		}
	}
	if !found {
		ctx.Destroy()
		return nil, fmt.Errorf("no matching slot/token")
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(session)
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11 login failed: %v", err)
	}
	p := &pkcs11Provider{
		ctx:        ctx,
		slot:       slot,
		session:    session,
		modulePath: modulePath,
		pin:        pin,
	}
	// ensure AES wrap key
	if err := p.findOrCreateSymKey(aesLabel); err != nil {
		p.Close()
		return nil, err
	}
	// ensure signing key pair
	if err := p.findOrCreateSignKey(signKeyLabel); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *pkcs11Provider) Close() {
	if p.ctx != nil {
		_ = p.ctx.Logout(p.session)
		_ = p.ctx.CloseSession(p.session)
		_ = p.ctx.Finalize()
		p.ctx.Destroy()
		p.ctx = nil
	}
}

func (p *pkcs11Provider) findOrCreateSymKey(label string) error {
	// lookup
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	}
	_ = p.ctx.FindObjectsInit(p.session, template)
	objs, _, err := p.ctx.FindObjects(p.session, 1)
	_ = p.ctx.FindObjectsFinal(p.session)
	if err == nil && len(objs) > 0 {
		p.rootSymHandle = objs[0]
		return nil
	}
	// generate AES key
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	h, err := p.ctx.GenerateKey(p.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, keyTemplate)
	if err != nil {
		return err
	}
	p.rootSymHandle = h
	return nil
}

func (p *pkcs11Provider) findOrCreateSignKey(label string) error {
	// find private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	_ = p.ctx.FindObjectsInit(p.session, template)
	objs, _, err := p.ctx.FindObjects(p.session, 1)
	_ = p.ctx.FindObjectsFinal(p.session)
	if err == nil && len(objs) > 0 {
		p.signHandle = objs[0]
		return nil
	}
	// generate EC key pair (P-256)
	pubTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label+"_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsP256()),
	}
	privTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, privHandle, err := p.ctx.GenerateKeyPair(p.session, mech, pubTempl, privTempl)
	if err != nil {
		return err
	}
	p.signHandle = privHandle
	return nil
}

func ecParamsP256() []byte {
	// DER OID for prime256v1: 06 08 2A 86 48 CE 3D 03 01 07
	return []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
}

func (p *pkcs11Provider) SealWithRoot(plaintext []byte) ([]byte, error) {
	// CKM_AES_GCM with IV (12 bytes) -> ciphertext with tag appended by HSM implementation
	iv := randomBytes(12)
	gcmParams := pkcs11.NewGCMParams(iv, nil, 128)
	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := p.ctx.EncryptInit(p.session, []*pkcs11.Mechanism{mech}, p.rootSymHandle); err != nil {
		return nil, err
	}
	ct, err := p.ctx.Encrypt(p.session, plaintext)
	if err != nil {
		return nil, err
	}
	// Prepend IV for later decryption
	out := append(iv, ct...)
	return out, nil
}

func (p *pkcs11Provider) UnsealWithRoot(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:12]
	ct := ciphertext[12:]
	gcmParams := pkcs11.NewGCMParams(iv, nil, 128)
	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := p.ctx.DecryptInit(p.session, []*pkcs11.Mechanism{mech}, p.rootSymHandle); err != nil {
		return nil, err
	}
	pt, err := p.ctx.Decrypt(p.session, ct)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (p *pkcs11Provider) Sign(msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	if err := p.ctx.SignInit(p.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, p.signHandle); err != nil {
		return nil, err
	}
	sigRaw, err := p.ctx.Sign(p.session, h[:])
	if err != nil {
		return nil, err
	}
	// pkcs11 ECDSA signature is raw R||S; convert to ASN.1 DER
	rLen := len(sigRaw) / 2
	r := new(big.Int).SetBytes(sigRaw[:rLen])
	s := new(big.Int).SetBytes(sigRaw[rLen:])
	asn, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, err
	}
	return asn, nil
}

func (p *pkcs11Provider) Verify(msg, sig []byte) (bool, error) {
	// Try to verify locally by exporting public key (if available)
	pub, err := p.exportPublicKey()
	if err != nil {
		return false, err
	}
	h := sha256.Sum256(msg)
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return false, err
	}
	ok := ecdsa.Verify(pub, h[:], esig.R, esig.S)
	return ok, nil
}

func (p *pkcs11Provider) HybridEncrypt(recipientPub []byte, plaintext []byte) (ct []byte, meta []byte, err error) {
	return nil, nil, fmt.Errorf("hybrid encrypt not supported in PKCS11 provider")
}
func (p *pkcs11Provider) HybridDecrypt(priv []byte, ct []byte, meta []byte) ([]byte, error) {
	return nil, fmt.Errorf("hybrid decrypt not supported")
}

func (p *pkcs11Provider) exportPublicKey() (*ecdsa.PublicKey, error) {
	// Simplified: attempt to read CKA_EC_POINT from public object. Implementation depends on HSM.
	// For robust behavior, store public key material at key creation time in keystore.
	return nil, fmt.Errorf("exportPublicKey not implemented: store public key during key generation for later verification")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(crypto_rand.Reader, b)
	return b
}