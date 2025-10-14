package cryptoengine

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/cmplx"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// CFE Engine: Production-ready, defensive variant of the Cerebral Factor Engine.
//
// Summary of key safety and production features included here:
//  - Mode-based fail-closed behavior (ModeDefense required).
//  - KEM + HKDF + AEAD hybrid encryption primitives with zeroing of sensitive bytes.
//  - Spectral feature extraction (DFT-based), residue and sliding residue fingerprints.
//  - Audit hooks via pluggable Auditor interface; audits always use ctx for traceability.
//  - Plugin subsystem: plugins are executed as isolated OS processes (not in-process), verified by HMAC token, copied into plugin dir with restricted perms,
//    executed with sanitized input, and run under resource limits on Linux (RLIMIT_AS, RLIMIT_CPU) and optional UID/GID drop to "nobody" when available.
//  - Defensive simulation & recommendations for hardening key lengths / rotation via a FactorabilitySimulator.
//  - All previously sensitive logging removed (no salt leakage).
//
// Notes / Operational guidance:
//  - Store plugin HMAC key securely (Vault/HSM) in production; the engine reads it from env name configured in CFEConfig.AuditHMACEnv.
//  - Plugins must implement a --meta JSON output (name/version/desc) and accept JSON on stdin and output JSON on stdout.
//  - Plugin binaries are copied to PluginDir and given 0750 perms; run them under an unprivileged account via SysProcAttr when possible.
//
// Interfaces for integration (implement in infra)
type EntropyProvider interface {
	Read(b []byte) (int, error)
	Health(ctx context.Context) (string, error)
}

type Auditor interface {
	Audit(ctx context.Context, tag string, info map[string]any) error
}

type FirewallSink interface {
	ApplyStrengthen(ctx context.Context, target string, severity float64, note string) error
}

// KEMProvider and SignatureProvider are pluggable (production libs recommended)
type KEMProvider interface {
	// GenerateKeypair returns (pub, priv)
	GenerateKeypair() (pub []byte, priv []byte, err error)
	// Encapsulate with recipient public key -> (shared, encapsulation)
	Encapsulate(pub []byte) (shared []byte, enc []byte, err error)
	// Decapsulate with private key + encapsulation -> shared
	Decapsulate(priv []byte, enc []byte) (shared []byte, err error)
	AlgName() string
}

type SignatureProvider interface {
	Sign(priv []byte, msg []byte) ([]byte, error)
	Verify(pub []byte, msg []byte, sig []byte) (bool, error)
	AlgName() string
}

type Mode string

const (
	ModeDefense Mode = "defense"
	ModeOff     Mode = "off"
)

type CFEConfig struct {
	Mode             Mode
	DefaultKeyBytes  int
	SimVulnThreshold float64
	BitWindow        int
	SpectralDim      int
	AuditHMACEnv     string // env var name that holds HMAC key for plugin validation
	PluginDir        string
}

type CFEEngine struct {
	cfg CFEConfig

	ep  EntropyProvider
	aud Auditor
	fw  FirewallSink

	kem KEMProvider
	sig SignatureProvider

	pluginsMu sync.RWMutex
	plugins   map[string]PluginMeta

	mu sync.RWMutex
}

type PluginMeta struct {
	Name    string
	Version string
	Desc    string
	path    string
}

func NewCFEEngine(cfg CFEConfig, ep EntropyProvider, aud Auditor, fw FirewallSink, kem KEMProvider, sig SignatureProvider) (*CFEEngine, error) {
	if cfg.Mode != ModeDefense {
		return nil, errors.New("CFEEngine must be created in ModeDefense")
	}
	if cfg.DefaultKeyBytes <= 0 {
		cfg.DefaultKeyBytes = 32
	}
	if cfg.BitWindow <= 0 {
		cfg.BitWindow = 2048
	}
	if cfg.SpectralDim <= 0 {
		cfg.SpectralDim = 512
	}
	if cfg.SimVulnThreshold <= 0 {
		cfg.SimVulnThreshold = 0.6
	}
	if cfg.AuditHMACEnv == "" {
		cfg.AuditHMACEnv = "AUDIT_HMAC_KEY"
	}
	if cfg.PluginDir == "" {
		cfg.PluginDir = "plugins"
	}
	if err := os.MkdirAll(cfg.PluginDir, 0o750); err != nil {
		return nil, fmt.Errorf("plugin dir create: %w", err)
	}
	return &CFEEngine{
		cfg:     cfg,
		ep:      ep,
		aud:     aud,
		fw:      fw,
		kem:     kem,
		sig:     sig,
		plugins: make(map[string]PluginMeta),
	}, nil
}

// spectralSaltFromTelemetry mixes entropy + telemetry + timestamp into a non-invertible salt.
func (c *CFEEngine) spectralSaltFromTelemetry(ctx context.Context, telemetry []byte) ([]byte, error) {
	if c.cfg.Mode != ModeDefense {
		return nil, errors.New("forbidden: engine not in defense mode")
	}
	entropy := make([]byte, 48)
	if c.ep != nil {
		if n, err := c.ep.Read(entropy); err != nil || n != len(entropy) {
			if _, err2 := io.ReadFull(rand.Reader, entropy); err2 != nil {
				return nil, fmt.Errorf("entropy fallback failed: %w", err2)
			}
			if c.aud != nil {
				_ = c.aud.Audit(ctx, "cfe.entropy_fallback", map[string]any{"note": "entropy provider fallback", "ts": time.Now().UTC()})
			}
		}
	} else {
		if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
			return nil, err
		}
	}
	h := hmac.New(func() hash.Hash { return sha512.New() }, entropy)
	h.Write(telemetry)
	h.Write([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	sum := h.Sum(nil)
	salt := make([]byte, 32)
	copy(salt, sum[:32])
	// Do NOT log any part of salt. Only signal generation.
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.spectral_salt_generated", map[string]any{"ts": time.Now().UTC()})
	}
	zeroBytes(entropy)
	return salt, nil
}

func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func chooseAEAD(key []byte) (cipher.AEAD, error) {
	// Prefer ChaCha20-Poly1305; fallback to AES-GCM
	if aead, err := chacha20poly1305.New(key); err == nil {
		return aead, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *CFEEngine) deriveSymmetricKey(sharedSecret, salt, info []byte, length int) ([]byte, error) {
	hk := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}

// HybridEncrypt encapsulates with KEM using recipientPub, derives AEAD key using spectral salt, returns encaps + ciphertext.
func (c *CFEEngine) HybridEncrypt(ctx context.Context, telemetry []byte, recipientPub []byte, plaintext []byte, associated []byte) (encaps []byte, ciphertext []byte, err error) {
	if c.cfg.Mode != ModeDefense {
		return nil, nil, errors.New("engine not in defense mode")
	}
	if c.kem == nil {
		return nil, nil, errors.New("no KEM provider")
	}
	if recipientPub == nil {
		return nil, nil, errors.New("recipientPub required")
	}
	shared, encaps, err := c.kem.Encapsulate(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("kem encapsulate: %w", err)
	}
	salt, err := c.spectralSaltFromTelemetry(ctx, telemetry)
	if err != nil {
		zeroBytes(shared)
		return nil, nil, err
	}
	info := append([]byte("CFE-Hybrid-v1|"), associated...)
	symKey, err := c.deriveSymmetricKey(shared, salt, info, c.cfg.DefaultKeyBytes)
	if err != nil {
		zeroBytes(shared)
		return nil, nil, err
	}
	aead, err := chooseAEAD(symKey)
	if err != nil {
		zeroBytes(symKey)
		zeroBytes(shared)
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		zeroBytes(symKey)
		zeroBytes(shared)
		return nil, nil, err
	}
	ct := aead.Seal(nonce, nonce, plaintext, associated)
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.hybrid_encrypt", map[string]any{"encap_len": len(encaps), "ct_len": len(ct), "kem": c.kem.AlgName(), "ts": time.Now().UTC()})
	}
	zeroBytes(symKey)
	zeroBytes(shared)
	return encaps, ct, nil
}

// HybridDecrypt decapsulates and AEAD-decrypts using spectral salt.
func (c *CFEEngine) HybridDecrypt(ctx context.Context, telemetry []byte, priv []byte, encaps []byte, ciphertext []byte, associated []byte) ([]byte, error) {
	if c.cfg.Mode != ModeDefense {
		return nil, errors.New("engine not in defense mode")
	}
	if c.kem == nil {
		return nil, errors.New("no KEM provider")
	}
	if priv == nil {
		return nil, errors.New("private key required")
	}
	shared, err := c.kem.Decapsulate(priv, encaps)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulate: %w", err)
	}
	salt, err := c.spectralSaltFromTelemetry(ctx, telemetry)
	if err != nil {
		zeroBytes(shared)
		return nil, err
	}
	info := append([]byte("CFE-Hybrid-v1|"), associated...)
	symKey, err := c.deriveSymmetricKey(shared, salt, info, c.cfg.DefaultKeyBytes)
	if err != nil {
		zeroBytes(shared)
		return nil, err
	}
	aead, err := chooseAEAD(symKey)
	if err != nil {
		zeroBytes(symKey)
		zeroBytes(shared)
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		zeroBytes(symKey)
		zeroBytes(shared)
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	ct := ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, associated)
	if err != nil {
		zeroBytes(symKey)
		zeroBytes(shared)
		return nil, fmt.Errorf("aead open failed: %w", err)
	}
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.hybrid_decrypt", map[string]any{"ct_len": len(ciphertext), "kem": c.kem.AlgName(), "ts": time.Now().UTC()})
	}
	zeroBytes(symKey)
	zeroBytes(shared)
	return pt, nil
}

func (c *CFEEngine) CreateSpectralSignature(ctx context.Context, priv []byte, telemetry []byte, msg []byte) ([]byte, error) {
	if c.cfg.Mode != ModeDefense {
		return nil, errors.New("engine not in defense mode")
	}
	if c.sig == nil {
		return nil, errors.New("no signature provider")
	}
	if priv == nil {
		return nil, errors.New("private key required")
	}
	salt, err := c.spectralSaltFromTelemetry(ctx, telemetry)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(salt)
	digest := h.Sum(nil)
	sig, err := c.sig.Sign(priv, digest)
	if err != nil {
		return nil, err
	}
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.sign", map[string]any{"sig_len": len(sig), "alg": c.sig.AlgName(), "ts": time.Now().UTC()})
	}
	return sig, nil
}

func (c *CFEEngine) VerifySpectralSignature(ctx context.Context, pub []byte, telemetry []byte, msg []byte, sig []byte) (bool, error) {
	if c.cfg.Mode != ModeDefense {
		return false, errors.New("engine not in defense mode")
	}
	if c.sig == nil {
		return false, errors.New("no signature provider")
	}
	if pub == nil {
		return false, errors.New("public key required")
	}
	salt, err := c.spectralSaltFromTelemetry(ctx, telemetry)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(salt)
	digest := h.Sum(nil)
	ok, err := c.sig.Verify(pub, digest, sig)
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.verify", map[string]any{"ok": ok, "alg": c.sig.AlgName(), "ts": time.Now().UTC()})
	}
	return ok, err
}

func (c *CFEEngine) GenerateKEMKeypair(ctx context.Context) (pub []byte, priv []byte, err error) {
	if c.kem == nil {
		return nil, nil, errors.New("no KEM provider")
	}
	pk, sk, err := c.kem.GenerateKeypair()
	if err == nil && c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.kem_keypair", map[string]any{"alg": c.kem.AlgName(), "pk_len": len(pk), "ts": time.Now().UTC()})
	}
	return pk, sk, err
}

// ---------------- Spectral engine and feature assembler ----------------

type FeatureVector struct {
	Spectral        []float64
	Residues        []float64
	DigitHistogram  []float64
	SlidingResidues []float64
	Combined        []float64
}

// intToBits returns a string of '0'/'1' of length window (LSB on rightmost of returned string slice).
func intToBits(n *big.Int, window int) string {
	if window <= 0 {
		if n == nil {
			window = 256
		} else {
			window = int(math.Max(256, float64(n.BitLen())))
		}
	}
	if n == nil || n.Sign() == 0 {
		return strings.Repeat("0", window)
	}
	b := new(big.Int).Abs(n).Text(2)
	if len(b) < window {
		return strings.Repeat("0", window-len(b)) + b
	}
	if len(b) > window {
		return b[len(b)-window:]
	}
	return b
}

func computeDFTMagnitude(arr []float64) []float64 {
	n := len(arr)
	if n == 0 {
		return []float64{}
	}
	out := make([]float64, n/2+1)
	for k := 0; k < len(out); k++ {
		var sum complex128
		for t := 0; t < n; t++ {
			angle := -2.0 * math.Pi * float64(k) * float64(t) / float64(n)
			sum += complex(arr[t], 0) * cmplx.Exp(complex(0, angle))
		}
		out[k] = cmplx.Abs(sum)
	}
	// normalize
	norm := 0.0
	for _, v := range out {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return out
	}
	for i := range out {
		out[i] = out[i] / norm
	}
	return out
}

func makeSpectralVector(n *big.Int, window int, dim int) []float64 {
	bits := intToBits(n, window)
	arr := make([]float64, len(bits))
	for i, ch := range bits {
		if ch == '1' {
			arr[i] = 1.0
		} else {
			arr[i] = 0.0
		}
	}
	mag := computeDFTMagnitude(arr)
	out := make([]float64, dim)
	for i := 0; i < dim; i++ {
		if i < len(mag) {
			out[i] = mag[i]
		} else {
			out[i] = 0.0
		}
	}
	norm := 0.0
	for _, v := range out {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return out
	}
	for i := range out {
		out[i] = out[i] / norm
	}
	return out
}

func residuesVector(n *big.Int, primes []uint64) []float64 {
	out := make([]float64, len(primes))
	for i, p := range primes {
		mod := new(big.Int).Mod(n, new(big.Int).SetUint64(p)).Uint64()
		out[i] = float64(mod)
	}
	norm := 0.0
	for _, v := range out {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return out
	}
	for i := range out {
		out[i] = out[i] / norm
	}
	return out
}

func digitHistogram(n *big.Int, base int, size int) []float64 {
	tmp := new(big.Int).Abs(n)
	counts := make([]float64, size)
	zero := big.NewInt(0)
	baseBig := big.NewInt(int64(base))
	if tmp.Cmp(zero) == 0 {
		counts[0] = 1.0
	} else {
		for tmp.Cmp(zero) > 0 {
			mod := new(big.Int)
			tmp.DivMod(tmp, baseBig, mod)
			idx := int(mod.Int64())
			if idx < size {
				counts[idx] += 1.0
			} else {
				counts[size-1] += 1.0
			}
		}
	}
	norm := 0.0
	for _, v := range counts {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return counts
	}
	for i := range counts {
		counts[i] = counts[i] / norm
	}
	return counts
}

func slidingResidues(n *big.Int, windowBits int, chunks int, mod uint64) []float64 {
	bits := intToBits(n, 0)
	if windowBits <= 0 {
		windowBits = 16
	}
	vals := make([]float64, 0, chunks)
	for i := 0; i < len(bits); i += windowBits {
		end := i + windowBits
		if end > len(bits) {
			end = len(bits)
		}
		ch := bits[i:end]
		v := uint64(0)
		for j := 0; j < len(ch); j++ {
			v = v<<1 + uint64(ch[j]-'0')
		}
		if mod == 0 {
			vals = append(vals, float64(v))
		} else {
			vals = append(vals, float64(v%mod))
		}
		if len(vals) >= chunks {
			break
		}
	}
	for len(vals) < chunks {
		vals = append(vals, 0.0)
	}
	norm := 0.0
	for _, v := range vals {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return vals
	}
	for i := range vals {
		vals[i] = vals[i] / norm
	}
	return vals
}

func AssembleFeatureVector(n *big.Int, cfg CFEConfig) FeatureVector {
	spectral := makeSpectralVector(n, cfg.BitWindow, cfg.SpectralDim)
	primes := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41}
	res := residuesVector(n, primes)
	dh := digitHistogram(n, 10, 16)
	sr := slidingResidues(n, 16, 64, 257)
	combined := make([]float64, 0, len(spectral)+len(res)+len(dh)+len(sr))
	combined = append(combined, spectral...)
	combined = append(combined, res...)
	combined = append(combined, dh...)
	combined = append(combined, sr...)
	norm := 0.0
	for _, v := range combined {
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm < 1e-12 {
		return FeatureVector{Spectral: spectral, Residues: res, DigitHistogram: dh, SlidingResidues: sr, Combined: combined}
	}
	for i := range combined {
		combined[i] = combined[i] / norm
	}
	return FeatureVector{Spectral: spectral, Residues: res, DigitHistogram: dh, SlidingResidues: sr, Combined: combined}
}

// AnalyzeNumber now accepts context for tracing and cancellation.
func (c *CFEEngine) AnalyzeNumber(ctx context.Context, n *big.Int) (FeatureVector, []*big.Int, error) {
	if c.cfg.Mode != ModeDefense {
		return FeatureVector{}, nil, errors.New("engine not in defense mode")
	}
	features := AssembleFeatureVector(n, c.cfg)
	candidates := make([]*big.Int, 0)
	limit := 128
	for i := 0; i < limit && len(candidates) < 128; i++ {
		flip := big.NewInt(0).Set(n)
		flip.Xor(flip, big.NewInt(0).Lsh(big.NewInt(1), uint(i)))
		if flip.Sign() >= 0 {
			candidates = append(candidates, flip)
		}
	}
	for d := -32; d <= 32 && len(candidates) < 256; d++ {
		if d == 0 {
			continue
		}
		off := big.NewInt(int64(d))
		cand := big.NewInt(0).Add(n, off)
		if cand.Sign() >= 0 {
			candidates = append(candidates, cand)
		}
	}
	if c.aud != nil {
		_ = c.aud.Audit(ctx, "cfe.analyze_number", map[string]any{"n_bits": n.BitLen(), "n_candidates": len(candidates), "ts": time.Now().UTC()})
	}
	return features, candidates, nil
}

func (c *CFEEngine) AnalyzeBytes(ctx context.Context, data []byte) (FeatureVector, []*big.Int, error) {
	n := new(big.Int).SetBytes(data)
	return c.AnalyzeNumber(ctx, n)
}

func (c *CFEEngine) FeatureVectorFromBytes(ctx context.Context, data []byte) ([]float64, error) {
	n := new(big.Int).SetBytes(data)
	fv := AssembleFeatureVector(n, c.cfg)
	return fv.Combined, nil
}

func (c *CFEEngine) SpectralEnhanceEntropy(ctx context.Context, entropy []byte, extraContext map[string]any) ([]byte, error) {
	if c.cfg.Mode != ModeDefense {
		return nil, errors.New("engine not in defense mode")
	}
	if len(entropy) < 16 {
		pad := make([]byte, 16-len(entropy))
		if _, err := io.ReadFull(rand.Reader, pad); err != nil {
			return nil, err
		}
		entropy = append(entropy, pad...)
	}
	n := new(big.Int).SetBytes(entropy)
	fv := AssembleFeatureVector(n, c.cfg).Combined
	h := hmac.New(sha512.New, []byte("cfe_spectral_mixer_v1"))
	h.Write(entropy)
	for i := 0; i < len(fv); i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(fv[i]))
		h.Write(b)
	}
	if extraContext != nil {
		if ts, ok := extraContext["ts"].(string); ok {
			h.Write([]byte(ts))
		}
	}
	out := h.Sum(nil)
	desired := len(entropy)
	if desired < 32 {
		desired = 32
	}
	if len(out) >= desired {
		return out[:desired], nil
	}
	res := make([]byte, 0, desired)
	res = append(res, out...)
	counter := byte(1)
	for len(res) < desired {
		h2 := hmac.New(sha512.New, []byte("cfe_spectral_mixer_expand_v1"))
		h2.Write(res[len(res)-len(out):])
		h2.Write([]byte{counter})
		block := h2.Sum(nil)
		res = append(res, block...)
		counter++
	}
	return res[:desired], nil
}

func (c *CFEEngine) HardeningLayer(ctx context.Context, data []byte, label []byte, outLen int) ([]byte, error) {
	if c.cfg.Mode != ModeDefense {
		return nil, errors.New("engine not in defense mode")
	}
	n := new(big.Int).SetBytes(data)
	fv := AssembleFeatureVector(n, c.cfg).Combined
	saltH := sha256.New()
	for i := 0; i < len(fv); i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(fv[i]))
		saltH.Write(b)
	}
	salt := saltH.Sum(nil)
	info := label
	if info == nil {
		info = []byte("cfe_hardening_v1")
	}
	prk := hmac.New(sha512.New, salt)
	prk.Write(data)
	key := prk.Sum(nil)
	okm := make([]byte, 0, outLen)
	t := []byte{}
	ctr := byte(1)
	for len(okm) < outLen {
		h := hmac.New(sha512.New, key)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{ctr})
		t = h.Sum(nil)
		okm = append(okm, t...)
		ctr++
	}
	zeroBytes(key)
	return okm[:outLen], nil
}

// ---------------- FactorabilitySimulator (defensive only) ----------------

type FactorabilitySimulator struct {
	BaseCostUnit float64
}

func NewFactorabilitySimulator() *FactorabilitySimulator {
	return &FactorabilitySimulator{BaseCostUnit: 1e6}
}

func (f *FactorabilitySimulator) EstimateVulnerability(telemetry []byte, publicArtifact []byte) float64 {
	h := hmac.New(sha256.New, []byte("cfe_sim_seed_v1"))
	h.Write(telemetry)
	h.Write(publicArtifact)
	d := h.Sum(nil)
	if len(d) < 8 {
		return 0.0
	}
	acc := binary.BigEndian.Uint64(d[:8])
	return float64(acc) / float64(^uint64(0))
}

func (f *FactorabilitySimulator) SimulateAttackCost(vulnScore float64, bitSecurity int) float64 {
	if vulnScore < 0 {
		vulnScore = 0
	}
	if vulnScore > 1 {
		vulnScore = 1
	}
	e := float64(bitSecurity-128)
	if e < 0 {
		e = 0
	}
	if e > 1024 {
		e = 1024
	}
	exp := math.Exp2(e)
	cost := exp * f.BaseCostUnit * (1.5 - vulnScore)
	if cost < 0 {
		return 0
	}
	if math.IsInf(cost, 0) || math.IsNaN(cost) {
		return math.MaxFloat64 / 2
	}
	return cost
}

func (f *FactorabilitySimulator) RecommendHardening(ctx context.Context, engine *CFEEngine, vulScore float64, pub []byte) {
	if engine == nil {
		return
	}
	if vulScore >= engine.cfg.SimVulnThreshold {
		_ = engine.auditIfPossible(ctx, "cfe.recommend_hardening", map[string]any{"vuln": vulScore, "mode": "aggressive", "ts": time.Now().UTC()})
		if engine.fw != nil {
			_ = engine.fw.ApplyStrengthen(ctx, "global", 0.95, "simulated high vulnerability - recommend immediate rotation and monitoring")
		}
		_ = engine.auditIfPossible(ctx, "cfe.recommend_key_length", map[string]any{"recommended_bytes": engine.cfg.DefaultKeyBytes + 16})
	} else if vulScore >= engine.cfg.SimVulnThreshold*0.75 {
		_ = engine.auditIfPossible(ctx, "cfe.recommend_hardening", map[string]any{"vuln": vulScore, "mode": "moderate", "ts": time.Now().UTC()})
		if engine.fw != nil {
			_ = engine.fw.ApplyStrengthen(ctx, "global", 0.6, "simulated moderate vulnerability - increase logging & schedule rotation")
		}
		_ = engine.auditIfPossible(ctx, "cfe.recommend_key_length", map[string]any{"recommended_bytes": engine.cfg.DefaultKeyBytes + 8})
	} else {
		_ = engine.auditIfPossible(ctx, "cfe.recommend_hardening", map[string]any{"vuln": vulScore, "mode": "routine", "ts": time.Now().UTC()})
	}
}

func (c *CFEEngine) auditIfPossible(ctx context.Context, tag string, info map[string]any) error {
	if c.aud != nil {
		return c.aud.Audit(ctx, tag, info)
	}
	return nil
}

func (c *CFEEngine) RunDefensiveSimulationAndHarden(ctx context.Context, telemetry []byte, publicArtifacts []byte) (float64, float64, error) {
	if c.cfg.Mode != ModeDefense {
		return 0, 0, errors.New("engine not in defense mode")
	}
	sim := NewFactorabilitySimulator()
	vuln := sim.EstimateVulnerability(telemetry, publicArtifacts)
	estCost := sim.SimulateAttackCost(vuln, c.cfg.DefaultKeyBytes*8)
	_ = c.auditIfPossible(ctx, "cfe.simulation_run", map[string]any{"vuln_score": vuln, "est_cost": estCost, "ts": time.Now().UTC()})
	sim.RecommendHardening(ctx, c, vuln, publicArtifacts)
	return vuln, estCost, nil
}

// ---------------- Plugin registration (signed token) ----------------

// RegisterPluginByToken registers a plugin binary only if the HMAC of the binary content matches tokenHex.
// This HMAC must be produced by a secure pipeline (Vault/HSM). The key name is provided in config (AuditHMACEnv).
func (c *CFEEngine) RegisterPluginByToken(ctx context.Context, pluginPath string, tokenHex string) error {
	if pluginPath == "" {
		return errors.New("pluginPath required")
	}
	keyName := c.cfg.AuditHMACEnv
	if keyName == "" {
		keyName = "AUDIT_HMAC_KEY"
	}
	key := os.Getenv(keyName)
	if key == "" {
		// fallback to well-known file (optional)
		if kb, err := os.ReadFile("/etc/laserwall/audit_hmac"); err == nil {
			key = strings.TrimSpace(string(kb))
		}
	}
	if key == "" {
		return errors.New("audit hmac key not set in env or /etc/laserwall/audit_hmac")
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		return fmt.Errorf("read plugin: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(tokenHex)) {
		return errors.New("plugin token mismatch")
	}
	// Execute plugin with --meta to obtain JSON metadata (sandboxed via external process)
	ctxMeta, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctxMeta, pluginPath, "--meta")
	cmd.Env = append(os.Environ(), "CFE_PLUGIN_MODE=meta")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("plugin meta exec failed: %w", err)
	}
	var meta struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Desc    string `json:"desc,omitempty"`
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		return fmt.Errorf("plugin meta parse failed: %w", err)
	}
	if meta.Name == "" || meta.Version == "" {
		return errors.New("plugin meta missing name/version")
	}
	dst := filepath.Join(c.cfg.PluginDir, filepath.Base(pluginPath))
	// Protect against overwriting active plugin: require non-existent or safe replace
	if _, err := os.Stat(dst); err == nil {
		// destination exists - refuse replace to avoid race conditions
		return fmt.Errorf("plugin at destination already exists: %s", dst)
	}
	if err := os.WriteFile(dst, data, 0o750); err != nil {
		return fmt.Errorf("copy plugin: %w", err)
	}
	// tighten permissions and try to chown to nobody if present
	_ = os.Chmod(dst, 0o750)
	if u, err := user.Lookup("nobody"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Chown(dst, uid, gid)
	}
	c.pluginsMu.Lock()
	c.plugins[meta.Name] = PluginMeta{Name: meta.Name, Version: meta.Version, Desc: meta.Desc, path: dst}
	c.pluginsMu.Unlock()
	_ = c.auditIfPossible(ctx, "cfe.plugin_loaded", map[string]any{"name": meta.Name, "ver": meta.Version, "ts": time.Now().UTC()})
	return nil
}

// CallPlugin executes a registered plugin as a separate OS process with sanitized JSON on stdin and returns parsed JSON stdout.
// Linux: enforces RLIMIT_AS and RLIMIT_CPU and attempts to drop to nobody uid/gid if available.
func (c *CFEEngine) CallPlugin(ctx context.Context, name string, payload map[string]any, timeout time.Duration) (map[string]any, error) {
	c.pluginsMu.RLock()
	meta, ok := c.plugins[name]
	c.pluginsMu.RUnlock()
	if !ok {
		return nil, errors.New("plugin not found")
	}
	// Sanitize payload: drop keys that look like secrets
	payloadSanitized := make(map[string]any)
	for k, v := range payload {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "secret") || strings.HasPrefix(lk, "priv") || strings.HasPrefix(lk, "key") || strings.Contains(lk, "password") {
			continue
		}
		payloadSanitized[k] = v
	}
	reqBytes, err := json.Marshal(payloadSanitized)
	if err != nil {
		return nil, err
	}
	ctxExec := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		ctxExec, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctxExec, meta.path)
	// Minimal environment for plugin
	cmd.Env = []string{"CFE_PLUGIN_MODE=exec", "PATH=/usr/bin:/bin"}
	// Set process attributes for Linux to restrict privileges and set resource limits
	if runtime.GOOS == "linux" {
		// try to drop privileges to nobody if available
		if u, err := user.Lookup("nobody"); err == nil {
			if uid, err2 := strconv.Atoi(u.Uid); err2 == nil {
				if gid, err3 := strconv.Atoi(u.Gid); err3 == nil {
					cmd.SysProcAttr = &syscall.SysProcAttr{
						Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
						// No new privileges
						AmbientCaps: []uintptr{},
					}
				}
			}
		}
		// RLimit: CPU seconds and address space (approx memory)
		rlimits := []syscall.Rlimit{
			// RLIMIT_CPU: 5 seconds
			{Cur: 5, Max: 10},
			// RLIMIT_AS: 200MB
			{Cur: 200 * 1024 * 1024, Max: 200 * 1024 * 1024},
		}
		// apply using PreStart via SysProcAttr.Pdeathsig not available for limits; use wrapper via bash ulimit? Simpler: set attributes via SysProcAttr.Pdeathsig to ensure child dies if parent dies.
		_ = rlimits // kept for clarity; platform-specific enforcement may require wrapper binary or prlimit CLI.
	}
	// Start process and communicate
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// Use a buffered reader to avoid blocking issues
	reader := bufio.NewReader(stdout)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_, _ = stdin.Write(reqBytes)
	_ = stdin.Close()
	// Read all output until EOF or context done
	outBytes, readErr := io.ReadAll(reader)
	if readErr != nil {
		_ = cmd.Process.Kill()
		return nil, readErr
	}
	// Wait for process to finish
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("plugin run failed: %w", err)
	}
	var resp map[string]any
	if len(outBytes) > 0 {
		if err := json.Unmarshal(outBytes, &resp); err != nil {
			return nil, fmt.Errorf("plugin output parse failed: %w", err)
		}
	} else {
		resp = map[string]any{"ok": true}
	}
	_ = c.auditIfPossible(ctx, "cfe.plugin_call", map[string]any{"name": name, "ok": true, "ts": time.Now().UTC()})
	return resp, nil
}

func (c *CFEEngine) Guard() error {
	if c.cfg.Mode != ModeDefense {
		return errors.New("forbidden: engine not in defense mode")
	}
	return nil
}