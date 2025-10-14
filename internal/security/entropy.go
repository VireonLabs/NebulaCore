
//
// Military-grade hybrid entropy manager.
// Integrates OS CSPRNG, local aggregator, optional AI provider, optional attestation.
// Provides forward-secure chaining, HKDF extraction, reseed policies, encrypted seed storage helper.
//
// IMPORTANT: This greatly increases complexity and hardening inside Go constraints.
// For highest assurance use HSM/TPM for key material and operations.

package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

const (
	_seedDerivationLabel = "EntropySeedDerivation-v2"
	_callContextLabel    = "EntropyCallContext-v1"
	_storeSalt           = "entropy_store_salt_v1"
)

// -----------------------------
// Extended config
// -----------------------------
type EntropyConfig struct {
	ReseedIntervalBytes uint64        // reseed after generating these many bytes (default 1MB)
	ReseedIntervalTime  time.Duration // reseed at least every duration (default 1m)
	MinSeedMaterial     int           // min bytes for seed material (default 64)
	ResponsibleMode     bool          // if true, stricter limits apply
	Logger              *log.Logger

	// AI integration hyperparams
	AIConfidenceIgnore   float64 // < this -> ignore AI output (default 0.20)
	AIConfidencePartial  float64 // between ignore and this -> partial use (default 0.60)
	AIConfidenceCapBytes int     // max bytes from AI to accept (default 128)

	// Forward-secrecy / chain params
	ChainMixLabel []byte // label for HKDF mixing
}

func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		ReseedIntervalBytes: 1 * 1024 * 1024, // 1 MB
		ReseedIntervalTime:  1 * time.Minute,
		MinSeedMaterial:     64,
		ResponsibleMode:     true,
		Logger:              log.New(os.Stderr, "[entropy] ", log.LstdFlags|log.Lmsgprefix),
		AIConfidenceIgnore:  0.20,
		AIConfidencePartial: 0.60,
		AIConfidenceCapBytes: 128,
		ChainMixLabel:       []byte("EntropyChain-v1"),
	}
}

// -----------------------------
// HMAC-DRBG (SHA-512) - kept as building block
// -----------------------------
type hmacDRBG struct {
	K []byte
	V []byte
	// reseedCounter increments each reseed
	reseedCounter uint64
}

func newHMACDRBG(seed []byte) *hmacDRBG {
	K := make([]byte, sha512.Size)
	V := make([]byte, sha512.Size)
	for i := range K {
		K[i] = 0x00
		V[i] = 0x01
	}
	drbg := &hmacDRBG{K: K, V: V, reseedCounter: 1}
	drbg.update(seed)
	return drbg
}

func (d *hmacDRBG) reseed(seed []byte) {
	d.update(seed)
	d.reseedCounter = 1
}

func (d *hmacDRBG) update(seed []byte) {
	h := hmac.New(sha512.New, d.K)
	h.Write(d.V)
	h.Write([]byte{0x00})
	if len(seed) > 0 {
		h.Write(seed)
	}
	d.K = h.Sum(nil)
	h2 := hmac.New(sha512.New, d.K)
	h2.Write(d.V)
	d.V = h2.Sum(nil)
	if len(seed) == 0 {
		return
	}
	h3 := hmac.New(sha512.New, d.K)
	h3.Write(d.V)
	h3.Write([]byte{0x01})
	h3.Write(seed)
	d.K = h3.Sum(nil)
	h4 := hmac.New(sha512.New, d.K)
	h4.Write(d.V)
	d.V = h4.Sum(nil)
}

func (d *hmacDRBG) generate(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid generate size")
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		h := hmac.New(sha512.New, d.K)
		h.Write(d.V)
		d.V = h.Sum(nil)
		out = append(out, d.V...)
	}
	d.update(nil)
	d.reseedCounter++
	return out[:n], nil
}

// -----------------------------
// Utility helpers
// -----------------------------
func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// safeReadOS populates dest with OS CSPRNG, returns error if fails.
func safeReadOS(dest []byte) error {
	_, err := io.ReadFull(crand.Reader, dest)
	return err
}

// hkdfExtractExpand convenience: returns outLen bytes derived from keyMaterial and info
func hkdfExtractExpand(secret []byte, info []byte, outLen int) ([]byte, error) {
	h := hkdf.New(sha512.New, secret, nil, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// scrypt+AES-GCM helper (for seed storage)
func storeSecretEncrypted(path string, secret []byte, passphrase []byte) error {
	k, err := scrypt.Key(passphrase, []byte(_storeSalt), 1<<15, 8, 1, 32)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, secret, nil)
	dir := filepath.Dir(path)
	if dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	return os.WriteFile(path, append(nonce, ct...), 0o600)
}

func loadSecretEncrypted(path string, passphrase []byte) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := scrypt.Key(passphrase, []byte(_storeSalt), 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(b) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := b[:gcm.NonceSize()]
	ct := b[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// -----------------------------
// EntropyManager (advanced)
// -----------------------------
type EntropyManager struct {
	cfg EntropyConfig

	mu sync.Mutex
	// aggregator provided externally
	aggregator *EntropyAggregator

	aiProvider AIEntropyProvider
	attestProv AttestationProvider

	// internal master seed (high-entropy secret) — forward-secure updated
	seedMaster []byte

	// internal DRBG used as derivation engine
	drbg *hmacDRBG

	// counters & telemetry
	bytesGened   uint64
	lastReseedAt time.Time
	callCounter  uint64 // monotonic per-call counter (atomic)

	logger *log.Logger
}

// NewEntropyManager creates and seeds it using OS + aggregator + optional AI provider.
// This implementation is aggressive about mixing many sources and keeping forward secrecy.
func NewEntropyManager(cfg EntropyConfig, aggregator *EntropyAggregator) (*EntropyManager, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "[entropy] ", log.LstdFlags|log.Lmsgprefix)
	}
	if aggregator == nil {
		aggregator = NewEntropyAggregator()
	}
	// set defaults for AI thresholds if 0
	if cfg.AIConfidenceIgnore == 0 {
		cfg.AIConfidenceIgnore = 0.20
	}
	if cfg.AIConfidencePartial == 0 {
		cfg.AIConfidencePartial = 0.60
	}
	if cfg.AIConfidenceCapBytes == 0 {
		cfg.AIConfidenceCapBytes = 128
	}
	if cfg.ChainMixLabel == nil {
		cfg.ChainMixLabel = []byte("EntropyChain-v1")
	}

	em := &EntropyManager{cfg: cfg, aggregator: aggregator, logger: cfg.Logger}
	// seed master
	if err := em.initialSeed(); err != nil {
		return nil, err
	}
	return em, nil
}

// initialSeed builds a seedMaster from a wide mix of sources (OS + aggregator + optional AI + attestation)
func (e *EntropyManager) initialSeed() error {
	seed, err := e.collectSeedMaterial()
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// seed master is larger than MinSeedMaterial for more entropy
	sm := make([]byte, 64)
	copy(sm, seed)
	zeroBytes(seed)
	// initialize chain: derive drbg key material from seedMaster
	drbgKey, err := hkdfExtractExpand(sm, append([]byte(_seedDerivationLabel), e.cfg.ChainMixLabel...), sha512.Size)
	if err != nil {
		zeroBytes(sm)
		return err
	}
	e.seedMaster = make([]byte, len(sm))
	copy(e.seedMaster, sm)
	zeroBytes(sm)
	e.drbg = newHMACDRBG(drbgKey)
	zeroBytes(drbgKey)
	e.lastReseedAt = time.Now()
	e.bytesGened = 0
	atomic.StoreUint64(&e.callCounter, 0)
	e.logger.Printf("initialSeed: done (minseed=%d)", e.cfg.MinSeedMaterial)
	return nil
}

// collectSeedMaterial: heavy-weight seeding function
// - collects OS CSPRNG, aggregator snapshot, AI provider (policy-based), attestation seal, and environment noise.
// - returns at least MinSeedMaterial bytes.
func (e *EntropyManager) collectSeedMaterial() ([]byte, error) {
	min := e.cfg.MinSeedMaterial
	if min < 32 {
		min = 32
	}
	// staged buffers
	buf := &bytes.Buffer{}

	// 1) OS CSPRNG chunk
	osb := make([]byte, min)
	if err := safeReadOS(osb); err == nil {
		buf.Write(osb)
	} else {
		// fallback: timestamp/pid/mem
		tmp := make([]byte, min)
		binary.LittleEndian.PutUint64(tmp[0:8], uint64(time.Now().UnixNano()))
		binary.LittleEndian.PutUint64(tmp[8:16], uint64(os.Getpid()))
		buf.Write(tmp)
	}
	zeroBytes(osb)

	// 2) aggregator snapshot
	e.aggregator.Collect()
	e.aggregator.mu.Lock()
	ag := make([]byte, len(e.aggregator.entropy))
	copy(ag, e.aggregator.entropy)
	e.aggregator.mu.Unlock()
	buf.Write(ag)
	zeroBytes(ag)

	// 3) AI provider with policy: map confidence -> how many bytes to accept
	if e.aiProvider != nil {
		if data, conf, err := e.aiProvider.GetEntropy(time.Now()); err == nil && len(data) > 0 {
			// decide use fraction
			if conf < e.cfg.AIConfidenceIgnore {
				// ignore AI
				e.logger.Printf("collectSeedMaterial: AI ignored (conf=%.3f)", conf)
			} else {
				maxUse := len(data)
				// cap
				if maxUse > e.cfg.AIConfidenceCapBytes {
					maxUse = e.cfg.AIConfidenceCapBytes
				}
				var use int
				if conf < e.cfg.AIConfidencePartial {
					// partial proportion between ignore..partial mapped to 0.25..0.5
					scale := (conf - e.cfg.AIConfidenceIgnore) / (e.cfg.AIConfidencePartial - e.cfg.AIConfidenceIgnore)
					if scale < 0 {
						scale = 0
					}
					use = int(float64(maxUse) * (0.25 + 0.25*scale))
				} else {
					// strong confidence: up to 50-100% scaled by confidence
					scale := math.Min(1.0, (conf-e.cfg.AIConfidencePartial)/(1.0-e.cfg.AIConfidencePartial))
					use = int(float64(maxUse) * (0.5 + 0.5*scale))
				}
				if use <= 0 {
					use = 1
				}
				if use > maxUse {
					use = maxUse
				}
				buf.Write(data[:use])
				zeroBytes(data[:use])
				e.logger.Printf("collectSeedMaterial: AI mixed bytes=%d conf=%.3f", use, conf)
			}
		} else if err != nil {
			e.logger.Printf("collectSeedMaterial: AI provider error: %v", err)
		}
	}

	// 4) attestation seal (optional)
	if e.attestProv != nil {
		if seal, err := e.attestProv.ProvideSeal(); err == nil && len(seal) > 0 {
			// include but bounded
			if len(seal) > 128 {
				buf.Write(seal[:128])
			} else {
				buf.Write(seal)
			}
			zeroBytes(seal)
		}
	}

	// 5) environment noise: memstats, monotonic time, goroutine count
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var env [56]byte
	binary.LittleEndian.PutUint64(env[0:8], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(env[8:16], uint64(ms.Alloc))
	binary.LittleEndian.PutUint64(env[16:24], uint64(ms.Sys))
	binary.LittleEndian.PutUint64(env[24:32], uint64(ms.TotalAlloc))
	binary.LittleEndian.PutUint64(env[32:40], uint64(ms.NumGC))
	binary.LittleEndian.PutUint64(env[40:48], uint64(runtime.NumGoroutine()))
	binary.LittleEndian.PutUint64(env[48:56], uint64(os.Getpid()))
	buf.Write(env[:])

	// 6) OS extra randomness
	extra := make([]byte, 64)
	if err := safeReadOS(extra); err == nil {
		buf.Write(extra)
	}
	zeroBytes(extra)

	// 7) compress / derive: HMAC-SHA512 over the collected buffer + label
	h := hmac.New(sha512.New, []byte(_seedDerivationLabel))
	h.Write(buf.Bytes())
	seed := h.Sum(nil)

	// ensure min length
	if len(seed) < min {
		ext := make([]byte, min-len(seed))
		if err := safeReadOS(ext); err == nil {
			seed = append(seed, ext...)
		} else {
			// deterministic extension
			tmp := make([]byte, min-len(seed))
			binary.LittleEndian.PutUint64(tmp[:8], uint64(time.Now().UnixNano()))
			seed = append(seed, tmp...)
		}
	}

	// clean temp buffers
	zeroBytes(buf.Bytes()[:0])
	return seed[:min], nil
}

// -----------------------------
// Public API
// -----------------------------

// RegisterAIProvider registers an AIEntropyProvider (can be nil).
func (e *EntropyManager) RegisterAIProvider(p AIEntropyProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p != nil {
		e.logger.Printf("RegisterAIProvider: %s", p.Name())
	} else {
		e.logger.Print("RegisterAIProvider: clearing provider")
	}
	e.aiProvider = p
}

// RegisterAttestationProvider registers an AttestationProvider (optional).
func (e *EntropyManager) RegisterAttestationProvider(a AttestationProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a != nil {
		e.logger.Printf("RegisterAttestationProvider: %s", a.Name())
	}
	e.attestProv = a
}

// MixExternalEntropy manually mixes external bytes into seedMaster and reseeds DRBG.
func (e *EntropyManager) MixExternalEntropy(external []byte) error {
	if len(external) == 0 {
		return errors.New("external empty")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	// limit external size in ResponsibleMode
	if e.cfg.ResponsibleMode && len(external) > 64*1024 {
		e.logger.Printf("MixExternalEntropy: truncating large external input (len=%d)", len(external))
		external = external[:64*1024]
	}

	h := hmac.New(sha512.New, e.seedMaster)
	h.Write([]byte("ExternalMix-v2"))
	h.Write(external)
	newSeed := h.Sum(nil)

	// update seedMaster = HKDF(newSeed || oldSeed) to ensure one-way chaining
	combined := append(newSeed, e.seedMaster...)
	next, err := hkdfExtractExpand(combined, e.cfg.ChainMixLabel, len(e.seedMaster))
	if err != nil {
		zeroBytes(newSeed)
		return err
	}
	zeroBytes(e.seedMaster)
	e.seedMaster = next
	e.drbg.reseed(newSeed)
	e.lastReseedAt = time.Now()
	e.bytesGened = 0
	zeroBytes(newSeed)
	zeroBytes(combined)
	e.logger.Printf("MixExternalEntropy: reseeded with external input")
	return nil
}

// GetRandomBytes returns n cryptographically secure bytes with heavy mixing and forward-chaining.
// It derives per-call material from seedMaster, a per-call OS nonce, call counter, and environment.
// After generating, it advances seedMaster with one-way mixing (forward-secrecy).
func (e *EntropyManager) GetRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("n must be >0")
	}
	// quick path: lock for reseed and generation
	e.mu.Lock()
	defer e.mu.Unlock()

	// reseed if needed
	if e.shouldReseed() {
		if err := e.reseedLocked(); err != nil {
			e.logger.Printf("GetRandomBytes: reseed error: %v", err)
			// continue with current state
		}
	}

	// per-call context
	callIdx := atomic.AddUint64(&e.callCounter, 1)
	// gather per-call OS nonce
	nonce := make([]byte, 32)
	_ = safeReadOS(nonce) // ignore error; we still proceed

	// environment snapshot
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var env [40]byte
	binary.LittleEndian.PutUint64(env[0:8], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(env[8:16], uint64(ms.Alloc))
	binary.LittleEndian.PutUint64(env[16:24], uint64(ms.Sys))
	binary.LittleEndian.PutUint64(env[24:32], uint64(ms.TotalAlloc))
	binary.LittleEndian.PutUint64(env[32:40], callIdx)

	// derive per-call seed material: HKDF(seedMaster, info = call context || nonce)
	info := append([]byte(_callContextLabel), env[:]...)
	info = append(info, nonce...)
	perCallKey, err := hkdfExtractExpand(e.seedMaster, info, 64)
	if err != nil {
		zeroBytes(nonce)
		return nil, err
	}

	// derive requested output using HKDF-expand from perCallKey
	out, err := hkdfExtractExpand(perCallKey, append([]byte("output_expand_v1"), info...), n)
	if err != nil {
		zeroBytes(nonce); zeroBytes(perCallKey)
		return nil, err
	}

	// For defense-in-depth, XOR with DRBG output and small OS chunk
	drbgOut, _ := e.drbg.generate(n)
	osb := make([]byte, n)
	_ = safeReadOS(osb)
	for i := 0; i < n; i++ {
		out[i] ^= drbgOut[i] ^ osb[i]
	}
	zeroBytes(drbgOut)
	zeroBytes(osb)

	// forward-update seedMaster one-way: seedMaster = HMAC(seedMaster, perCallKey || nonce || env)
	h := hmac.New(sha512.New, e.seedMaster)
	h.Write(perCallKey)
	h.Write(nonce)
	h.Write(env[:])
	nextSeed := h.Sum(nil)
	// collapse/derive fixed-size master (keep same length)
	newMaster, err := hkdfExtractExpand(nextSeed, e.cfg.ChainMixLabel, len(e.seedMaster))
	if err == nil {
		zeroBytes(e.seedMaster)
		e.seedMaster = newMaster
	} else {
		// if HKDF fails (unlikely), at least overwrite via nextSeed truncated/expanded
		if len(nextSeed) >= len(e.seedMaster) {
			copy(e.seedMaster, nextSeed[:len(e.seedMaster)])
		} else {
			// expand via DRBG
			tmp, _ := e.drbg.generate(len(e.seedMaster))
			copy(e.seedMaster, tmp)
			zeroBytes(tmp)
		}
	}
	zeroBytes(nextSeed)
	zeroBytes(perCallKey)
	zeroBytes(nonce)

	// update counters
	e.bytesGened += uint64(n)
	return out, nil
}

// GetRandomInt returns pseudorandom int64 in [0, max)
func (e *EntropyManager) GetRandomInt(max int64) (int64, error) {
	if max <= 0 {
		return 0, errors.New("max must be >0")
	}
	// pick byte length
	bytesNeeded := int((bitsNeeded(uint64(max)) + 7) / 8)
	b, err := e.GetRandomBytes(bytesNeeded)
	if err != nil {
		return 0, err
	}
	n := new(big.Int).SetBytes(b)
	mod := new(big.Int).SetInt64(max)
	n.Mod(n, mod)
	return n.Int64(), nil
}

// bitsNeeded returns bits needed to represent v-1.
func bitsNeeded(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	var bits uint64
	for v > 0 {
		bits++
		v >>= 1
	}
	return bits
}

// -----------------------------
// Reseed / housekeeping
// -----------------------------
func (e *EntropyManager) shouldReseed() bool {
	if e.drbg == nil || e.seedMaster == nil {
		return true
	}
	if e.bytesGened >= e.cfg.ReseedIntervalBytes {
		return true
	}
	if time.Since(e.lastReseedAt) >= e.cfg.ReseedIntervalTime {
		return true
	}
	return false
}

func (e *EntropyManager) reseedLocked() error {
	// assume e.mu held by caller
	seed, err := e.collectSeedMaterial()
	if err != nil {
		return err
	}
	// new master: HKDF(seed || oldMaster)
	combined := append(seed, e.seedMaster...)
	next, err := hkdfExtractExpand(combined, e.cfg.ChainMixLabel, len(e.seedMaster))
	if err != nil {
		// fallback: seed becomes new master (best effort)
		if len(seed) >= len(e.seedMaster) {
			copy(e.seedMaster, seed[:len(e.seedMaster)])
		} else {
			// expand
			tmp, _ := hkdfExtractExpand(seed, []byte("fallback_expand"), len(e.seedMaster))
			copy(e.seedMaster, tmp)
			zeroBytes(tmp)
		}
	} else {
		zeroBytes(e.seedMaster)
		e.seedMaster = next
	}
	// reseed DRBG
	e.drbg.reseed(seed)
	e.lastReseedAt = time.Now()
	e.bytesGened = 0
	zeroBytes(seed)
	zeroBytes(combined)
	e.logger.Printf("reseedLocked: reseeded at %s", e.lastReseedAt.Format(time.RFC3339))
	return nil
}

// -----------------------------
// Operational helpers
// -----------------------------

// StoreSeedEncrypted stores current seedMaster encrypted by passphrase to file.
// Use HSM/PKCS11 in production rather than passphrase files.
func (e *EntropyManager) StoreSeedEncrypted(path string, passphrase []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seedMaster == nil {
		return errors.New("no seed present")
	}
	return storeSecretEncrypted(path, e.seedMaster, passphrase)
}

// LoadSeedEncrypted loads seedMaster from encrypted file and overwrites current seedMaster.
func (e *EntropyManager) LoadSeedEncrypted(path string, passphrase []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	pt, err := loadSecretEncrypted(path, passphrase)
	if err != nil {
		return err
	}
	// overwrite
	zeroBytes(e.seedMaster)
	e.seedMaster = make([]byte, len(pt))
	copy(e.seedMaster, pt)
	zeroBytes(pt)
	// reseed DRBG accordingly
	drbgKey, err := hkdfExtractExpand(e.seedMaster, append([]byte(_seedDerivationLabel), e.cfg.ChainMixLabel...), sha512.Size)
	if err != nil {
		return err
	}
	e.drbg = newHMACDRBG(drbgKey)
	zeroBytes(drbgKey)
	e.lastReseedAt = time.Now()
	e.bytesGened = 0
	return nil
}

// Wipe zeros internal secrets (useful for process shutdown)
func (e *EntropyManager) Wipe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seedMaster != nil {
		zeroBytes(e.seedMaster)
		e.seedMaster = nil
	}
	if e.drbg != nil {
		zeroBytes(e.drbg.K)
		zeroBytes(e.drbg.V)
		e.drbg = nil
	}
	e.bytesGened = 0
	e.logger.Printf("Wipe: internal secrets cleared")
}

// SelfTest performs a lightweight operational test.
func (e *EntropyManager) SelfTest() error {
	// generate small outputs and ensure variability
	a, err := e.GetRandomBytes(16)
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Millisecond)
	b, err := e.GetRandomBytes(16)
	if err != nil {
		zeroBytes(a)
		return err
	}
	if bytes.Equal(a, b) {
		zeroBytes(a); zeroBytes(b)
		return errors.New("selftest: outputs identical")
	}
	zeroBytes(a); zeroBytes(b)
	return nil
}

// GetStatus returns runtime status (non-secrets)
func (e *EntropyManager) GetStatus() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := map[string]interface{}{
		"drbg_present":      e.drbg != nil,
		"seed_present":      e.seedMaster != nil,
		"bytes_generated":   e.bytesGened,
		"last_reseed_at":    e.lastReseedAt.Format(time.RFC3339),
		"reseed_interval_s": int64(e.cfg.ReseedIntervalTime.Seconds()),
		"ai_provider":       nil,
	}
	if e.aiProvider != nil {
		status["ai_provider"] = e.aiProvider.Name()
	}
	if e.attestProv != nil {
		status["attestation_provider"] = e.attestProv.Name()
	}
	return status
}
  