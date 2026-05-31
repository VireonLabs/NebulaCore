// internal/security/ai_entropy.go
// AI-driven entropy algorithm (algorithm-only provider).
// Implements AIEntropyProvider interface expected by internal/security/entropy.go.
//
// Design goals:
//  - Provide an algorithmic, audit-friendly "AI-like" entropy producer based on a mix of
//    timing jitter, system stats, chaotic PRNG state, lightweight spectral transform,
//    and HMAC-SHA512/HKDF extraction.
//  - Be dependency-free (std lib only + golang.org/x/crypto/hkdf), concurrency-safe,
//    and suitable for mixing into the main EntropyManager.
//  - Expose a confidence score [0,1] to signal how much of the provider output to use.
//
// Security notes:
//  - Auxiliary entropy source (MIX, not REPLACE). Do not rely on it alone for initial
//    seeding of critical keys unless combined with a trusted CSPRNG/HSM source.
//  - Best-effort zeroing is attempted for buffers; Go does not guarantee physical memory
//    zeroing. For highest assurance use HSM/native secure memory.

package security

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math"
	"math/big"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Ensure AIEntropyAlgorithm implements AIEntropyProvider
var _ AIEntropyProvider = (*AIEntropyAlgorithm)(nil)

// Options for algorithm construction
type AIEntropyOptions struct {
	PoolSize             int     // bytes in internal pool (default 64)
	JitterSamples        int     // number of timing jitter samples per GetEntropy (default 8)
	UseOSRandFallback    bool    // if true, mix OS RNG when confidence is low
	ConfidenceBaseline   float64 // baseline confidence used to scale result (0..1) default 0.6
	ExtractorLabel       []byte  // label for HKDF extraction
	MaxOutputBytes       int     // maximum bytes GetEntropy returns (cap) default 128
	EnableSpectralBlend  bool    // enable lightweight spectral blending (default true)
	EnablePrimeHeuristic bool    // enable heuristic prime fragment (default false — optional/costly)
}

// AIEntropyAlgorithm is an algorithmic AI-style entropy provider.
// It maintains an internal pool, a small chaotic PRNG state, and collects multiple kinds
// of observations on each call to GetEntropy. It does NOT perform any persistent storage.
type AIEntropyAlgorithm struct {
	mu     sync.Mutex
	pool   []byte    // internal pool state
	state  [2]uint64 // xoroshiro128+ state
	seeded bool

	opts AIEntropyOptions

	// optional hash constructor used for extraction (for easier testing)
	hmacCtor func(key []byte) hash.Hash
	nowFunc  func() time.Time
}

// NewAIEntropyAlgorithm creates a new provider with safe defaults.
func NewAIEntropyAlgorithm(opts *AIEntropyOptions) (*AIEntropyAlgorithm, error) {
	o := AIEntropyOptions{
		PoolSize:             64,
		JitterSamples:        8,
		UseOSRandFallback:    true,
		ConfidenceBaseline:   0.6,
		ExtractorLabel:       []byte("ai_entropy_v1"),
		MaxOutputBytes:       128,  // reduced default for safety
		EnableSpectralBlend:  true,
		EnablePrimeHeuristic: false, // disabled by default (costly)
	}
	if opts != nil {
		if opts.PoolSize > 0 {
			o.PoolSize = opts.PoolSize
		}
		if opts.JitterSamples > 0 {
			o.JitterSamples = opts.JitterSamples
		}
		if opts.MaxOutputBytes > 0 {
			o.MaxOutputBytes = opts.MaxOutputBytes
		}
		o.UseOSRandFallback = opts.UseOSRandFallback
		if opts.ConfidenceBaseline >= 0 {
			o.ConfidenceBaseline = math.Min(math.Max(opts.ConfidenceBaseline, 0.0), 1.0)
		}
		if len(opts.ExtractorLabel) > 0 {
			o.ExtractorLabel = opts.ExtractorLabel
		}
		o.EnableSpectralBlend = opts.EnableSpectralBlend
		o.EnablePrimeHeuristic = opts.EnablePrimeHeuristic
	}

	a := &AIEntropyAlgorithm{
		pool:     make([]byte, o.PoolSize),
		seeded:   false,
		opts:     o,
		hmacCtor: func(key []byte) hash.Hash { return hmac.New(sha512.New, key) },
		nowFunc:  time.Now,
	}

	// seed internal xoroshiro state from crypto/rand if possible
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err == nil {
		a.state[0] = binary.LittleEndian.Uint64(buf[0:8])
		a.state[1] = binary.LittleEndian.Uint64(buf[8:16])
		a.seeded = true
		ZeroBytes(buf)
	} else {
		// fallback deterministic-but-changing seed (time-derived) — only if CSPRNG missing
		t := uint64(time.Now().UnixNano())
		a.state[0] = t ^ 0x9e3779b97f4a7c15
		a.state[1] = (t << 21) ^ 0x6a09e667f3bcc909
		a.seeded = true
	}

	// initialize pool with a quick OS read if available
	tmp := make([]byte, a.opts.PoolSize)
	if _, err := crand.Read(tmp); err == nil {
		copy(a.pool, tmp)
		ZeroBytes(tmp)
	} else {
		// fallback: mix state values into pool
		for i := 0; i < len(a.pool); i += 8 {
			v := a.xoroshiroNext()
			var t [8]byte
			binary.LittleEndian.PutUint64(t[:], v)
			copy(a.pool[i:], t[:])
		}
	}

	return a, nil
}

// Name returns provider identifier.
func (a *AIEntropyAlgorithm) Name() string { return "AIEntropyAlgorithm:v1" }

// rotl helper
func rotl(x uint64, k int) uint64 { return (x << uint(k)) | (x >> (64 - uint(k))) }

// xoroshiro128+ next (pure Go, small state)
// Note: xoroshiro is used here as a fast chaotic internal state only; outputs are mixed
// with OS CSPRNG and system observations before being emitted.
func (a *AIEntropyAlgorithm) xoroshiroNext() uint64 {
	// state is seeded in constructor; keep simple update
	s0 := a.state[0]
	s1 := a.state[1]
	result := s0 + s1

	s1 ^= s0
	a.state[0] = rotl(s0, 55) ^ s1 ^ (s1 << 14)
	a.state[1] = rotl(s1, 36)

	return result
}

// simple spectral blend: compute tiny rolling "spectrum" measure to improve diversity.
// It's not a full FFT; it computes differences and mixes them to capture high-frequency jitter.
func spectralBlend(samples []uint64) []byte {
	if len(samples) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(samples)*8)
	for i := 1; i < len(samples); i++ {
		diff := samples[i] - samples[i-1]
		var v [8]byte
		binary.LittleEndian.PutUint64(v[:], diff)
		buf = append(buf, v[:]...)
	}
	h := sha512.New()
	h.Write(buf)
	out := h.Sum(nil)
	return out
}

// GetEntropy collects algorithmic observations and returns bytes + confidence score.
// Intended to be non-blocking and reasonably fast. Caller (EntropyManager) must apply
// the confidence-based policy when deciding how many bytes to mix.
func (a *AIEntropyAlgorithm) GetEntropy(ctx context.Context, size int) (data []byte, confidence float64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1) Collect jitter samples
	jitterSamples := a.opts.JitterSamples
	if jitterSamples < 4 {
		jitterSamples = 4
	}
	samples := make([]uint64, 0, jitterSamples)
	for i := 0; i < jitterSamples; i++ {
		t0 := a.nowFunc().UnixNano()
		_ = a.xoroshiroNext() // create tiny unpredictability/jitter
		t1 := a.nowFunc().UnixNano()
		samples = append(samples, uint64(t1-t0))
	}

	// 2) collect runtime memstats (non-blocking)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// 3) mix internal PRNG outputs
	prngOut := make([]byte, 32)
	for i := 0; i < 4; i++ {
		v := a.xoroshiroNext()
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], v)
		copy(prngOut[i*8:(i+1)*8], tmp[:])
	}

	// 4) spectral blend of timing samples
	var spec []byte
	if a.opts.EnableSpectralBlend {
		spec = spectralBlend(samples)
	}

	// 5) combine observations into "raw material" via HMAC-SHA512
	h := hmac.New(sha512.New, a.opts.ExtractorLabel)
	var tbuf [8]byte
	binary.LittleEndian.PutUint64(tbuf[:], uint64(time.Now().UnixNano()))
	h.Write(tbuf[:])

	var mbuf [40]byte
	binary.LittleEndian.PutUint64(mbuf[0:8], ms.Alloc)
	binary.LittleEndian.PutUint64(mbuf[8:16], ms.TotalAlloc)
	binary.LittleEndian.PutUint64(mbuf[16:24], ms.Sys)
	binary.LittleEndian.PutUint64(mbuf[24:32], uint64(ms.NumGC))
	binary.LittleEndian.PutUint64(mbuf[32:40], uint64(ms.PauseTotalNs))
	h.Write(mbuf[:])

	h.Write(prngOut)
	if spec != nil {
		h.Write(spec)
	}

	// Optional: lightweight prime fragment (disabled by default)
	if a.opts.EnablePrimeHeuristic {
		if pBytes, pErr := heuristicPrimeFragment(); pErr == nil && len(pBytes) > 0 {
			h.Write(pBytes)
			ZeroBytes(pBytes)
		}
	}

	raw := h.Sum(nil)

	// 6) Mix into internal pool (XOR-then-HMAC to update pool)
	for i := 0; i < len(a.pool); i++ {
		a.pool[i] ^= raw[i%len(raw)]
	}
	k := hmac.New(sha512.New, a.pool)
	k.Write([]byte("pool_update"))
	poolDigest := k.Sum(nil)
	copy(a.pool, poolDigest[:len(a.pool)])

	// 7) derive output via HKDF-SHA512 (final extraction)
	maxOut := a.opts.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = 128
	}
	outLen := len(a.pool)
	if outLen > maxOut {
		outLen = maxOut
	}
	hk := hkdf.New(sha512.New, a.pool, nil, append([]byte("ai_entropy_extract_v1"), tbuf[:]...))
	out := make([]byte, outLen)
	if _, err := hk.Read(out); err != nil {
		// fallback: try crypto/rand if available and allowed
		if a.opts.UseOSRandFallback {
			if _, rerr := crand.Read(out); rerr == nil {
				// low confidence fallback
				conf := 0.15
				ZeroBytes(prngOut)
				ZeroBytes(raw)
				ZeroBytes(poolDigest)
				ZeroBytes(mbuf[:])
				return out, conf, nil
			}
		}
		ZeroBytes(prngOut)
		ZeroBytes(raw)
		ZeroBytes(poolDigest)
		ZeroBytes(mbuf[:])
		return nil, 0, err
	}

	// 8) compute a simple variance-based confidence metric
	conf := a.estimateConfidence(samples, ms, prngOut, spec)

	// best-effort zeroing of temporaries
	ZeroBytes(prngOut)
	ZeroBytes(raw)
	ZeroBytes(poolDigest)
	ZeroBytes(mbuf[:])
	for i := range samples {
		samples[i] = 0
	}

	return out, conf, nil
}

// estimateConfidence produces a [0,1] confidence value based on diversity of sources.
func (a *AIEntropyAlgorithm) estimateConfidence(samples []uint64, ms runtime.MemStats, prngOut []byte, spec []byte) float64 {
	// timing variance
	if len(samples) < 2 {
		return a.opts.ConfidenceBaseline
	}
	var sum uint64
	for _, v := range samples {
		sum += v
	}
	mean := float64(sum) / float64(len(samples))
	var s float64
	for _, v := range samples {
		d := float64(v) - mean
		s += d * d
	}
	variance := s / float64(len(samples))
	vscore := math.Tanh(math.Log1p(variance+1.0))

	// memory churn score
	memScore := math.Tanh(float64(ms.Alloc)/float64(1<<20) + float64(ms.NumGC)*0.1)

	// prng entropy heuristic: count non-zero bytes
	nz := 0
	for _, b := range prngOut {
		if b != 0 {
			nz++
		}
	}
	prngScore := float64(nz) / float64(len(prngOut))

	// spectral presence
	specScore := 0.0
	if len(spec) > 0 {
		sumv := 0
		for _, v := range spec {
			sumv += int(v)
		}
		specScore = math.Tanh(float64(sumv) / float64(len(spec)*128))
	}

	// combine weighted
	score := 0.45*vscore + 0.20*memScore + 0.25*prngScore + 0.10*specScore

	// bias towards baseline and clamp
	score = a.opts.ConfidenceBaseline*0.5 + score*0.5
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// heuristicPrimeFragment returns a small prime-derived blob as additional heuristic entropy.
// Disabled by default (costly) — enabled only if opts.EnablePrimeHeuristic == true.
func heuristicPrimeFragment() ([]byte, error) {
	bits := 128 + (time.Now().UnixNano() % 64)
	if bits < 64 {
		bits = 64
	}
	nBytes := int((bits + 7) / 8)
	b := make([]byte, nBytes)
	if _, err := crand.Read(b); err != nil {
		return nil, err
	}
	b[0] |= 0x80
	p := new(big.Int).SetBytes(b)
	for i := 0; i < 16; i++ {
		if p.ProbablyPrime(20) {
			return p.Bytes(), nil
		}
		p.Add(p, big.NewInt(1))
	}
	h := sha512.Sum512(b)
	return h[:32], nil
}

// SelfTest performs a lightweight functional check: ensures outputs vary across calls
// and confidence is reasonable. It is intended as an operational sanity check only.
func (a *AIEntropyAlgorithm) SelfTest() error {
	out1, conf1, err1 := a.GetEntropy(context.Background(), 32)
	if err1 != nil {
		return err1
	}
	time.Sleep(5 * time.Millisecond)
	out2, conf2, err2 := a.GetEntropy(context.Background(), 32)
	if err2 != nil {
		ZeroBytes(out1)
		return err2
	}
	// identical outputs -> likely broken
	if len(out1) == len(out2) {
		same := true
		for i := range out1 {
			if out1[i] != out2[i] {
				same = false
				break
			}
		}
		if same {
			ZeroBytes(out1); ZeroBytes(out2)
			return &SelfTestError{"ai_entropy: outputs identical across calls"}
		}
	}
	// confidence check (very lenient)
	if conf1 < 0.05 || conf2 < 0.05 {
		// warn but do not fail hard; return a warning-like error
		ZeroBytes(out1); ZeroBytes(out2)
		return &SelfTestError{"ai_entropy: low confidence observed"}
	}
	ZeroBytes(out1); ZeroBytes(out2)
	return nil
}

// SelfTestError is a small error type for SelfTest.
type SelfTestError struct{ Msg string }

func (e *SelfTestError) Error() string { return e.Msg }

// ZeroBytes: best-effort zeroing for slices
func ZeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}