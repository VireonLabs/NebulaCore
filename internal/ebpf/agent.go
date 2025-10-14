package ebpf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Signer signs byte blobs. Implementations should use HSM/Vault/KMS signatures in production.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Keystore is a minimal interface for storing raw blobs securely (e.g. Vault/secure keystore).
type Keystore interface {
	PutRaw(key string, raw []byte) error
	GetRaw(key string) ([]byte, error)
}

// SourceVerifier validates that an input source file is signed/approved by a trusted developer.
type SourceVerifier interface {
	// Verify returns nil if trusted, or an error describing why not trusted.
	Verify(srcPath string) error
}

// dualSignature is the container we store for dual-signed artifacts.
type dualSignature struct {
	Internal string `json:"internal"` // hex of internal signature
	External string `json:"external"` // hex of external signature (optional)
	Algo     string `json:"algo"`     // e.g. "sha256+ed25519" (informational)
	Time     string `json:"time"`     // ISO timestamp of signing
	Source   string `json:"source"`   // original source path (metadata)
}

// Loader compiles and stages eBPF objects securely.
type Loader struct {
	progDir       string
	tmpDir        string
	internal      Signer       // primary (internal) signer
	external      Signer       // optional external signer (KMS/HSM)
	ks            Keystore     // optional keystore to store signatures
	verifier      SourceVerifier
	logger        *log.Logger
	dstLocks      map[string]*sync.Mutex
	dlMu          sync.Mutex
	enableSandbox bool

	// simple cache: map[srcHashHex] => {dst, dstSigKeyOrPath}
	cache   map[string][2]string
	cacheMu sync.RWMutex
}

// NewLoader constructs Loader.
//
// progDir: directory where compiled objects are placed (will be created).
// tmpDir: directory to place temporaries (if empty uses os.TempDir()).
// internalSigner: required primary signer (for internal attestation).
// logger: optional; if nil, uses log.Default().
func NewLoader(progDir string, tmpDir string, internalSigner Signer, logger *log.Logger) *Loader {
	if progDir == "" {
		progDir = "/opt/laserwall/ebpf"
	}
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	if logger == nil {
		logger = log.Default()
	}
	if err := os.MkdirAll(progDir, 0o750); err != nil {
		logger.Printf("[ebpf] warning: failed create progDir %s: %v", progDir, err)
	}
	return &Loader{
		progDir:  progDir,
		tmpDir:   tmpDir,
		internal: internalSigner,
		logger:   logger,
		dstLocks: map[string]*sync.Mutex{},
		cache:    map[string][2]string{},
	}
}

// SetExternalSigner configures an external signer (KMS/HSM) for dual-attestation.
func (l *Loader) SetExternalSigner(s Signer) { l.external = s }

// SetKeystore configures a keystore to store signatures (instead of writing .sha256 files).
func (l *Loader) SetKeystore(ks Keystore) { l.ks = ks }

// SetSourceVerifier configures a verifier to check source signatures before building.
func (l *Loader) SetSourceVerifier(v SourceVerifier) { l.verifier = v }

// EnableSandbox toggles building inside a lightweight namespace sandbox (Linux-only).
func (l *Loader) EnableSandbox(enable bool) { l.enableSandbox = enable }

func (l *Loader) lockFor(dst string) func() {
	l.dlMu.Lock()
	m, ok := l.dstLocks[dst]
	if !ok {
		m = &sync.Mutex{}
		l.dstLocks[dst] = m
	}
	l.dlMu.Unlock()
	m.Lock()
	return func() { m.Unlock() }
}

// computeFileSHA256Hex reads file streaming and returns hex string.
func computeFileSHA256Hex(path string) (string, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", nil, err
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum), sum, nil
}

// atomicWriteFile writes data to tmp -> fsync -> rename
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, perm)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// BuildAndStage compiles C source to object, performs integrity checks, dual-signs, stores signature
// (to keystore if provided) and stages object atomically. Returns (dstObjectPath, dstSigKeyOrPath, error).
func (l *Loader) BuildAndStage(ctx context.Context, srcPath string) (string, string, error) {
	// normalize and check source
	srcPath = filepath.Clean(srcPath)
	info, err := os.Stat(srcPath)
	if err != nil {
		return "", "", fmt.Errorf("source not accessible: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("source is not a regular file: %s", srcPath)
	}

	// optional: verify source signature before building
	if l.verifier != nil {
		if err := l.verifier.Verify(srcPath); err != nil {
			return "", "", fmt.Errorf("source signature verification failed: %w", err)
		}
		l.logger.Printf("[ebpf] source verified: %s", srcPath)
	}

	// compute source hash to use cache key
	srcHashHex, _, err := computeFileSHA256Hex(srcPath)
	if err != nil {
		return "", "", fmt.Errorf("compute src hash: %w", err)
	}

	// if cached and artifact exists, return it
	l.cacheMu.RLock()
	if v, ok := l.cache[srcHashHex]; ok {
		l.cacheMu.RUnlock()
		dst, sig := v[0], v[1]
		// double-check dst exists
		if st, e := os.Stat(dst); e == nil && st.Mode().IsRegular() {
			l.logger.Printf("[ebpf] cache hit for src=%s -> dst=%s", srcPath, dst)
			return dst, sig, nil
		}
		// fallback continue build if file missing
	} else {
		l.cacheMu.RUnlock()
	}

	// ensure clang available
	clang, err := exec.LookPath("clang")
	if err != nil {
		return "", "", fmt.Errorf("clang not available: %w", err)
	}

	base := filepath.Base(srcPath)
	outName := base + ".o"

	// build into secure temp file
	tmpObj, err := os.CreateTemp(l.tmpDir, "ebpf-*.o")
	if err != nil {
		return "", "", fmt.Errorf("create temp object failed: %w", err)
	}
	tmpObjPath := tmpObj.Name()
	_ = tmpObj.Close()
	// ensure temp is removed on errors
	removeTmpObj := func() { _ = os.Remove(tmpObjPath) }

	// prepare clang command
	cmd := exec.CommandContext(ctx, clang, "-O2", "-target", "bpf", "-c", srcPath, "-o", tmpObjPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// optionally enable sandbox namespaces (Linux)
	if l.enableSandbox {
		// best-effort: apply user+net+mount namespaces to isolate build.
		// NOTE: this requires appropriate privileges or user namespace support.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		}
		// map uid/gid in userns might be required in production.
	}

	l.logger.Printf("[ebpf] building %s -> %s (sandbox=%v)", srcPath, tmpObjPath, l.enableSandbox)
	if err := cmd.Run(); err != nil {
		removeTmpObj()
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		return "", "", fmt.Errorf("clang failed: %v stderr=%s", err, stderr.String())
	}

	// compute object hash streaming
	objHashHex, objSum, err := computeFileSHA256Hex(tmpObjPath)
	if err != nil {
		removeTmpObj()
		return "", "", fmt.Errorf("compute object hash: %w", err)
	}

	// create internal signature (required)
	if l.internal == nil {
		removeTmpObj()
		return "", "", errors.New("internal signer not configured")
	}
	intSig, err := l.internal.Sign(objSum)
	if err != nil {
		removeTmpObj()
		return "", "", fmt.Errorf("internal signer failed: %w", err)
	}

	// create external signature if configured
	var extSig []byte
	if l.external != nil {
		extSig, err = l.external.Sign(objSum)
		if err != nil {
			// treat external signer failure as fatal to ensure dual attestation semantics.
			removeTmpObj()
			return "", "", fmt.Errorf("external signer failed: %w", err)
		}
	}

	// compose dual signature payload
	ds := dualSignature{
		Internal: hex.EncodeToString(intSig),
		External: hex.EncodeToString(extSig),
		Algo:     "sha256",
		Time:     time.Now().UTC().Format(time.RFC3339),
		Source:   srcPath,
	}
	dsB, _ := json.Marshal(ds)

	// prepare destination paths
	dst := filepath.Join(l.progDir, outName)
	dstSigFile := dst + ".sha256.json" // JSON container for dual signature

	// lock destination
	unlock := l.lockFor(dst)
	defer unlock()

	// defensive checks: refuse to overwrite symlink or directory
	if fi, err := os.Lstat(dst); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() {
			removeTmpObj()
			return "", "", fmt.Errorf("destination unsafe: %s", dst)
		}
	}

	// write object atomically into progDir
	tmpDstObj, err := os.CreateTemp(l.progDir, outName+".tmp-*")
	if err != nil {
		removeTmpObj()
		return "", "", fmt.Errorf("create temp in progDir failed: %w", err)
	}
	tmpDstObjPath := tmpDstObj.Name()
	// write contents
	srcF, err := os.Open(tmpObjPath)
	if err != nil {
		tmpDstObj.Close()
		_ = os.Remove(tmpDstObjPath)
		removeTmpObj()
		return "", "", fmt.Errorf("reopen tmp object: %w", err)
	}
	if _, err := io.Copy(tmpDstObj, srcF); err != nil {
		srcF.Close()
		tmpDstObj.Close()
		_ = os.Remove(tmpDstObjPath)
		removeTmpObj()
		return "", "", fmt.Errorf("copy to dst temp failed: %w", err)
	}
	srcF.Close()
	_ = tmpDstObj.Chmod(0o644)
	_ = tmpDstObj.Sync()
	_ = tmpDstObj.Close()

	if err := os.Rename(tmpDstObjPath, dst); err != nil {
		_ = os.Remove(tmpDstObjPath)
		removeTmpObj()
		return "", "", fmt.Errorf("rename to dst failed: %w", err)
	}

	// store signature: prefer keystore if provided (key = "ebpf/<outName>/<objHash>")
	sigKey := fmt.Sprintf("ebpf/%s/%s", outName, objHashHex)
	if l.ks != nil {
		if err := l.ks.PutRaw(sigKey, dsB); err != nil {
			// if keystore fails, roll back object to avoid inconsistent state
			_ = os.Remove(dst)
			removeTmpObj()
			return "", "", fmt.Errorf("keystore PutRaw failed: %w", err)
		}
		// record cache and return the keystore key as signature reference
		l.cacheMu.Lock()
		l.cache[srcHashHex] = [2]string{dst, sigKey}
		l.cacheMu.Unlock()
		// cleanup tmp build artifact
		_ = os.Remove(tmpObjPath)
		l.logger.Printf("[ebpf-audit] built src=%s dst=%s hash=%s sig_key=%s time=%s", srcPath, dst, objHashHex, sigKey, ds.Time)
		return dst, sigKey, nil
	}

	// otherwise write signature JSON file atomically adjacent to artifact
	tmpSig, err := os.CreateTemp(l.progDir, outName+".sig.tmp-*")
	if err != nil {
		_ = os.Remove(dst)
		removeTmpObj()
		return "", "", fmt.Errorf("create tmp sig failed: %w", err)
	}
	tmpSigPath := tmpSig.Name()
	if _, err := tmpSig.Write(dsB); err != nil {
		tmpSig.Close()
		_ = os.Remove(tmpSigPath)
		_ = os.Remove(dst)
		removeTmpObj()
		return "", "", fmt.Errorf("write tmp sig failed: %w", err)
	}
	_ = tmpSig.Sync()
	_ = tmpSig.Close()
	if err := os.Rename(tmpSigPath, dstSigFile); err != nil {
		_ = os.Remove(tmpSigPath)
		_ = os.Remove(dst)
		removeTmpObj()
		return "", "", fmt.Errorf("rename sig to dst failed: %w", err)
	}

	// update cache
	l.cacheMu.Lock()
	l.cache[srcHashHex] = [2]string{dst, dstSigFile}
	l.cacheMu.Unlock()

	_ = os.Remove(tmpObjPath)
	l.logger.Printf("[ebpf-audit] built src=%s dst=%s hash=%s sig=%s time=%s", srcPath, dst, objHashHex, dstSigFile, ds.Time)
	return dst, dstSigFile, nil
}

// ------------------------------
// Local test implementations
// ------------------------------

// LocalSigner is a simple test signer that returns SHA256(data).
// NOT suitable for production; replace with HSM/Vault-backed Signer.
type LocalSigner struct{}

func (s *LocalSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	// return raw hash as "signature" (binary)
	out := make([]byte, len(h))
	copy(out, h[:])
	return out, nil
}

// FileKeystore is a minimal file-based keystore for local testing.
type FileKeystore struct {
	dir string
}

func NewFileKeystore(dir string) (*FileKeystore, error) {
	if dir == "" {
		dir = "/var/lib/laserwall/keystore_local"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileKeystore{dir: dir}, nil
}

func (k *FileKeystore) pathFor(key string) string {
	// sanitize: replace slashes
	safe := filepath.Clean(key)
	// remove any leading "../"
	safe = filepath.Join(".", safe)
	return filepath.Join(k.dir, safe)
}

func (k *FileKeystore) PutRaw(key string, raw []byte) error {
	p := k.pathFor(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return atomicWriteFile(p, raw, 0o600)
}

func (k *FileKeystore) GetRaw(key string) ([]byte, error) {
	p := k.pathFor(key)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// SimpleSourceVerifier expects a sibling .sig file containing hex of the expected SHA256(sum).
// If a keystore is provided and contains a trusted entry "trusted_sources/<hex>", the signature must match that entry.
type SimpleSourceVerifier struct {
	ks Keystore // optional
}

func NewSimpleSourceVerifier(ks Keystore) *SimpleSourceVerifier {
	return &SimpleSourceVerifier{ks: ks}
}

func (v *SimpleSourceVerifier) Verify(srcPath string) error {
	sigPath := srcPath + ".sig"
	b, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("signature file missing: %w", err)
	}
	sigHex := string(bytes.TrimSpace(b))
	// compute actual hash
	actualHex, _, err := computeFileSHA256Hex(srcPath)
	if err != nil {
		return fmt.Errorf("compute src hash: %w", err)
	}
	// LocalSigner convention: signature == hex(sha256(src))
	if sigHex != actualHex {
		return fmt.Errorf("signature mismatch: sig=%s actual=%s", sigHex, actualHex)
	}
	// optional keystore check: if keystore contains trust entry for this sig
	if v.ks != nil {
		trustKey := "trusted_sources/" + sigHex
		if _, err := v.ks.GetRaw(trustKey); err == nil {
			// trusted
			return nil
		}
		// not explicitly trusted in keystore; still accept because signature matched
		// policy choice: we accept matching signature; to require keystore trust, return error here.
	}
	return nil
}