// internal/storage/distributed.go
// NebulaCore Distributed Storage (production-oriented)
// Production-oriented, hardened version with:
// - Manifest persistence (file-backed ManifestStore).
// - ShardInfo persisted in manifests (shard -> backend mapping).
// - Atomic upload (write shards first, cleanup on failure, then persist manifest).
// - PutShard with timeout + retries (supports ctx-aware backends).
// - Streaming upload API (uses StreamPlacementPlugin when available).
// - Merkle tree (binary) and verification.
// - Self-healing scanner invoking RepairPlugin periodically.
// - Hooks: PolicyChecker, Encryptor, MetricsCollector, ErasureCoder.
// - Manifest signing (HMAC) hook, plugin whitelist, orphan registry, context-aware backends.
// - Improvements: richer tracing (tracef), context-aware operations, persistent orphan registry,
//   and chunked streaming fallback to avoid full temp-file buffering for very large uploads.

package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"plugin"
)

// -------------------- Models --------------------

type Shard struct {
	ID         string
	Backend    string
	Region     string
	Data       []byte
	Checksum   string // plaintext checksum (if available)
	CipherHash string // ciphertext checksum (if encrypted)
	Parity     bool
	Index      int
	CreatedAt  time.Time
}

type ShardInfo struct {
	ID             string `json:"id"`
	Backend        string `json:"backend"`
	Region         string `json:"region,omitempty"`
	Index          int    `json:"index"`
	Checksum       string `json:"checksum,omitempty"`        // plaintext checksum
	CipherChecksum string `json:"cipher_checksum,omitempty"` // checksum of what was stored on backend
}

type FileManifest struct {
	FileName   string            `json:"file_name"`
	Shards     []ShardInfo       `json:"shards"`
	Regions    []string          `json:"regions"`
	Version    int               `json:"version"`
	MerkleRoot string            `json:"merkle_root"`
	Signature  []byte            `json:"signature,omitempty"`
	History    []string          `json:"history"`
	Meta       map[string]any    `json:"meta"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// -------------------- Interfaces / Hooks --------------------

type StorageBackend interface {
	PutShard(shard Shard) error
	GetShard(shardID string) (Shard, error)
	DeleteShard(shardID string) error
	ListShards(prefix string) ([]string, error)
}

// optional context-aware backend interface (preferred)
type StorageBackendWithCtx interface {
	PutShardCtx(ctx context.Context, shard Shard) error
	GetShardCtx(ctx context.Context, shardID string) (Shard, error)
	DeleteShardCtx(ctx context.Context, shardID string) error
}

type PlacementPlugin interface {
	PlaceShards(file []byte, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error)
}

type StreamPlacementPlugin interface {
	PlaceShardsStream(r io.Reader, size int64, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error)
}

type RepairPlugin interface {
	Repair(ctx context.Context, manifest *FileManifest, backends map[string]StorageBackend) error
}

type ErasureCoder interface {
	Encode(file []byte, dataShards, parityShards int) ([]Shard, error)
	Reconstruct(shards []Shard, dataShards, parityShards int) ([]byte, error)
}

type PolicyChecker func(action string, manifest *FileManifest, opts map[string]any) error

type Encryptor interface {
	Encrypt(plain []byte, meta map[string]any) ([]byte, error)
	Decrypt(cipher []byte, meta map[string]any) ([]byte, error)
}

type MetricsCollector interface {
	ObserveUpload(file string, bytes int)
	ObserveDownload(file string, bytes int)
	ObserveRepair(file string, success bool, duration time.Duration)
	IncShardStored()
	IncShardDeleted()
}

// ManifestStore: durable manifest persistence
type ManifestStore interface {
	Save(m FileManifest) error
	Load(name string) (FileManifest, bool, error)
	LoadAll() ([]FileManifest, error)
	Delete(name string) error
}

// Manifest signer (HMAC or KMS-backed signer)
type ManifestSigner interface {
	Sign(m *FileManifest) error
	Verify(m *FileManifest) error
}

// Orphan registry to record orphaned shards if deletion fails
type OrphanRegistry interface {
	RegisterOrphan(sh Shard) error
	ListOrphans() []Shard
	CleanupOlderThan(d time.Duration) []Shard
}

// -------------------- Storage core --------------------

type DistributedStorage struct {
	mu              sync.RWMutex
	backends        map[string]StorageBackend
	manifests       map[string]FileManifest
	manifestStore   ManifestStore
	repairPlugin    RepairPlugin
	placementPlugin PlacementPlugin
	erasureCoder    ErasureCoder
	plugins         map[string]*plugin.Plugin
	traces          []string
	auditLog        []string

	policyChecker PolicyChecker
	encryptor     Encryptor
	metrics       MetricsCollector

	repairInterval time.Duration
	repairCtx      context.Context
	repairCancel   context.CancelFunc
	repairRunning  bool

	rng *rand.Rand

	// production additions
	manifestSigner  ManifestSigner
	orphanRegistry  OrphanRegistry
	pluginWhitelist map[string]bool
}

func NewDistributedStorage() *DistributedStorage {
	src := rand.NewSource(time.Now().UnixNano())
	return &DistributedStorage{
		backends:       make(map[string]StorageBackend),
		manifests:      make(map[string]FileManifest),
		plugins:        make(map[string]*plugin.Plugin),
		repairInterval: 60 * time.Second,
		rng:            rand.New(src),
		pluginWhitelist: nil,
	}
}

// -------------------- Manifest store (file-backed) --------------------

type FileManifestStore struct {
	dir string
}

func NewFileManifestStore(dir string) (*FileManifestStore, error) {
	if dir == "" {
		return nil, errors.New("manifest store dir empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileManifestStore{dir: dir}, nil
}

func (fs *FileManifestStore) pathFor(name string) string {
	// minimal sanitize: strip any path separators
	name = strings.ReplaceAll(name, string(filepath.Separator), "_")
	filename := fmt.Sprintf("%s.json", name)
	return filepath.Join(fs.dir, filename)
}

func (fs *FileManifestStore) Save(m FileManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := fs.pathFor(m.FileName) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, fs.pathFor(m.FileName))
}

func (fs *FileManifestStore) Load(name string) (FileManifest, bool, error) {
	var m FileManifest
	path := fs.pathFor(name)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false, err
	}
	return m, true, nil
}

func (fs *FileManifestStore) LoadAll() ([]FileManifest, error) {
	files, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, err
	}
	out := []FileManifest{}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		if !strings.HasSuffix(fi.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fs.dir, fi.Name()))
		if err != nil {
			continue
		}
		var m FileManifest
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func (fs *FileManifestStore) Delete(name string) error {
	return os.Remove(fs.pathFor(name))
}

// -------------------- Setters / registration --------------------
func (s *DistributedStorage) SetManifestStore(ms ManifestStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifestStore = ms
	if ms != nil {
		if all, err := ms.LoadAll(); err == nil {
			for _, m := range all {
				s.manifests[m.FileName] = m
			}
		}
	}
}

func (s *DistributedStorage) RegisterBackend(name string, backend StorageBackend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backends[name] = backend
	s.traces = append(s.traces, fmt.Sprintf("backend %s registered", name))
}

func (s *DistributedStorage) SetPlacementPlugin(pp PlacementPlugin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.placementPlugin = pp
}

func (s *DistributedStorage) SetRepairPlugin(rp RepairPlugin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repairPlugin = rp
}

func (s *DistributedStorage) SetErasureCoder(ec ErasureCoder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.erasureCoder = ec
}

func (s *DistributedStorage) SetPolicyChecker(pc PolicyChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyChecker = pc
}

func (s *DistributedStorage) SetEncryptor(e Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = e
}

func (s *DistributedStorage) SetMetricsCollector(m MetricsCollector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics = m
}

// Manifest signer setter
func (s *DistributedStorage) SetManifestSigner(ms ManifestSigner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifestSigner = ms
}

// Orphan registry setter
func (s *DistributedStorage) SetOrphanRegistry(or OrphanRegistry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orphanRegistry = or
}

// Plugin whitelist setter (list of allowed plugin base filenames)
func (s *DistributedStorage) SetPluginWhitelist(list []string) {
	m := make(map[string]bool, len(list))
	for _, p := range list {
		m[p] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pluginWhitelist = m
}

// -------------------- Helpers --------------------

func (s *DistributedStorage) makeShardID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), s.rng.Int63())
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// tracef: richer tracing + stdout logging for operators
func (s *DistributedStorage) tracef(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	// append to in-memory traces with lock
	s.mu.Lock()
	s.traces = append(s.traces, msg)
	s.mu.Unlock()
	// also log to standard logger for operators
	log.Printf("[DistributedStorage] %s", msg)
}

// small helper: sign manifest if signer present
func (s *DistributedStorage) ensureSignManifest(m *FileManifest) error {
	s.mu.RLock()
	signer := s.manifestSigner
	s.mu.RUnlock()
	if signer == nil {
		return nil
	}
	return signer.Sign(m)
}

// putShardWithRetry: supports ctx-aware backend when available
func (s *DistributedStorage) putShardWithRetry(ctx context.Context, be StorageBackend, sh Shard, attempts int, attemptTimeout time.Duration) error {
	var lastErr error
	// detect ctx-aware backend
	if beWithCtx, ok := be.(StorageBackendWithCtx); ok {
		for i := 0; i < attempts; i++ {
			// if ctx already cancelled, bail early
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			cctx, cancel := context.WithTimeout(ctx, attemptTimeout)
			err := beWithCtx.PutShardCtx(cctx, sh)
			cancel()
			if err == nil {
				s.tracef("putShard success (ctx-aware) shard=%s backend=%s", sh.ID, sh.Backend)
				return nil
			}
			lastErr = err
			s.tracef("putShard attempt %d failed shard=%s backend=%s err=%v", i+1, sh.ID, sh.Backend, err)
			backoff := time.Duration(200*int(math.Pow(2, float64(i)))) * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return lastErr
	}
	// fallback: run blocking PutShard in goroutine with timeout
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		cctx, cancel := context.WithTimeout(ctx, attemptTimeout)
		done := make(chan error, 1)
		go func() {
			done <- be.PutShard(sh)
		}()
		select {
		case err := <-done:
			cancel()
			if err == nil {
				s.tracef("putShard success shard=%s backend=%s", sh.ID, sh.Backend)
				return nil
			}
			lastErr = err
			s.tracef("putShard failed shard=%s backend=%s err=%v", sh.ID, sh.Backend, err)
		case <-cctx.Done():
			cancel()
			lastErr = fmt.Errorf("putshard timeout")
			s.tracef("putShard timeout shard=%s backend=%s", sh.ID, sh.Backend)
		}
		backoff := time.Duration(200*int(math.Pow(2, float64(i)))) * time.Millisecond
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}

// getShardBackendDirect: get shard from specified backend (uses encryptor to decrypt), prefers ctx-aware backend
func (s *DistributedStorage) getShardBackendDirect(ctx context.Context, backendName, shardID string) (Shard, error) {
	s.mu.RLock()
	be, ok := s.backends[backendName]
	enc := s.encryptor
	s.mu.RUnlock()
	if !ok {
		return Shard{}, fmt.Errorf("backend %s not registered", backendName)
	}
	// if ctx already cancelled
	select {
	case <-ctx.Done():
		return Shard{}, ctx.Err()
	default:
	}
	if beWithCtx, ok := be.(StorageBackendWithCtx); ok {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		sh, err := beWithCtx.GetShardCtx(cctx, shardID)
		if err != nil {
			return Shard{}, err
		}
		if enc != nil {
			plain, err := enc.Decrypt(sh.Data, map[string]any{"shard_id": sh.ID})
			if err != nil {
				return Shard{}, fmt.Errorf("decrypt failed: %w", err)
			}
			sh.Data = plain
		}
		return sh, nil
	}
	// fallback: run blocking GetShard in goroutine with timeout
	done := make(chan struct {
		sh  Shard
		err error
	}, 1)
	go func() {
		sh, err := be.GetShard(shardID)
		done <- struct {
			sh  Shard
			err error
		}{sh: sh, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return Shard{}, r.err
		}
		if enc != nil {
			plain, err := enc.Decrypt(r.sh.Data, map[string]any{"shard_id": r.sh.ID})
			if err != nil {
				return Shard{}, fmt.Errorf("decrypt failed: %w", err)
			}
			r.sh.Data = plain
		}
		return r.sh, nil
	case <-time.After(15 * time.Second):
		return Shard{}, errors.New("getshard timeout")
	case <-ctx.Done():
		return Shard{}, ctx.Err()
	}
}

// computeMerkleRoot: binary merkle over shard.Data
func computeMerkleRoot(shards []Shard) string {
	if len(shards) == 0 {
		return sha256Hex([]byte{})
	}
	leaves := make([][]byte, 0, len(shards))
	for _, sh := range shards {
		h := sha256.Sum256(sh.Data)
		leaves = append(leaves, h[:])
	}
	for len(leaves) > 1 {
		if len(leaves)%2 == 1 {
			dup := make([]byte, len(leaves[len(leaves)-1]))
			copy(dup, leaves[len(leaves)-1])
			leaves = append(leaves, dup)
		}
		next := make([][]byte, 0, len(leaves)/2)
		for i := 0; i < len(leaves); i += 2 {
			conc := append(leaves[i], leaves[i+1]...)
			h := sha256.Sum256(conc)
			next = append(next, h[:])
		}
		leaves = next
	}
	return hex.EncodeToString(leaves[0])
}

// -------------------- Upload APIs --------------------

// UploadStream: streaming-aware upload. Uses StreamPlacementPlugin if available, else falls back to safe buffering.
// Improvements:
// - supports ctx cancellation across all phases,
// - chunked streaming fallback (avoid holding huge temp file in disk for TB files),
// - richer tracing,
// - atomic write semantics and orphan recording on cleanup.
func (s *DistributedStorage) UploadStream(ctx context.Context, name string, r io.Reader, size int64, opts map[string]any) error {
	// policy check
	if s.policyChecker != nil {
		if err := s.policyChecker("upload", nil, map[string]any{"filename": name, "opts": opts}); err != nil {
			return err
		}
	}

	// capture placement/erasure/encryptor/backends snapshot
	s.mu.RLock()
	pp := s.placementPlugin
	var spp StreamPlacementPlugin
	if pp != nil {
		if sp, ok := pp.(StreamPlacementPlugin); ok {
			spp = sp
		}
	}
	ec := s.erasureCoder
	backendsCopy := make(map[string]StorageBackend, len(s.backends))
	for k, v := range s.backends {
		backendsCopy[k] = v
	}
	enc := s.encryptor
	metrics := s.metrics
	orphanReg := s.orphanRegistry
	s.mu.RUnlock()

	// If placement plugin supports streaming, delegate
	if spp != nil {
		shards, err := spp.PlaceShardsStream(r, size, backendsCopy, opts)
		if err != nil {
			return err
		}
		// compute merkle and persist shards similar to below
		return s.persistShardsWithCtx(ctx, name, shards, opts, enc, metrics, orphanReg)
	}

	// If erasure coder present and placement plugin absent, we need the full data for encoding.
	if ec != nil && (pp == nil) {
		// when encoding is required, buffer to temp file if size large, to avoid OOM
		var data []byte
		var err error
		if size > 0 && size <= 256*1024*1024 {
			data, err = io.ReadAll(r)
			if err != nil {
				return err
			}
		} else {
			tmp, err := os.CreateTemp("", "upload-*")
			if err != nil {
				return err
			}
			defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
			if _, err := io.Copy(tmp, r); err != nil {
				return err
			}
			if _, err := tmp.Seek(0, io.SeekStart); err != nil {
				return err
			}
			data, err = io.ReadAll(tmp)
			if err != nil {
				return err
			}
		}
		shards, err := ec.Encode(data, 4, 2) // defaults; placement may be embedded in shards from EC
		if err != nil {
			return err
		}
		// set shard IDs if missing
		for i := range shards {
			if shards[i].ID == "" {
				shards[i].ID = s.makeShardID(name)
			}
		}
		return s.persistShardsWithCtx(ctx, name, shards, opts, enc, metrics, orphanReg)
	}

	// Fallback placement: replicate or chunked replication for very large streams.
	// We'll stream in CHUNKs and place each chunk as a shard (replication).
	const defaultChunkSize = 64 * 1024 * 1024 // 64MB
	chunkSize := defaultChunkSize
	if v, ok := opts["chunk_size"].(int); ok && v > 0 {
		chunkSize = v
	}
	buf := make([]byte, chunkSize)
	shardsAll := make([]Shard, 0)
	chunkIndex := 0
	for {
		// Respect ctx cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			// For ErrUnexpectedEOF we still have n>0; for EOF n==0 break
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				// proceed to handle partial chunk below
			} else {
				return err
			}
		}
		if n == 0 {
			break
		}
		chunk := make([]byte, n)
		copy(chunk, buf[:n])
		// create shards for this chunk (replicate across backends)
		s.mu.RLock()
		names := make([]string, 0, len(s.backends))
		for k := range s.backends {
			names = append(names, k)
		}
		sort.Strings(names)
		s.mu.RUnlock()
		if len(names) == 0 {
			return errors.New("no backends available")
		}
		replicas := len(names)
		if v, ok := opts["replicas"].(int); ok && v > 0 {
			replicas = v
		}
		chunkShards := make([]Shard, 0, replicas)
		for i := 0; i < replicas; i++ {
			sh := Shard{
				ID:        s.makeShardID(name),
				Backend:   names[(chunkIndex+i)%len(names)],
				Data:      chunk,
				Checksum:  sha256Hex(chunk),
				Parity:    false,
				Index:     chunkIndex,
				CreatedAt: time.Now().UTC(),
			}
			chunkShards = append(chunkShards, sh)
		}
		// encrypt chunk shards if needed and write them now (atomic semantics per-chunk)
		for i := range chunkShards {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if enc != nil {
				cipher, err := enc.Encrypt(chunkShards[i].Data, map[string]any{"file": name, "shard_id": chunkShards[i].ID, "index": chunkShards[i].Index})
				if err != nil {
					// cleanup previously written shards
					for _, w := range shardsAll {
						if be, ok := s.backends[w.Backend]; ok {
							_ = be.DeleteShard(w.ID)
						}
					}
					return fmt.Errorf("encrypt shard failed: %w", err)
				}
				chunkShards[i].CipherHash = sha256Hex(cipher)
				chunkShards[i].Data = cipher
			}
			// write shard with retries
			ctxPut, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := s.putShardWithRetry(ctxPut, s.backends[chunkShards[i].Backend], chunkShards[i], 3, 8*time.Second)
			cancel()
			if err != nil {
				// cleanup previously written shards
				for _, w := range shardsAll {
					if be, ok := s.backends[w.Backend]; ok {
						if derr := be.DeleteShard(w.ID); derr != nil {
							if orphanReg != nil {
								_ = orphanReg.RegisterOrphan(w)
							}
						}
						if metrics != nil {
							metrics.IncShardDeleted()
						}
					}
				}
				if orphanReg != nil {
					_ = orphanReg.RegisterOrphan(chunkShards[i])
				}
				return fmt.Errorf("failed write shard %s: %w", chunkShards[i].ID, err)
			}
			shardsAll = append(shardsAll, chunkShards[i])
			if metrics != nil {
				metrics.IncShardStored()
			}
			s.tracef("streamed chunk shard %s backend=%s index=%d", chunkShards[i].ID, chunkShards[i].Backend, chunkShards[i].Index)
		}
		chunkIndex++
		// when reached EOF
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			// we've handled the last partial chunk; break
			break
		}
	}

	// build manifest from chunk-shards. Each chunk produced replicas; we persist one manifest referencing one shard per chunk (choose first replica per chunk)
	shardInfos := make([]ShardInfo, 0)
	// choose first encountered shard for each index
	indexMap := map[int]bool{}
	for _, sh := range shardsAll {
		if indexMap[sh.Index] {
			continue
		}
		indexMap[sh.Index] = true
		shardInfos = append(shardInfos, ShardInfo{
			ID:             sh.ID,
			Backend:        sh.Backend,
			Region:         sh.Region,
			Index:          sh.Index,
			Checksum:       sh.Checksum,
			CipherChecksum: sh.CipherHash,
		})
	}
	merkleRoot := computeMerkleRoot(shardsAll)
	now := time.Now().UTC()
	m := FileManifest{
		FileName:   name,
		Shards:     shardInfos,
		Regions:    nil,
		Version:    1,
		MerkleRoot: merkleRoot,
		History:    []string{fmt.Sprintf("stream-uploaded at %s", now.String())},
		Meta:       map[string]any{"chunked": true, "chunks": chunkIndex},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if v, ok := opts["owner"].(string); ok {
		m.Meta["owner"] = v
	}
	// sign + persist manifest
	if s.manifestStore != nil {
		// sign
		if err := s.ensureSignManifest(&m); err != nil {
			// cleanup shardsAll
			for _, w := range shardsAll {
				if be, ok := s.backends[w.Backend]; ok {
					_ = be.DeleteShard(w.ID)
					if s.metrics != nil {
						s.metrics.IncShardDeleted()
					}
				}
			}
			return fmt.Errorf("failed sign manifest: %w", err)
		}
		if err := s.manifestStore.Save(m); err != nil {
			for _, w := range shardsAll {
				if be, ok := s.backends[w.Backend]; ok {
					if derr := be.DeleteShard(w.ID); derr != nil {
						if orphanReg != nil {
							_ = orphanReg.RegisterOrphan(w)
						}
					}
					if s.metrics != nil {
						s.metrics.IncShardDeleted()
					}
				}
			}
			return fmt.Errorf("failed save manifest: %w", err)
		}
	}
	// update in-memory
	s.mu.Lock()
	s.manifests[name] = m
	s.traces = append(s.traces, fmt.Sprintf("stream upload %s v%d shards=%d", name, m.Version, len(shardsAll)))
	s.mu.Unlock()
	if metrics != nil {
		if sizeVal, ok := opts["size"].(int); ok {
			metrics.ObserveUpload(name, sizeVal)
		}
	}
	return nil
}

// persistShardsWithCtx: helper used by UploadStream after getting shards list
func (s *DistributedStorage) persistShardsWithCtx(ctx context.Context, name string, shards []Shard, opts map[string]any, enc Encryptor, metrics MetricsCollector, orphanReg OrphanRegistry) error {
	// compute plain checksums/merkle before encryption overwrite
	plainShardsForMerkle := make([]Shard, 0, len(shards))
	for i := range shards {
		if shards[i].ID == "" {
			shards[i].ID = s.makeShardID(name)
		}
		shards[i].CreatedAt = time.Now().UTC()
		plain := shards[i].Data
		plainChecksum := sha256Hex(plain)
		shards[i].Checksum = plainChecksum
		plainShardsForMerkle = append(plainShardsForMerkle, Shard{
			ID:        shards[i].ID,
			Backend:   shards[i].Backend,
			Data:      plain,
			Checksum:  plainChecksum,
			Index:     shards[i].Index,
			CreatedAt: shards[i].CreatedAt,
		})
	}
	// encrypt if needed
	for i := range shards {
		if enc != nil {
			cipher, err := enc.Encrypt(shards[i].Data, map[string]any{"file": name, "shard_id": shards[i].ID, "index": shards[i].Index})
			if err != nil {
				return fmt.Errorf("encrypt shard failed: %w", err)
			}
			shards[i].CipherHash = sha256Hex(cipher)
			shards[i].Data = cipher
		} else {
			shards[i].CipherHash = ""
		}
	}
	// persist shards atomically
	written := []Shard{}
	for i := range shards {
		sh := &shards[i]
		if sh.Backend == "" {
			// assign backend round-robin if missing
			s.mu.RLock()
			names := make([]string, 0, len(s.backends))
			for k := range s.backends {
				names = append(names, k)
			}
			sort.Strings(names)
			s.mu.RUnlock()
			if len(names) == 0 {
				for _, w := range written {
					_ = s.backends[w.Backend].DeleteShard(w.ID)
					if metrics != nil {
						metrics.IncShardDeleted()
					}
				}
				return errors.New("no backends available to store shards")
			}
			sh.Backend = names[sh.Index%len(names)]
		}
		// respect ctx
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ctxPut, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := s.putShardWithRetry(ctxPut, s.backends[sh.Backend], *sh, 3, 8*time.Second)
		cancel()
		if err != nil {
			// cleanup written shards; if deletion fails register orphan
			for _, w := range written {
				if be, ok := s.backends[w.Backend]; ok {
					if derr := be.DeleteShard(w.ID); derr != nil {
						if orphanReg != nil {
							_ = orphanReg.RegisterOrphan(w)
						}
					}
					if metrics != nil {
						metrics.IncShardDeleted()
					}
				}
			}
			if orphanReg != nil {
				_ = orphanReg.RegisterOrphan(*sh)
			}
			return fmt.Errorf("failed write shard %s: %w", sh.ID, err)
		}
		written = append(written, *sh)
		if metrics != nil {
			metrics.IncShardStored()
		}
		s.tracef("persisted shard %s backend=%s index=%d", sh.ID, sh.Backend, sh.Index)
	}
	// Build manifest and persist via ManifestStore (if set) atomically
	shardInfos := make([]ShardInfo, 0, len(shards))
	for _, sh := range shards {
		shardInfos = append(shardInfos, ShardInfo{
			ID:             sh.ID,
			Backend:        sh.Backend,
			Region:         sh.Region,
			Index:          sh.Index,
			Checksum:       sh.Checksum,
			CipherChecksum: sh.CipherHash,
		})
	}
	merkleRoot := computeMerkleRoot(plainShardsForMerkle)
	now := time.Now().UTC()
	m := FileManifest{
		FileName:   name,
		Shards:     shardInfos,
		Regions:    nil,
		Version:    1,
		MerkleRoot: merkleRoot,
		History:    []string{fmt.Sprintf("uploaded at %s", now.String())},
		Meta:       map[string]any{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if v, ok := opts["regions"].([]string); ok {
		m.Regions = v
	}
	if v, ok := opts["owner"].(string); ok {
		m.Meta["owner"] = v
	}
	// include EC metadata if present in opts
	if ds, ok := opts["data_shards"].(int); ok {
		m.Meta["data_shards"] = ds
	}
	if ps, ok := opts["parity_shards"].(int); ok {
		m.Meta["parity_shards"] = ps
	}
	// if manifest exists increment version
	if s.manifestStore != nil {
		if prev, found, err := s.manifestStore.Load(name); err == nil && found {
			m.Version = prev.Version + 1
			m.History = append(prev.History, m.History...)
			m.CreatedAt = prev.CreatedAt
		}
		// sign manifest if possible
		if err := s.ensureSignManifest(&m); err != nil {
			// attempt cleanup of written shards on failure
			for _, w := range written {
				if be, ok := s.backends[w.Backend]; ok {
					_ = be.DeleteShard(w.ID)
					if metrics != nil {
						metrics.IncShardDeleted()
					}
				}
			}
			return fmt.Errorf("failed sign manifest: %w", err)
		}
		if err := s.manifestStore.Save(m); err != nil {
			// Save failed: attempt cleanup of written shards to avoid orphans
			for _, w := range written {
				if be, ok := s.backends[w.Backend]; ok {
					if derr := be.DeleteShard(w.ID); derr != nil {
						if orphanReg != nil {
							_ = orphanReg.RegisterOrphan(w)
						}
					}
					if metrics != nil {
						metrics.IncShardDeleted()
					}
				}
			}
			return fmt.Errorf("failed save manifest: %w", err)
		}
	}
	// update in-memory map
	s.mu.Lock()
	s.manifests[name] = m
	s.traces = append(s.traces, fmt.Sprintf("upload %s v%d shards=%d", name, m.Version, len(shards)))
	s.mu.Unlock()
	if metrics != nil {
		if sizeVal, ok := opts["size"].(int); ok {
			metrics.ObserveUpload(name, sizeVal)
		}
	}
	return nil
}

// Upload (convenience, reads all bytes into memory; prefer UploadStream for large files)
func (s *DistributedStorage) Upload(ctx context.Context, name string, data []byte, opts map[string]any) error {
	return s.UploadStream(ctx, name, io.NopCloser(bytesReader(data)), int64(len(data)), opts)
}

// bytesReader provides io.ReadCloser over []byte.
func bytesReader(b []byte) *readCloserBytes {
	return &readCloserBytes{b: b}
}
type readCloserBytes struct {
	b []byte
	i int64
}
func (r *readCloserBytes) Read(p []byte) (int, error) {
	if r.i >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += int64(n)
	return n, nil
}
func (r *readCloserBytes) Close() error { return nil }

// -------------------- Download --------------------
func (s *DistributedStorage) Download(ctx context.Context, name string) ([]byte, error) {
	// allow ctx cancellation early
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	s.mu.RLock()
	m, ok := s.manifests[name]
	pc := s.policyChecker
	metrics := s.metrics
	ec := s.erasureCoder
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("manifest not found")
	}
	if pc != nil {
		if err := pc("download", &m, map[string]any{"filename": name}); err != nil {
			return nil, err
		}
	}
	// fetch shards according to manifest.Shards (direct mapping)
	var mu sync.Mutex
	found := []Shard{}
	missing := []string{}
	wg := sync.WaitGroup{}
	for _, si := range m.Shards {
		wg.Add(1)
		go func(si ShardInfo) {
			defer wg.Done()
			// respect ctx
			select {
			case <-ctx.Done():
				return
			default:
			}
			sh, err := s.getShardBackendDirect(ctx, si.Backend, si.ID)
			if err != nil {
				mu.Lock()
				missing = append(missing, si.ID)
				mu.Unlock()
				return
			}
			// verify plaintext checksum
			if sha256Hex(sh.Data) != si.Checksum {
				mu.Lock()
				missing = append(missing, si.ID)
				mu.Unlock()
				return
			}
			// preserve Index from manifest (backend may not return)
			sh.Index = si.Index
			mu.Lock()
			found = append(found, sh)
			mu.Unlock()
		}(si)
	}
	wg.Wait()

	// If missing and repair plugin exists, try repair and retry once
	if len(missing) > 0 && s.repairPlugin != nil {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.repairPlugin.Repair(rctx, &m, s.backends)
		cancel()
		if err == nil {
			// reload manifest from store (if present)
			if s.manifestStore != nil {
				if mm, foundM, err := s.manifestStore.Load(name); err == nil && foundM {
					m = mm
					s.mu.Lock()
					s.manifests[name] = mm
					s.mu.Unlock()
				}
			}
			// retry once
			var f2 []Shard
			var missing2 []string
			for _, si := range m.Shards {
				sh, err := s.getShardBackendDirect(ctx, si.Backend, si.ID)
				if err != nil {
					missing2 = append(missing2, si.ID)
					continue
				}
				if sha256Hex(sh.Data) != si.Checksum {
					missing2 = append(missing2, si.ID)
					continue
				}
				sh.Index = si.Index
				f2 = append(f2, sh)
			}
			if len(missing2) == 0 {
				found = f2
				missing = nil
			}
		}
	}

	// Attempt reconstruction with erasure coder if available
	if ec != nil {
		// read EC params from manifest meta
		dataShards := 0
		parityShards := 0
		if v, ok := m.Meta["data_shards"].(int); ok {
			dataShards = v
		} else if v, ok := m.Meta["data_shards"].(float64); ok {
			dataShards = int(v)
		}
		if v, ok := m.Meta["parity_shards"].(int); ok {
			parityShards = v
		} else if v, ok := m.Meta["parity_shards"].(float64); ok {
			parityShards = int(v)
		}
		if dataShards > 0 {
			data, err := ec.Reconstruct(found, dataShards, parityShards)
			if err == nil {
				if metrics != nil {
					metrics.ObserveDownload(name, len(data))
				}
				return data, nil
			}
		}
	}

	// Naive concat ordered by Index
	sort.Slice(found, func(i, j int) bool { return found[i].Index < found[j].Index })
	var agg []byte
	for _, sh := range found {
		agg = append(agg, sh.Data...)
	}
	if metrics != nil {
		metrics.ObserveDownload(name, len(agg))
	}
	// verify merkle root
	if m.MerkleRoot != "" {
		calculated := computeMerkleRoot(found)
		if calculated != m.MerkleRoot {
			return nil, fmt.Errorf("merkle mismatch: got %s expected %s", calculated, m.MerkleRoot)
		}
	}
	return agg, nil
}

// -------------------- Self-healing --------------------

func (s *DistributedStorage) StartSelfHealing(interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repairRunning {
		return
	}
	if interval > 0 {
		s.repairInterval = interval
	}
	s.repairCtx, s.repairCancel = context.WithCancel(context.Background())
	s.repairRunning = true
	go s.repairLoop(s.repairCtx)
}

func (s *DistributedStorage) StopSelfHealing() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repairRunning && s.repairCancel != nil {
		s.repairCancel()
	}
	s.repairRunning = false
}

func (s *DistributedStorage) repairLoop(ctx context.Context) {
	ticker := time.NewTicker(s.repairInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// use background context for scans but respect cancellation
			s.scanAndRepair(ctx)
		}
	}
}

func (s *DistributedStorage) scanAndRepair(ctx context.Context) {
	s.mu.RLock()
	names := make([]string, 0, len(s.manifests))
	for k := range s.manifests {
		names = append(names, k)
	}
	s.mu.RUnlock()

	for _, name := range names {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		func() {
			defer cancel()
			s.mu.RLock()
			m := s.manifests[name]
			rp := s.repairPlugin
			pc := s.policyChecker
			s.mu.RUnlock()
			if pc != nil {
				if err := pc("repair_check", &m, map[string]any{"filename": name}); err != nil {
					return
				}
			}
			needsRepair := false
			for _, si := range m.Shards {
				_, err := s.getShardBackendDirect(cctx, si.Backend, si.ID)
				if err != nil {
					needsRepair = true
					break
				}
			}
			if needsRepair && rp != nil {
				start := time.Now()
				err := rp.Repair(cctx, &m, s.backends)
				success := err == nil
				if s.metrics != nil {
					s.metrics.ObserveRepair(name, success, time.Since(start))
				}
				if err != nil {
					s.traces = append(s.traces, fmt.Sprintf("repair failed %s: %v", name, err))
				} else {
					s.traces = append(s.traces, fmt.Sprintf("repair succeeded %s", name))
					// reload manifest from store if possible
					if s.manifestStore != nil {
						if mm, found, err := s.manifestStore.Load(name); err == nil && found {
							s.mu.Lock()
							s.manifests[name] = mm
							s.mu.Unlock()
						}
					}
				}
			}
		}()
	}
}

// TriggerRepair: manual trigger (single manifest or all if name empty)
func (s *DistributedStorage) TriggerRepair(ctx context.Context, name string) error {
	if name == "" {
		s.mu.RLock()
		names := make([]string, 0, len(s.manifests))
		for k := range s.manifests {
			names = append(names, k)
		}
		s.mu.RUnlock()
		for _, n := range names {
			if err := s.TriggerRepair(ctx, n); err != nil {
				return err
			}
		}
		return nil
	}
	s.mu.RLock()
	m, ok := s.manifests[name]
	rp := s.repairPlugin
	s.mu.RUnlock()
	if !ok {
		return errors.New("manifest not found")
	}
	if s.policyChecker != nil {
		if err := s.policyChecker("repair", &m, map[string]any{"filename": name}); err != nil {
			return err
		}
	}
	if rp == nil {
		return errors.New("no repair plugin configured")
	}
	return rp.Repair(ctx, &m, s.backends)
}

// -------------------- Plugins --------------------

func (s *DistributedStorage) LoadPlugin(name, path string) error {
	// basic whitelist check
	s.mu.RLock()
	wl := s.pluginWhitelist
	s.mu.RUnlock()
	if wl != nil {
		base := filepath.Base(path)
		if allowed := wl[base]; !allowed {
			return fmt.Errorf("plugin %s not in whitelist", base)
		}
	}
	p, err := plugin.Open(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plugins[name] = p
	s.traces = append(s.traces, fmt.Sprintf("plugin %s loaded", name))
	return nil
}

// -------------------- Manifest helpers --------------------

func (s *DistributedStorage) GetManifest(name string) (FileManifest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.manifests[name]
	return m, ok
}

func (s *DistributedStorage) ListManifests() []FileManifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FileManifest, 0, len(s.manifests))
	for _, m := range s.manifests {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FileName < out[j].FileName })
	return out
}

// Export/Import manifest (provenance)
func (s *DistributedStorage) ExportManifestJSON(name string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.manifests[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return json.MarshalIndent(m, "", "  ")
}

func (s *DistributedStorage) ImportManifestJSON(b []byte) error {
	var m FileManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m.FileName == "" || len(m.Shards) == 0 {
		return errors.New("invalid manifest")
	}
	// verify signature if signer available
	s.mu.RLock()
	signer := s.manifestSigner
	s.mu.RUnlock()
	if signer != nil {
		if err := signer.Verify(&m); err != nil {
			return fmt.Errorf("manifest signature verify failed: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.UpdatedAt = time.Now().UTC()
	if prev, ok := s.manifests[m.FileName]; ok {
		m.Version = prev.Version + 1
		m.CreatedAt = prev.CreatedAt
	}
	s.manifests[m.FileName] = m
	if s.manifestStore != nil {
		if err := s.manifestStore.Save(m); err != nil {
			return err
		}
	}
	return nil
}

// -------------------- Built-in simple placements --------------------

type SimpleReplicationPlacement struct{}

func (p *SimpleReplicationPlacement) PlaceShards(file []byte, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error) {
	if len(backends) == 0 {
		return nil, errors.New("no backends")
	}
	replicas := 1
	if v, ok := opts["replicas"].(int); ok && v > 0 {
		replicas = v
	}
	names := make([]string, 0, len(backends))
	for k := range backends {
		names = append(names, k)
	}
	sort.Strings(names)
	shards := make([]Shard, 0, replicas)
	for i := 0; i < replicas; i++ {
		part := make([]byte, len(file))
		copy(part, file)
		sh := Shard{
			ID:        fmt.Sprintf("rep-%d-%d", time.Now().UnixNano(), i),
			Backend:   names[i%len(names)],
			Data:      part,
			Checksum:  sha256Hex(part),
			Parity:    false,
			Index:     i,
			CreatedAt: time.Now().UTC(),
		}
		shards = append(shards, sh)
	}
	return shards, nil
}

type SimpleXORParityPlacement struct{}

func (p *SimpleXORParityPlacement) PlaceShards(file []byte, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error) {
	if len(backends) == 0 {
		return nil, errors.New("no backends")
	}
	dataShards := 2
	if v, ok := opts["data_shards"].(int); ok && v > 1 {
		dataShards = v
	}
	names := make([]string, 0, len(backends))
	for k := range backends {
		names = append(names, k)
	}
	sort.Strings(names)
	chunkSize := (len(file) + dataShards - 1) / dataShards
	shards := make([]Shard, 0, dataShards+1)
	var parity []byte
	for i := 0; i < dataShards; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(file) {
			end = len(file)
		}
		part := make([]byte, end-start)
		copy(part, file[start:end])
		if parity == nil {
			parity = make([]byte, len(part))
			copy(parity, part)
		} else {
			if len(part) > len(parity) {
				newp := make([]byte, len(part))
				copy(newp, parity)
				parity = newp
			}
			for j := range part {
				parity[j] ^= part[j]
			}
		}
		sh := Shard{
			ID:        fmt.Sprintf("xor-%d-%d", time.Now().UnixNano(), i),
			Backend:   names[i%len(names)],
			Data:      part,
			Checksum:  sha256Hex(part),
			Parity:    false,
			Index:     i,
			CreatedAt: time.Now().UTC(),
		}
		shards = append(shards, sh)
	}
	par := Shard{
		ID:        fmt.Sprintf("xor-parity-%d", time.Now().UnixNano()),
		Backend:   names[len(shards)%len(names)],
		Data:      parity,
		Checksum:  sha256Hex(parity),
		Parity:    true,
		Index:     len(shards),
		CreatedAt: time.Now().UTC(),
	}
	shards = append(shards, par)
	return shards, nil
}

// Implement StreamPlacementPlugin for SimpleReplicationPlacement and SimpleXORParityPlacement

func (p *SimpleReplicationPlacement) PlaceShardsStream(r io.Reader, size int64, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error) {
	tmp, err := os.CreateTemp("", "place-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, r); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(tmp)
	if err != nil {
		return nil, err
	}
	return p.PlaceShards(data, backends, opts)
}

func (p *SimpleXORParityPlacement) PlaceShardsStream(r io.Reader, size int64, backends map[string]StorageBackend, opts map[string]any) ([]Shard, error) {
	tmp, err := os.CreateTemp("", "place-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, r); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(tmp)
	if err != nil {
		return nil, err
	}
	return p.PlaceShards(data, backends, opts)
}

// -------------------- Expose functions --------------------

func (s *DistributedStorage) ExposeFunctions() map[string]any {
	return map[string]any{
		"register_backend":      s.RegisterBackend,
		"upload_stream":         s.UploadStream,
		"upload":                s.Upload,
		"download":              s.Download,
		"trigger_repair":        s.TriggerRepair,
		"load_plugin":           s.LoadPlugin,
		"set_placement_plugin":  s.SetPlacementPlugin,
		"set_repair_plugin":     s.SetRepairPlugin,
		"set_encryptor":         s.SetEncryptor,
		"set_policy_checker":    s.SetPolicyChecker,
		"set_metrics_collector": s.SetMetricsCollector,
		"list_manifests":        s.ListManifests,
		"get_manifest":          s.GetManifest,
		"start_self_healing":    s.StartSelfHealing,
		"stop_self_healing":     s.StopSelfHealing,
		"set_manifest_store":    s.SetManifestStore,
	}
}

// -------------------- Simple implementations for ManifestSigner & OrphanRegistry (optional helpers) --------------------

// HMAC-based manifest signer (key management should be via Vault in production)
type HMACManifestSigner struct {
	Key []byte
}

func NewHMACManifestSigner(key []byte) *HMACManifestSigner { return &HMACManifestSigner{Key: key} }

func (hs *HMACManifestSigner) Sign(m *FileManifest) error {
	// canonicalize by copying and zeroing signature, then marshaling
	copyM := *m
	copyM.Signature = nil
	b, err := json.Marshal(copyM)
	if err != nil {
		return err
	}
	h := hmac.New(sha256.New, hs.Key)
	if _, err := h.Write(b); err != nil {
		return err
	}
	m.Signature = h.Sum(nil)
	return nil
}

func (hs *HMACManifestSigner) Verify(m *FileManifest) error {
	if len(m.Signature) == 0 {
		return errors.New("no signature on manifest")
	}
	copyM := *m
	copyM.Signature = nil
	b, err := json.Marshal(copyM)
	if err != nil {
		return err
	}
	expected := hmac.New(sha256.New, hs.Key)
	if _, err := expected.Write(b); err != nil {
		return err
	}
	if !hmac.Equal(m.Signature, expected.Sum(nil)) {
		return errors.New("manifest signature mismatch")
	}
	return nil
}

// In-memory orphan registry (simple)
type InMemoryOrphanRegistry struct {
	mu      sync.Mutex
	entries map[string]Shard
	timeMap map[string]time.Time
}

func NewInMemoryOrphanRegistry() *InMemoryOrphanRegistry {
	return &InMemoryOrphanRegistry{entries: make(map[string]Shard), timeMap: make(map[string]time.Time)}
}

func (r *InMemoryOrphanRegistry) RegisterOrphan(sh Shard) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[sh.ID] = sh
	r.timeMap[sh.ID] = time.Now().UTC()
	return nil
}

func (r *InMemoryOrphanRegistry) ListOrphans() []Shard {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Shard, 0, len(r.entries))
	for _, v := range r.entries {
		out = append(out, v)
	}
	return out
}

func (r *InMemoryOrphanRegistry) CleanupOlderThan(d time.Duration) []Shard {
	cut := time.Now().UTC().Add(-d)
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := []Shard{}
	for id, t := range r.timeMap {
		if t.Before(cut) {
			removed = append(removed, r.entries[id])
			delete(r.entries, id)
			delete(r.timeMap, id)
		}
	}
	return removed
}

// PersistentOrphanRegistry: lightweight JSON-backed orphan registry stored on disk
type PersistentOrphanRegistry struct {
	mu      sync.Mutex
	entries map[string]Shard
	timeMap map[string]time.Time
	file    string
}

func NewPersistentOrphanRegistry(path string) (*PersistentOrphanRegistry, error) {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	r := &PersistentOrphanRegistry{
		entries: make(map[string]Shard),
		timeMap: make(map[string]time.Time),
		file:    path,
	}
	_ = r.load()
	return r, nil
}

func (r *PersistentOrphanRegistry) RegisterOrphan(sh Shard) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[sh.ID] = sh
	r.timeMap[sh.ID] = time.Now().UTC()
	if err := r.flush(); err != nil {
		// log but do not fail registration
		log.Printf("[PersistentOrphanRegistry] flush error: %v", err)
	}
	return nil
}

func (r *PersistentOrphanRegistry) ListOrphans() []Shard {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Shard, 0, len(r.entries))
	for _, v := range r.entries {
		out = append(out, v)
	}
	return out
}

func (r *PersistentOrphanRegistry) CleanupOlderThan(d time.Duration) []Shard {
	cut := time.Now().UTC().Add(-d)
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := []Shard{}
	for id, t := range r.timeMap {
		if t.Before(cut) {
			removed = append(removed, r.entries[id])
			delete(r.entries, id)
			delete(r.timeMap, id)
		}
	}
	if err := r.flush(); err != nil {
		log.Printf("[PersistentOrphanRegistry] flush error during cleanup: %v", err)
	}
	return removed
}

func (r *PersistentOrphanRegistry) flush() error {
	tmp := r.file + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	data := struct {
		Entries map[string]Shard       `json:"entries"`
		TimeMap map[string]time.Time   `json:"time_map"`
	}{
		Entries: r.entries,
		TimeMap: r.timeMap,
	}
	if err := enc.Encode(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, r.file)
}

func (r *PersistentOrphanRegistry) load() error {
	f, err := os.Open(r.file)
	if err != nil {
		// no file yet
		return nil
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	data := struct {
		Entries map[string]Shard     `json:"entries"`
		TimeMap map[string]time.Time `json:"time_map"`
	}{}
	if err := dec.Decode(&data); err != nil {
		return err
	}
	r.entries = data.Entries
	r.timeMap = data.TimeMap
	return nil
}