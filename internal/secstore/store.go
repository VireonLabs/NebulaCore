package secstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type fileHeader struct {
	Version        int    `json:"v"`
	Alg            string `json:"alg"`
	NonceSize      int    `json:"nonce_size"`
	WrappedDEKMeta string `json:"wrapped_dek_meta,omitempty"`
	KEKID          string `json:"kek_id,omitempty"`
}

type fileParts struct {
	header  []byte
	wrapped []byte
	ct      []byte
}

type SimpleEncryptedStore struct {
	mutex     sync.RWMutex
	dir       string
	masterKey []byte
	kms       KMSWrapper
}

func NewSimpleEncryptedStore(dir string, masterKey []byte) (*SimpleEncryptedStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &SimpleEncryptedStore{
		dir:       dir,
		masterKey: masterKey,
	}, nil
}

func (s *SimpleEncryptedStore) SetKMS(kms KMSWrapper) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.kms = kms
}

func splitHeaderAndRest(b []byte) *fileParts {
	chunks := bytes.Split(b, []byte("||"))
	if len(chunks) < 3 {
		return nil
	}
	return &fileParts{
		header:  chunks[0],
		wrapped: chunks[1],
		ct:      chunks[2],
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	tmpName := filename + ".tmp"
	if err := os.WriteFile(tmpName, data, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}

// Get and Put methods would be here in a real implementation
func (s *SimpleEncryptedStore) Put(ctx context.Context, key string, plaintext []byte) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    // 1. Generate DEK
    dek := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, dek); err != nil {
        return err
    }
    defer zero(dek)

    // 2. Wrap DEK
    var wrapped []byte
    var meta string
    var kekID string
    var err error

    if s.kms != nil {
        wrapped, meta, err = s.kms.Wrap(ctx, "default", dek)
        kekID = "kms:default"
    } else {
        if s.masterKey == nil {
            return errors.New("no master key or KMS")
        }
        // Local wrap (simplified)
        block, _ := aes.NewCipher(s.masterKey)
        gcm, _ := cipher.NewGCM(block)
        nonce := make([]byte, gcm.NonceSize())
        io.ReadFull(rand.Reader, nonce)
        wrapped = gcm.Seal(nonce, nonce, dek, nil)
        kekID = "local"
    }
    if err != nil {
        return err
    }

    // 3. Encrypt data with DEK
    block, _ := aes.NewCipher(dek)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    // 4. Build file
    hdr := fileHeader{
        Version:        1,
        Alg:            "AES-GCM",
        NonceSize:      gcm.NonceSize(),
        WrappedDEKMeta: meta,
        KEKID:          kekID,
    }
    hb, _ := json.Marshal(hdr)

    out := bytes.NewBuffer(nil)
    out.Write(hb)
    out.Write([]byte("||"))
    out.Write(wrapped)
    out.Write([]byte("||"))
    out.Write(ciphertext)

    path := filepath.Join(s.dir, key+".enc")
    return atomicWriteFile(path, out.Bytes(), 0600)
}

func (s *SimpleEncryptedStore) Get(ctx context.Context, key string) ([]byte, error) {
    s.mutex.RLock()
    defer s.mutex.RUnlock()

    path := filepath.Join(s.dir, key+".enc")
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    parts := splitHeaderAndRest(b)
    if parts == nil {
        return nil, errors.New("invalid file format")
    }

    var hdr fileHeader
    if err := json.Unmarshal(parts.header, &hdr); err != nil {
        return nil, err
    }

    // Unwrap DEK
    var dek []byte
    if s.kms != nil && strings.HasPrefix(hdr.KEKID, "kms:") {
        dek, err = s.kms.Unwrap(ctx, "default", parts.wrapped)
    } else {
        // Local unwrap (simplified)
        if s.masterKey == nil {
            return nil, errors.New("no master key")
        }
        block, _ := aes.NewCipher(s.masterKey)
        gcm, _ := cipher.NewGCM(block)
        nonce := parts.wrapped[:gcm.NonceSize()]
        cw := parts.wrapped[gcm.NonceSize():]
        dek, err = gcm.Open(nil, nonce, cw, nil)
    }
    if err != nil {
        return nil, err
    }
    defer zero(dek)

    // Decrypt data
    block, _ := aes.NewCipher(dek)
    gcm, _ := cipher.NewGCM(block)
    nonce := parts.ct[:gcm.NonceSize()]
    ct := parts.ct[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, nil)
}
