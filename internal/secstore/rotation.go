package secstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RewrapAllFiles iterates over all .enc files and rewraps the DEKs using current KMS provider.
// Usage: call this function after you have set s.kms to a new provider (or after key rotation in vault).
func (s *SimpleEncryptedStore) RewrapAllFiles(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// must have KMS available
	if s.kms == nil {
		return fmt.Errorf("no KMS configured for rewrap")
	}
	err := filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".enc" {
			return nil
		}
		// read file
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parts := splitHeaderAndRest(b)
		if parts == nil {
			return fmt.Errorf("invalid format %s", path)
		}
		var hdr fileHeader
		if err := json.Unmarshal(parts.header, &hdr); err != nil {
			return err
		}
		// unwrap with existing method (local or existing KMS)
		dek, err := s.unwrapForRotation(ctx, &hdr, parts.wrapped)
		if err != nil {
			return fmt.Errorf("unwrap failed %s: %v", path, err)
		}
		// wrap with current s.kms
		wrapped, meta, err := s.kms.Wrap(ctx, "default", dek)
		if err != nil {
			zero(dek)
			return err
		}
		// build new header
		newHdr := fileHeader{Version: hdr.Version, Alg: hdr.Alg, NonceSize: hdr.NonceSize, WrappedDEKMeta: meta, KEKID: "kms:default"}
		hb, _ := json.Marshal(newHdr)
		out := bytes.NewBuffer(nil)
		out.Write(hb)
		out.Write([]byte("||"))
		out.Write(wrapped)
		out.Write([]byte("||"))
		out.Write(parts.ct)
		if err := atomicWriteFile(path, out.Bytes(), 0o600); err != nil {
			zero(dek)
			return err
		}
		zero(dek)
		return nil
	})
	return err
}

// helper to unwrap using existing local code paths (extracted to call from rotation)
func (s *SimpleEncryptedStore) unwrapForRotation(ctx context.Context, hdr *fileHeader, wrapped []byte) ([]byte, error) {
	// if hdr indicates wrapped by kms and current s.kms present, use it
	if s.kms != nil && hdr != nil && strings.HasPrefix(hdr.KEKID, "kms:") {
		dk, err := s.kms.Unwrap(ctx, "default", wrapped)
		if err == nil {
			return dk, nil
		}
		// fallthrough to local unwrap attempt only if masterKey present (legacy)
	}
	// local unwrap
	if s.masterKey == nil {
		return nil, fmt.Errorf("no local masterKey to unwrap")
	}
	kblk, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	kaead, err := cipher.NewGCM(kblk)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < kaead.NonceSize() {
		return nil, fmt.Errorf("wrapped dek too short")
	}
	knonce := wrapped[:kaead.NonceSize()]
	cw := wrapped[kaead.NonceSize():]
	dk, err := kaead.Open(nil, knonce, cw, nil)
	if err != nil {
		return nil, err
	}
	return dk, nil
}