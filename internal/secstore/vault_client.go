package secstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultClientWrapper with KV v1/v2 awareness and binary-safe operations.
type VaultClientWrapper struct {
	client *vault.Client
	addr   string
	token  string
}

func NewVaultClientWrapper(addr, token string) (*VaultClientWrapper, error) {
	cfg := vault.DefaultConfig()
	if addr != "" {
		cfg.Address = addr
	}
	cli, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if token != "" {
		cli.SetToken(token)
	}
	return &VaultClientWrapper{client: cli, addr: cfg.Address, token: token}, nil
}

// GetRaw supports KV v2 (secret/data/<path>) and returns raw bytes (base64-decoded if necessary).
func (v *VaultClientWrapper) GetRaw(path string) ([]byte, error) {
	if v.client == nil {
		return nil, errors.New("vault not configured")
	}
	// first try direct read (KV v1)
	sec, err := v.client.Logical().Read(path)
	if err == nil && sec != nil && sec.Data != nil {
		if vstr, ok := sec.Data["value"].(string); ok {
			if dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(vstr)); derr == nil {
				return dec, nil
			}
			return []byte(vstr), nil
		}
		b, _ := json.Marshal(sec.Data)
		return b, nil
	}
	// try kv v2 style
	sec2, err2 := v.client.Logical().Read("secret/data/" + path)
	if err2 == nil && sec2 != nil && sec2.Data != nil {
		if d, ok := sec2.Data["data"]; ok {
			if m, ok2 := d.(map[string]interface{}); ok2 {
				if val, ok3 := m["value"]; ok3 {
					if s, ok4 := val.(string); ok4 {
						if dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); derr == nil {
							return dec, nil
						}
						return []byte(s), nil
					}
				}
				b, _ := json.Marshal(m)
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("vault get failed for path %s: %v / %v", path, err, err2)
}

func (v *VaultClientWrapper) PutRaw(path string, data []byte) error {
	if v.client == nil {
		return errors.New("vault not configured")
	}
	val := base64.StdEncoding.EncodeToString(data)
	_, err := v.client.Logical().Write(path, map[string]interface{}{"value": val})
	if err != nil {
		_, err = v.client.Logical().Write("secret/data/"+path, map[string]interface{}{"data": map[string]interface{}{"value": val}})
	}
	return err
}

func (v *VaultClientWrapper) AutoUnseal() error {
	// Delegated to Vault server configuration; no-op here but retry to ensure connectivity.
	if v.client == nil {
		return errors.New("vault not configured")
	}
	// simple connectivity check
	_, err := v.client.Sys().Health()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return nil
}