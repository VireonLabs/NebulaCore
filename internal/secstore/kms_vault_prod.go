package secstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// VaultClient provides robust methods for Vault Transit usage with AppRole fallback.
type VaultClient struct {
	httpClient  *http.Client
	baseURL     string // e.g. https://vault:8200
	transitPath string // e.g. "transit"
	token       string
}

// NewVaultClientFromEnv reads VAULT_ADDR + VAULT_TOKEN or VAULT_APPROLE_ID/SECRET_FILE
func NewVaultClientFromEnv() (*VaultClient, error) {
	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	if addr == "" {
		return nil, fmt.Errorf("VAULT_ADDR not set")
	}
	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	// Optionally support AppRole (role_id & secret_id file)
	if token == "" {
		roleID := strings.TrimSpace(os.Getenv("VAULT_APPROLE_ID"))
		secretPath := strings.TrimSpace(os.Getenv("VAULT_APPROLE_SECRET_FILE"))
		if roleID != "" && secretPath != "" {
			secretB, err := os.ReadFile(secretPath)
			if err != nil {
				return nil, fmt.Errorf("read secret file: %v", err)
			}
			secret := strings.TrimSpace(string(secretB))
			// login
			loginURL := addr + "/v1/auth/approle/login"
			body := map[string]string{"role_id": roleID, "secret_id": secret}
			bb, _ := json.Marshal(body)
			resp, err := http.Post(loginURL, "application/json", bytes.NewReader(bb))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				b, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("approle login failed: %s", string(b))
			}
			var out struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				return nil, fmt.Errorf("approle decode failed: %v", err)
			}
			token = out.Auth.ClientToken
		}
	}
	if token == "" {
		return nil, fmt.Errorf("no VAULT_TOKEN and no APPROLE provided")
	}
	transitPath := strings.Trim(os.Getenv("VAULT_TRANSIT_PATH"), "/")
	return &VaultClient{
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		baseURL:     addr,
		transitPath: transitPath,
		token:       token,
	}, nil
}

func (v *VaultClient) do(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.baseURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

// VaultTransitKMS is production-ready Vault wrapper implementing KMSWrapper
type VaultTransitKMS struct {
	client  *VaultClient
	keyName string
}

// NewVaultTransitKMSFromEnv constructs a VaultTransitKMS using environment configuration.
// keyName is the transit key to use (e.g., "laserwall-transit").
func NewVaultTransitKMSFromEnv(keyName string) (*VaultTransitKMS, error) {
	cli, err := NewVaultClientFromEnv()
	if err != nil {
		return nil, err
	}
	// default transit path
	if cli.transitPath == "" {
		cli.transitPath = "transit"
	}
	if keyName == "" {
		return nil, fmt.Errorf("keyName required")
	}
	return &VaultTransitKMS{client: cli, keyName: keyName}, nil
}

// Wrap implements KMSWrapper.Wrap using Vault transit/encrypt
func (v *VaultTransitKMS) Wrap(ctx context.Context, kekID string, dek []byte) ([]byte, string, error) {
	payload := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}
	path := fmt.Sprintf("/v1/%s/encrypt/%s", v.client.transitPath, v.keyName)
	b, status, err := v.client.do(ctx, "POST", path, payload)
	if err != nil {
		return nil, "", err
	}
	if status >= 400 {
		return nil, "", fmt.Errorf("vault encrypt error: %s", string(b))
	}
	var out struct {
		Data struct {
			Ciphertext  string `json:"ciphertext"`
			CreatedTime string `json:"created_time"`
			KeyVersion  int    `json:"key_version,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, "", err
	}
	meta := fmt.Sprintf("vault:%s:%s", v.keyName, out.Data.CreatedTime)
	if out.Data.KeyVersion != 0 {
		meta = fmt.Sprintf("%s:v%d", meta, out.Data.KeyVersion)
	}
	return []byte(out.Data.Ciphertext), meta, nil
}

// Unwrap implements KMSWrapper.Unwrap using Vault transit/decrypt
func (v *VaultTransitKMS) Unwrap(ctx context.Context, kekID string, wrapped []byte) ([]byte, error) {
	payload := map[string]string{"ciphertext": string(wrapped)}
	path := fmt.Sprintf("/v1/%s/decrypt/%s", v.client.transitPath, v.keyName)
	b, status, err := v.client.do(ctx, "POST", path, payload)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("vault decrypt error: %s", string(b))
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// Sign uses transit/sign/<key> to sign data (input is raw bytes)
func (v *VaultTransitKMS) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	payload := map[string]string{"input": base64.StdEncoding.EncodeToString(data)}
	path := fmt.Sprintf("/v1/%s/sign/%s", v.client.transitPath, v.keyName)
	b, status, err := v.client.do(ctx, "POST", path, payload)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("vault sign error: %s", string(b))
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return []byte(out.Data.Signature), nil
}

// Verify uses transit/verify/<key> to check signature validity
func (v *VaultTransitKMS) Verify(ctx context.Context, keyID string, data []byte, sig []byte) (bool, error) {
	payload := map[string]string{
		"input":     base64.StdEncoding.EncodeToString(data),
		"signature": string(sig),
	}
	path := fmt.Sprintf("/v1/%s/verify/%s", v.client.transitPath, v.keyName)
	b, status, err := v.client.do(ctx, "POST", path, payload)
	if err != nil {
		return false, err
	}
	if status >= 400 {
		return false, fmt.Errorf("vault verify error: %s", string(b))
	}
	var out struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return false, err
	}
	return out.Data.Valid, nil
}

func (v *VaultTransitKMS) Info() map[string]string {
	return map[string]string{"type": "vault", "key": v.keyName}
}