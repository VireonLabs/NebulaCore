package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// GetAuditHMACKeyFromVault fetches the audit HMAC key from Vault KV (or other secret path).
// Expects VAULT_ADDR + VAULT_TOKEN env, secretPath like "secret/data/laserwall/audit".
func GetAuditHMACKeyFromVault(ctx context.Context, secretPath string) ([]byte, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, fmt.Errorf("vault creds not set")
	}
	url := fmt.Sprintf("%s/v1/%s", addr, secretPath)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("X-Vault-Token", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault get secret: %s", string(b))
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// KV v2 stores value under "data"."data"
	if inner, ok := out.Data["data"]; ok {
		if m, ok2 := inner.(map[string]any); ok2 {
			if v, ok3 := m["hmac_key"].(string); ok3 {
				return []byte(v), nil
			}
		}
	}
	// fallback: top-level key
	if v, ok := out.Data["hmac_key"].(string); ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("hmac_key not found in vault secret")
}