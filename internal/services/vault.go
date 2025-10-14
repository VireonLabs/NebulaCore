// internal/services/vault.go
package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultConfig holds options for the Vault client behavior.
type VaultConfig struct {
	Addr           string        // Vault address (overrides NEB_VAULT_ADDR if set)
	Token          string        // Initial token (overrides NEB_VAULT_TOKEN if set)
	Namespace      string        // Optional Vault namespace (Enterprise)
	CacheTTL       time.Duration // TTL for in-memory secret cache (default if per-key TTL not provided)
	RenewThreshold float64       // fraction of TTL when to attempt renew (0.8 = 80%)
	RenewJitter    time.Duration // jitter added/subtracted to renewal schedule
	ReauthFunc     func() (string, error) // optional function to get a new token if renew fails
	Logger         *log.Logger   // optional logger (defaults to std log)
	MaxRetries     int           // retry attempts for network ops
	RetryBaseDelay time.Duration // base backoff delay
}

// VaultClient is a production-ready wrapper around HashiCorp Vault API.
// Features: TTL cache, background token auto-renewal, health check, retries, KVv2 support,
// plus per-key cache TTL and an example AppRole reauth helper.
type VaultClient struct {
	client  *vault.Client
	cfg     VaultConfig
	cacheMu sync.RWMutex
	cache   map[string]cachedSecret
	stopCh  chan struct{}
	wg      sync.WaitGroup
	logger  *log.Logger
}

type cachedSecret struct {
	data      map[string]interface{}
	expiresAt time.Time
}

// NewVaultClient creates a configured VaultClient.
// If cfg fields are empty, env vars NEB_VAULT_ADDR / NEB_VAULT_TOKEN are used.
func NewVaultClient(cfg VaultConfig) (*VaultClient, error) {
	addr := cfg.Addr
	if addr == "" {
		addr = os.Getenv("NEB_VAULT_ADDR")
	}
	token := cfg.Token
	if token == "" {
		token = os.Getenv("NEB_VAULT_TOKEN")
	}
	if addr == "" || token == "" {
		return nil, errors.New("vault addr or token not provided (env NEB_VAULT_ADDR / NEB_VAULT_TOKEN or config)")
	}
	vaultCfg := vault.DefaultConfig()
	if addr != "" {
		vaultCfg.Address = addr
	}
	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// sane defaults
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.RenewThreshold <= 0 || cfg.RenewThreshold > 1 {
		cfg.RenewThreshold = 0.80
	}
	if cfg.RenewJitter == 0 {
		cfg.RenewJitter = 5 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 4
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = 200 * time.Millisecond
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	vc := &VaultClient{
		client: client,
		cfg:    cfg,
		cache:  make(map[string]cachedSecret),
		stopCh: make(chan struct{}),
		logger: logger,
	}

	// start token renewal background worker
	vc.wg.Add(1)
	go vc.tokenAutoRenewalLoop()

	return vc, nil
}

// Close stops background tasks (call before program exit or when no longer needed)
func (v *VaultClient) Close() {
	close(v.stopCh)
	v.wg.Wait()
}

// Health checks Vault system health. Returns nil if healthy and unsealed.
func (v *VaultClient) Health(ctx context.Context) error {
	health, err := v.client.Sys().Health()
	if err != nil {
		return err
	}
	if health == nil {
		return errors.New("vault health: nil response")
	}
	if health.Sealed {
		return errors.New("vault is sealed")
	}
	// optionally check version/policies etc.
	return nil
}

// StoreSecret stores a secret at the provided path. Supports KV v1 and v2 transparently.
// data is the map of key->value.
func (v *VaultClient) StoreSecret(ctx context.Context, path string, data map[string]interface{}) error {
	op := func() error {
		_, err := v.client.Logical().Write(path, data)
		return err
	}
	if err := v.doWithRetry(ctx, op); err != nil {
		return err
	}
	// remove cache entry if exists
	v.cacheMu.Lock()
	delete(v.cache, path)
	v.cacheMu.Unlock()
	return nil
}

// ReadSecret reads a secret from Vault with caching using the default TTL from config.
func (v *VaultClient) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	return v.ReadSecretCachedTTL(ctx, path, 0)
}

// ReadSecretCachedTTL reads a secret and caches it for the provided per-call ttl.
// If ttl == 0 the client's configured CacheTTL is used.
func (v *VaultClient) ReadSecretCachedTTL(ctx context.Context, path string, ttl time.Duration) (map[string]interface{}, error) {
	// check cache first
	v.cacheMu.RLock()
	ce, ok := v.cache[path]
	v.cacheMu.RUnlock()
	if ok && time.Now().Before(ce.expiresAt) {
		v.logger.Printf("[vault] cache hit %s", path)
		return deepCopyMap(ce.data), nil
	}

	var secret *vault.Secret
	op := func() error {
		s, err := v.client.Logical().Read(path)
		if err != nil {
			return err
		}
		secret = s
		return nil
	}
	if err := v.doWithRetry(ctx, op); err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret at path: %s", path)
	}
	out := extractSecretData(secret)

	// determine ttl to use
	useTTL := ttl
	if useTTL <= 0 {
		useTTL = v.cfg.CacheTTL
	}

	// cache
	v.cacheMu.Lock()
	v.cache[path] = cachedSecret{data: deepCopyMap(out), expiresAt: time.Now().Add(useTTL)}
	v.cacheMu.Unlock()
	return deepCopyMap(out), nil
}

// RotateToken forces token renewal or reauthentication.
// If token cannot be renewed, and ReauthFunc is provided it will call it and set the new token.
func (v *VaultClient) RotateToken(ctx context.Context) error {
	v.logger.Println("[vault] RotateToken: attempting RenewSelf")
	lookup, err := v.client.Auth().Token().LookupSelf()
	if err == nil && lookup != nil {
		ttl := getTTLFromSecret(lookup)
		if ttl > 0 {
			increment := int(ttl / 2)
			_, err2 := v.client.Auth().Token().RenewSelf(increment)
			if err2 == nil {
				v.logger.Printf("[vault] RotateToken: renewed token by %d seconds", increment)
				return nil
			}
			v.logger.Printf("[vault] RotateToken: RenewSelf failed: %v", err2)
		}
	}
	// fallback: if ReauthFunc provided, call it
	if v.cfg.ReauthFunc != nil {
		v.logger.Println("[vault] RotateToken: calling ReauthFunc")
		newToken, err3 := v.cfg.ReauthFunc()
		if err3 != nil {
			return fmt.Errorf("rotate token reauth func failed: %w", err3)
		}
		v.client.SetToken(newToken)
		v.logger.Println("[vault] RotateToken: token replaced via ReauthFunc")
		return nil
	}
	return fmt.Errorf("rotate token: renew failed and no reauth method provided")
}

// ---------------- helpers ----------------

// doWithRetry runs operation with retry/backoff on transient errors.
func (v *VaultClient) doWithRetry(ctx context.Context, op func() error) error {
	var lastErr error
	base := v.cfg.RetryBaseDelay
	for attempt := 0; attempt < v.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := op(); err != nil {
			lastErr = err
			v.logger.Printf("[vault] op error attempt=%d err=%v", attempt+1, err)
			sleep := base * time.Duration(1<<attempt)
			time.Sleep(sleep)
			continue
		}
		return nil
	}
	return fmt.Errorf("operation failed after %d attempts: %w", v.cfg.MaxRetries, lastErr)
}

// tokenAutoRenewalLoop runs in background to renew token proactively.
func (v *VaultClient) tokenAutoRenewalLoop() {
	defer v.wg.Done()
	for {
		select {
		case <-v.stopCh:
			return
		default:
		}
		lookup, err := v.client.Auth().Token().LookupSelf()
		if err != nil {
			v.logger.Printf("[vault] token lookup error: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		ttl := getTTLFromSecret(lookup)
		if ttl <= 0 {
			v.logger.Println("[vault] token appears non-renewable; tokenAutoRenewalLoop exiting")
			return
		}
		wait := time.Duration(float64(ttl)*v.cfg.RenewThreshold) * time.Second
		// jitter
		jitter := time.Duration(0)
		if v.cfg.RenewJitter > 0 {
			jitter = time.Duration((time.Now().UnixNano()%int64(v.cfg.RenewJitter))) - (v.cfg.RenewJitter / 2)
		}
		wait = wait + jitter
		if wait < 1*time.Second {
			wait = 1 * time.Second
		}
		v.logger.Printf("[vault] token renew scheduled in %s (ttl=%d)", wait, ttl)
		select {
		case <-time.After(wait):
			v.logger.Println("[vault] attempting token renew (background)")
			_, err := v.client.Auth().Token().RenewSelf(0)
			if err != nil {
				v.logger.Printf("[vault] background RenewSelf failed: %v", err)
				if v.cfg.ReauthFunc != nil {
					v.logger.Println("[vault] background ReauthFunc invoked due to renew failure")
					if nt, e := v.cfg.ReauthFunc(); e == nil {
						v.client.SetToken(nt)
						v.logger.Println("[vault] background ReauthFunc replaced token successfully")
						continue
					} else {
						v.logger.Printf("[vault] background ReauthFunc failed: %v", e)
					}
				}
				time.Sleep(5 * time.Second)
				continue
			}
			v.logger.Println("[vault] background RenewSelf succeeded")
		case <-v.stopCh:
			v.logger.Println("[vault] tokenAutoRenewalLoop stopping")
			return
		}
	}
}

// getTTLFromSecret extracts ttl (seconds) from a token lookup secret.
func getTTLFromSecret(s *vault.Secret) int {
	if s == nil || s.Data == nil {
		return 0
	}
	if v, ok := s.Data["ttl"]; ok {
		switch t := v.(type) {
		case int:
			return t
		case int64:
			return int(t)
		case float64:
			return int(t)
		}
	}
	if v, ok := s.Data["lease_duration"]; ok {
		switch t := v.(type) {
		case int:
			return t
		case int64:
			return int(t)
		case float64:
			return int(t)
		}
	}
	if v, ok := s.Data["expire_time"]; ok {
		if str, ok := v.(string); ok {
			if tm, err := time.Parse(time.RFC3339, str); err == nil {
				dur := int(time.Until(tm).Seconds())
				if dur < 0 {
					return 0
				}
				return dur
			}
		}
	}
	return 0
}

// extractSecretData returns the actual key/value map for KV v1 and v2 compatibility.
func extractSecretData(s *vault.Secret) map[string]interface{} {
	if s == nil || s.Data == nil {
		return nil
	}
	if d, ok := s.Data["data"]; ok {
		if m, ok2 := d.(map[string]interface{}); ok2 {
			return m
		}
	}
	return s.Data
}

// deepCopyMap simple copy to avoid consumer mutating our cache internals.
func deepCopyMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ----------------------
// Helper: AppRole Reauth function generator
// Usage: after creating VaultClient vc, you can set:
// vc.cfg.ReauthFunc = MakeAppRoleReauthFunc(vc.client, "approle", "<roleID>", "<secretID>")
// or pass equivalent ReauthFunc in VaultConfig before creating client (then set client inside func closure).
func MakeAppRoleReauthFunc(client *vault.Client, mountPath, roleID, secretID string) func() (string, error) {
	// mountPath example: "approle" (so login path is "auth/approle/login")
	if mountPath == "" {
		mountPath = "approle"
	}
	return func() (string, error) {
		path := fmt.Sprintf("auth/%s/login", mountPath)
		data := map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		}
		secret, err := client.Logical().Write(path, data)
		if err != nil {
			return "", err
		}
		if secret == nil || secret.Auth == nil {
			return "", fmt.Errorf("approle login returned no auth")
		}
		if secret.Auth.ClientToken == "" {
			return "", fmt.Errorf("approle login returned empty token")
		}
		return secret.Auth.ClientToken, nil
	}
}