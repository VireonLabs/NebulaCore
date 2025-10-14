package bootstrap

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"konrotaharai-netizen/internal/security"
)

// TokenValidator validates the AI token (pluggable).
type TokenValidator func(ctx context.Context, token string) bool

// AIController exposes a safe gateway for an AI/model to interact with Coordinator.
// It enforces ACLs, rate-limits and audit.
type AIController struct {
	coord *Coordinator

	mu            sync.Mutex
	allowlist     map[string]bool
	rateLimits    map[string]*tokenBucket
	validateToken TokenValidator
}

type tokenBucket struct {
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
	mu     sync.Mutex
}

func newBucket(rate float64, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

func NewAIController(coord *Coordinator) *AIController {
	c := &AIController{
		coord:      coord,
		allowlist:  map[string]bool{"apply_policy": true, "simulate": true, "request_rekey": true},
		rateLimits: map[string]*tokenBucket{"default": newBucket(0.2, 5)},
	}
	// default validator: simple env/token check; replace with OIDC/SPIFFE in prod
	c.validateToken = func(ctx context.Context, token string) bool {
		// placeholder: compare to env token for local model
		if token == "local-model-token" {
			return true
		}
		// extend: verify JWT via keystore/OIDC provider
		return false
	}
	return c
}

func (a *AIController) checkToken(ctx context.Context, token string) bool {
	if a.validateToken != nil {
		return a.validateToken(ctx, token)
	}
	return false
}

// RequestApplyPolicy attempts to vet and apply a policy (coerces to internal Rule when possible).
func (a *AIController) RequestApplyPolicy(ctx context.Context, policy any, token string) error {
	if !a.checkToken(ctx, token) {
		return errors.New("unauthorized")
	}
	rl, ok := a.rateLimits["default"]
	if !ok || !rl.allow() {
		return errors.New("rate limited")
	}
	if a.coord == nil {
		return errors.New("coord unavailable")
	}
	if a.coord.Firewall == nil {
		return errors.New("firewall unavailable")
	}
	if err := a.coord.auditIfPossible(ctx, "ai.request_apply_policy", map[string]any{"ts": time.Now().UTC()}); err != nil {
		log.Printf("audit warning: %v", err)
	}
	// delegate vetting to Enforcer
	if a.coord.Enforcer != nil {
		if err := a.coord.Enforcer.VetPolicy(policy); err != nil {
			return err
		}
	}
	// attempt to coerce policy to internal Rule and apply
	if m, ok := policy.(map[string]any); ok {
		r := &security.Rule{}
		if idv, ok := m["id"].(string); ok {
			r.ID = idv
		}
		if sip, ok := m["src_ip"].(string); ok {
			r.SrcIP = sip
		}
		if act, ok := m["action"].(string); ok {
			r.Action = act
		}
		if ttlf, ok := m["ttl_seconds"].(float64); ok {
			r.TTL = time.Duration(int64(ttlf)) * time.Second
		}
		if err := a.coord.Firewall.AddPolicy(r); err != nil {
			return err
		}
		return nil
	}
	// if not coercible, treat as vetted and accepted (no-op)
	return nil
}

// SystemStatus returns minimal system overview for model.
func (a *AIController) SystemStatus(ctx context.Context) map[string]any {
	status := map[string]any{"time": time.Now().UTC()}
	if a.coord != nil {
		status["components"] = len(a.coord.comps)
		status["health"] = a.coord.SystemHealth()
	}
	return status
}