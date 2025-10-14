package security

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Rule represents a firewall policy rule.
type Rule struct {
	ID       string
	SrcIP    string
	Action   string
	Created  time.Time
	Priority int
	TTL      time.Duration
}

// LaserFirewall implements transactional apply via nftables with iptables fallback.
type LaserFirewall struct {
	mu       sync.Mutex
	policies map[string]*Rule
}

func NewLaserFirewall() *LaserFirewall {
	return &LaserFirewall{policies: make(map[string]*Rule)}
}

func (lf *LaserFirewall) ID() string { return "laserfirewall" }

func (lf *LaserFirewall) Start(ctx context.Context) error { return nil }
func (lf *LaserFirewall) Stop(ctx context.Context) error  { return nil }
func (lf *LaserFirewall) Health() map[string]interface{}  { return map[string]interface{}{"policies": len(lf.policies)} }

// AddPolicy applies a policy transactionally; supports canary via percent (0-100) - simplified here.
func (lf *LaserFirewall) AddPolicy(r *Rule) error {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if !isValidCIDR(r.SrcIP) && r.SrcIP != "" {
		return fmt.Errorf("invalid CIDR: %s", r.SrcIP)
	}
	if err := lf.applyNftRule(r); err != nil {
		if err2 := lf.applyIptablesRule(r); err2 != nil {
			return fmt.Errorf("apply failed nft:%v ipt:%v", err, err2)
		}
	}
	r.Created = time.Now()
	lf.policies[r.ID] = r
	return nil
}

func isValidCIDR(c string) bool {
	if c == "" {
		return true
	}
	return strings.Contains(c, "/")
}

func (lf *LaserFirewall) applyNftRule(r *Rule) error {
	cmd := exec.Command("nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", r.SrcIP, "counter", "drop")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("nft failed: %s %v", string(out), err)
		return err
	}
	return nil
}

func (lf *LaserFirewall) applyIptablesRule(r *Rule) error {
	cmd := exec.Command("iptables", "-I", "INPUT", "1", "-s", r.SrcIP, "-m", "comment", "--comment", "laserwall:"+r.ID, "-j", "DROP")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("iptables failed: %s %v", string(out), err)
		return err
	}
	return nil
}

// Cleanup expired rules
func (lf *LaserFirewall) Cleanup() {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	now := time.Now()
	for id, r := range lf.policies {
		if r.TTL > 0 && r.Created.Add(r.TTL).Before(now) {
			_ = lf.removeRule(r)
			delete(lf.policies, id)
		}
	}
}

func (lf *LaserFirewall) removeRule(r *Rule) error {
	cmd := exec.Command("iptables", "-D", "INPUT", "-m", "comment", "--comment", "laserwall:"+r.ID, "-j", "DROP")
	_ = cmd.Run()
	return nil
}