package connectors

import (
	"log"
	"math"
	"math/rand"
	"time"
)

type DOHumanHelper struct{}

func NewDOHumanHelper() *DOHumanHelper { return &DOHumanHelper{} }

func (d *DOHumanHelper) Name() string { return "DOHumanHelper" }

func (d *DOHumanHelper) SupportedOperations() []Operation {
	return []Operation{OpDiscover, OpList, OpManage, OpCustom}
}

// Gaussian human-like delay + browser-fingerprint randomizer
func (d *DOHumanHelper) DiscoverServices(req GatewayRequest) (GatewayResponse, error) {
	delay := int(math.Abs(rand.NormFloat64()*75.0+350.0)) // realistic delay
	log.Printf("[DO] Discover services (delay=%dms, browser fingerprint randomized)", delay)
	time.Sleep(time.Duration(delay) * time.Millisecond)
	telemetry := map[string]interface{}{
		"attempt_time": time.Now().Unix(),
		"fingerprint": rand.Int63(),
	}
	return GatewayResponse{Success: true, Data: map[string]interface{}{
		"services": []string{"Droplets", "Spaces", "DBs"},
		"telemetry": telemetry,
	}}, nil
}

// CAPTCHA + MFA/2FA hooks + error injection simulation
func (d *DOHumanHelper) ListResources(req GatewayRequest) (GatewayResponse, error) {
	log.Println("[DO] List resources (CAPTCHA/MFA hooks + error injection simulation)")
	fail := rand.Float64() < 0.12 // 12% simulate error
	meta := map[string]interface{}{"captcha": "solved", "mfa": "ok", "error_injected": fail}
	if fail {
		log.Printf("[DO] Simulating human error, will retry...")
		time.Sleep(time.Duration(rand.Intn(150)+100) * time.Millisecond)
	}
	return GatewayResponse{Success: true, Resources: []ResourceMetadata{
		{ID: "do-droplet-1", Name: "Droplet1", Type: "VM", Meta: meta},
	}}, nil
}

func (d *DOHumanHelper) ManageResource(req GatewayRequest) (GatewayResponse, error) {
	log.Println("[DO] Manage resource (form fill + automation + MFA watcher)")
	mfaFailed := rand.Float64() < 0.08
	hooks := map[string]interface{}{
		"mfa_failure": mfaFailed,
		"error_retry": !mfaFailed,
	}
	if mfaFailed {
		log.Println("[DO] MFA failure detected, sending signal to model.")
	}
	return GatewayResponse{Success: true, Message: "Resource managed with human-like automation", Data: hooks}, nil
}

func (d *DOHumanHelper) CustomOperation(req GatewayRequest) (GatewayResponse, error) {
	log.Println("[DO] Custom operation (simulate human interaction + fingerprint randomizer)")
	return GatewayResponse{Success: true, Message: "Custom human simulation executed", Data: map[string]interface{}{"fingerprint": rand.Int63()}}, nil
}

func (d *DOHumanHelper) PollAsync(req GatewayRequest, asyncID string) (GatewayResponse, error) {
	return GatewayResponse{Success: false, Error: "async polling not implemented"}, nil
}