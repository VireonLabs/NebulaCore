package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Aurionex/NebulaCore/aggregation"
	"github.com/Aurionex/NebulaCore/ai"
	"github.com/Aurionex/NebulaCore/connectors"
	"github.com/Aurionex/NebulaCore/microtasking"
	"github.com/Aurionex/NebulaCore/qos"
	"github.com/Aurionex/NebulaCore/scheduler"
	"github.com/Aurionex/NebulaCore/selfhealing"
	"github.com/Aurionex/NebulaCore/storage"
	"github.com/Aurionex/NebulaCore/telemetry"

	"github.com/Aurionex/NebulaCore/internal/auto_development"
	intsec "github.com/Aurionex/NebulaCore/internal/security"
	"github.com/Aurionex/NebulaCore/internal/billing"
	"github.com/Aurionex/NebulaCore/internal/geo"
	"github.com/Aurionex/NebulaCore/internal/identity"
	"github.com/Aurionex/NebulaCore/internal/marketplace"
	"github.com/Aurionex/NebulaCore/internal/monitoring"
	"github.com/Aurionex/NebulaCore/internal/network"
	"github.com/Aurionex/NebulaCore/internal/policy"
	"github.com/Aurionex/NebulaCore/internal/quantum"
	"github.com/Aurionex/NebulaCore/internal/scaling"
	"github.com/Aurionex/NebulaCore/internal/testing"
)

// Logger interface for pluggable logging
type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

type stdLogger struct{}

func (s *stdLogger) Info(args ...interface{})                  { log.Printf("[INFO] %s", sprint(args...)) }
func (s *stdLogger) Infof(format string, args ...interface{})  { log.Printf("[INFO] "+format, args...) }
func (s *stdLogger) Warn(args ...interface{})                  { log.Printf("[WARN] %s", sprint(args...)) }
func (s *stdLogger) Warnf(format string, args ...interface{})  { log.Printf("[WARN] "+format, args...) }
func (s *stdLogger) Error(args ...interface{})                 { log.Printf("[ERROR] %s", sprint(args...)) }
func (s *stdLogger) Errorf(format string, args ...interface{}) { log.Printf("[ERROR] "+format, args...) }

func sprint(args ...interface{}) string {
	if len(args) == 0 {
		return ""
	}
	return fmtSprint(args...)
}

func fmtSprint(args ...interface{}) string {
	return fmtSprintlnTrim(args...)
}

func fmtSprintlnTrim(args ...interface{}) string {
	s := ""
	for i, a := range args {
		if i > 0 {
			s += " "
		}
		s += toString(a)
	}
	return s
}

func toString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}

var logger Logger = &stdLogger{}

func SetLogger(l Logger) {
	if l != nil {
		logger = l
	}
}

type shutdowner interface {
	Shutdown(ctx context.Context) error
}

type closer interface {
	Close() error
}

type ServiceLister interface {
	ListServices() []string
}

func registerShutdownIfPossible(hooks *[]func(context.Context) error, comp interface{}) {
	if comp == nil {
		return
	}
	if s, ok := comp.(shutdowner); ok {
		*hooks = append(*hooks, func(ctx context.Context) error { return s.Shutdown(ctx) })
		return
	}
	if c, ok := comp.(closer); ok {
		*hooks = append(*hooks, func(ctx context.Context) error { return c.Close() })
		return
	}
}

func initCoreModules() (*aggregation.ResourcePool, *scheduler.AdvancedScheduler, *storage.DistributedStorage, *microtasking.MicroTaskManager, *telemetry.TelemetryManager, *qos.QoSManager, *selfhealing.SelfHealingManager) {
	resourcePool := aggregation.NewResourcePool()
	sched := scheduler.NewAdvancedScheduler(resourcePool)
	storageLayer := storage.NewDistributedStorage()
	mtm := microtasking.NewMicroTaskManager()
	telemetryManager := telemetry.NewTelemetryManager()
	qosManager := qos.NewQoSManager()
	selfHeal := selfhealing.NewSelfHealingManager()
	return resourcePool, sched, storageLayer, mtm, telemetryManager, qosManager, selfHeal
}

func initSmartModules(resourcePool *aggregation.ResourcePool, sched *scheduler.AdvancedScheduler, storageLayer *storage.DistributedStorage) (*auto_development.AutoDevEngine, *intsec.SecurityAdvisorAI, *testing.Sandbox, *monitoring.ServiceMonitor, *geo.LocationManager, *scaling.PredictiveScaler, *identity.IdentityFederation, *marketplace.Marketplace, *policy.SimulatorPolicyEngine, *quantum.QSA, *network.SDNController, *intsec.AttestationManager, *billing.BillingEngine, *policy.DataResidencyEnforcer, []func(context.Context) error) {
	hooks := []func(context.Context) error{}
	autoDev := auto_development.NewAutoDevEngine(resourcePool, sched, storageLayer)
	secAdvisor := intsec.NewSecurityAdvisorAI()
	sandbox := testing.NewSandbox("auto-test")
	sm := monitoring.NewServiceMonitor()
	locationMgr := geo.NewLocationManager()
	scaler := scaling.NewPredictiveScaler(sm)
	idFed := identity.NewIdentityFederation()
	market := marketplace.NewMarketplace()
	simPolicy := policy.NewSimulatorPolicyEngine()
	qsa := quantum.NewQSA()
	sdn := network.NewSDNController()
	attestation := intsec.NewAttestationManager()
	billingEngine := billing.NewBillingEngine()
	dataResidency := policy.NewDataResidencyEnforcer()
	registerShutdownIfPossible(&hooks, autoDev)
	registerShutdownIfPossible(&hooks, secAdvisor)
	registerShutdownIfPossible(&hooks, sandbox)
	registerShutdownIfPossible(&hooks, sm)
	registerShutdownIfPossible(&hooks, locationMgr)
	registerShutdownIfPossible(&hooks, scaler)
	registerShutdownIfPossible(&hooks, idFed)
	registerShutdownIfPossible(&hooks, market)
	registerShutdownIfPossible(&hooks, simPolicy)
	registerShutdownIfPossible(&hooks, qsa)
	registerShutdownIfPossible(&hooks, sdn)
	registerShutdownIfPossible(&hooks, attestation)
	registerShutdownIfPossible(&hooks, billingEngine)
	registerShutdownIfPossible(&hooks, dataResidency)
	return autoDev, secAdvisor, sandbox, sm, locationMgr, scaler, idFed, market, simPolicy, qsa, sdn, attestation, billingEngine, dataResidency, hooks
}

func initConnectorsAndOrchestrator(resourcePool *aggregation.ResourcePool, sched *scheduler.AdvancedScheduler, storageLayer *storage.DistributedStorage, mtm *microtasking.MicroTaskManager, telemetryManager *telemetry.TelemetryManager, qosManager *qos.QoSManager, selfHeal *selfhealing.SelfHealingManager) (*ai.AIOrchestrator, *monitoring.ServiceMonitor, []func(context.Context) error) {
	autoDev, secAdvisor, sandbox, serviceMon, locationMgr, scaler, idFed, market, simPolicy, qsa, sdn, attestation, billingEngine, dataResidency, hooks := initSmartModules(resourcePool, sched, storageLayer)
	linode := connectors.NewLinodeConnector(os.Getenv("LINODE_TOKEN"))
	hetzner := connectors.NewHetznerConnector(os.Getenv("HETZNER_TOKEN"))
	cloudflare, cfErr := connectors.NewCloudflareConnector(os.Getenv("CF_EMAIL"), os.Getenv("CF_KEY"))
	if cfErr != nil {
		logger.Warnf("cloudflare connector init failed: %v", cfErr)
	}
	registerShutdownIfPossible(&hooks, linode)
	registerShutdownIfPossible(&hooks, hetzner)
	registerShutdownIfPossible(&hooks, cloudflare)
	aiOrch := ai.NewAIOrchestrator(resourcePool, sched, storageLayer, mtm, telemetryManager, qosManager, func(cmd map[string]interface{}) bool { return true })
	funcs := aiOrch.ExposeFunctions()
	funcs["auto_dev"] = autoDev
	funcs["security_advisor"] = secAdvisor
	funcs["sandbox"] = sandbox
	funcs["service_monitor"] = serviceMon
	funcs["location_manager"] = locationMgr
	funcs["predictive_scaler"] = scaler
	funcs["identity_federation"] = idFed
	funcs["marketplace"] = market
	funcs["simulator_policy"] = simPolicy
	funcs["quantum_accelerator"] = qsa
	funcs["sdn_controller"] = sdn
	funcs["attestation_manager"] = attestation
	funcs["billing_engine"] = billingEngine
	funcs["data_residency"] = dataResidency
	funcs["self_healing"] = selfHeal
	funcs["linode_connector"] = linode
	funcs["hetzner_connector"] = hetzner
	if cloudflare != nil {
		funcs["cloudflare_connector"] = cloudflare
	}
	return aiOrch, serviceMon, hooks
}

func runSchedulers(ctx context.Context, sm *monitoring.ServiceMonitor, scaler interface{}) context.CancelFunc {
	scalerCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-scalerCtx.Done():
				return
			case <-ticker.C:
				if sm == nil || scaler == nil {
					continue
				}
				if s, ok := scaler.(interface{ ScanAndAdjust(context.Context) error }); ok {
					_ = s.ScanAndAdjust(scalerCtx)
					continue
				}
				if s2, ok := scaler.(interface{ AdjustResources(string) error }); ok {
					if sl, ok := interface{}(sm).(ServiceLister); ok {
						for _, svc := range sl.ListServices() {
							_ = s2.AdjustResources(svc)
						}
						continue
					}
					if us, ok := interface{}(sm).(interface{ Usages() map[string][]monitoring.ServiceUsage }); ok {
						for svc := range us.Usages() {
							_ = s2.AdjustResources(svc)
						}
						continue
					}
				}
			}
		}
	}()
	return cancel
}

func shutdownAll(ctx context.Context, hooks []func(context.Context) error) {
	var wg sync.WaitGroup
	for _, h := range hooks {
		wg.Add(1)
		go func(fn func(context.Context) error) {
			defer wg.Done()
			_ = fn(ctx)
		}(h)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		logger.Warn("shutdown timeout reached")
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	resourcePool, sched, storageLayer, mtm, telemetryManager, qosManager, selfHeal := initCoreModules()
	aiOrch, serviceMon, hooks := initConnectorsAndOrchestrator(resourcePool, sched, storageLayer, mtm, telemetryManager, qosManager, selfHeal)
	_ = aiOrch
	shutdownSchedulers := runSchedulers(ctx, serviceMon, scaling.NewPredictiveScaler(serviceMon))
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	cancel()
	shutdownSchedulers()
	shutdownAll(context.Background(), hooks)
	logger.Info("NebulaCore control-plane stopped")
}
