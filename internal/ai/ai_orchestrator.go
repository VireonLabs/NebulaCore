package ai

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

// Core subsystems
"github.com/Aurionex/NebulaCore/internal/aggregation"
"github.com/Aurionex/NebulaCore/internal/scheduler"
"github.com/Aurionex/NebulaCore/internal/storage"
"github.com/Aurionex/NebulaCore/internal/microtasking"
"github.com/Aurionex/NebulaCore/internal/telemetry"
"github.com/Aurionex/NebulaCore/internal/security"
"github.com/Aurionex/NebulaCore/internal/communication"
"github.com/Aurionex/NebulaCore/internal/training"
"github.com/Aurionex/NebulaCore/internal/qos"
"github.com/Aurionex/NebulaCore/internal/selfhealing"

// Advanced/Optional Modules (lazy-init in DirectMode)
"github.com/Aurionex/NebulaCore/internal/auto_development"
"github.com/Aurionex/NebulaCore/internal/monitoring"
"github.com/Aurionex/NebulaCore/internal/geo"
"github.com/Aurionex/NebulaCore/internal/scaling"
"github.com/Aurionex/NebulaCore/internal/identity"
"github.com/Aurionex/NebulaCore/internal/marketplace"
"github.com/Aurionex/NebulaCore/internal/policy"
"github.com/Aurionex/NebulaCore/internal/quantum"
"github.com/Aurionex/NebulaCore/internal/network"
"github.com/Aurionex/NebulaCore/internal/billing"

// Connectors system
"github.com/Aurionex/NebulaCore/connectors"
)

// -----------------------------------------------------------------------------
// Types / Enums
// -----------------------------------------------------------------------------

type CommandType string

const (
	CmdResourceManagement CommandType = "resource_management"
	CmdFileAPI            CommandType = "file_api"
	CmdAppAPI             CommandType = "app_api"
	CmdWebAPI             CommandType = "web_api"
	CmdCustom             CommandType = "custom"
)

type AIControlMode int

const (
	ProxyMode AIControlMode = iota
	DirectMode
)

func (m AIControlMode) String() string {
	switch m {
	case ProxyMode:
		return "ProxyMode"
	case DirectMode:
		return "DirectMode"
	default:
		return "Unknown"
	}
}

// -----------------------------------------------------------------------------
// Project Identity Management (Address + Key)
// -----------------------------------------------------------------------------

type ProjectIdentity struct {
	Address   string
	Key       string
	CreatedAt time.Time
	ExpiresAt time.Time // zero => no expiry
}

// -----------------------------------------------------------------------------
// Module interface for runtime discovery
// -----------------------------------------------------------------------------

// Module is a lightweight interface that modules can implement to expose a set
// of callable functions to the orchestrator.
type Module interface {
	ExposeFunctions() map[string]any
}

// -----------------------------------------------------------------------------
// Orchestrator struct
// -----------------------------------------------------------------------------
type AIOrchestrator struct {
	// Core subsystems (typed for direct API calls in code)
	ResourcePool     *aggregation.ResourcePool
	Scheduler        *scheduler.AdvancedScheduler
	StorageLayer     *storage.DistributedStorage
	MicrotaskManager *microtasking.MicroTaskManager
	TelemetryManager *telemetry.TelemetryManager
	QoSManager       *qos.QoSManager

	// Advanced/Optional Modules (typed convenience)
	AutoDev        *auto_development.AutoDevEngine
	Monitor        *monitoring.ServiceMonitor
	GeoManager     *geo.LocationManager
	Predictive     *scaling.PredictiveScaler
	IdentityFed    *identity.IdentityFederation
	Marketplace    *marketplace.Marketplace
	PolicySim      *policy.SimulatorPolicyEngine
	QuantumAccel   *quantum.QSA
	SDNController  *network.SDNController
	Attestation    *security.IsolationManager
	BillingEngine  *billing.BillingEngine
	DataResidency  *policy.DataResidencyEnforcer

	// connectors registry
	connectorManager *connectors.ConnectorManager

	// control
	Mode            AIControlMode
	mu              sync.Mutex
	approvalChecker func(cmd map[string]interface{}) bool

	// Identity management for agents/projects
	projectIdentities       map[string]ProjectIdentity // projectID => identity
	externalIdentityEndpoint string
	identityTTL              time.Duration // default TTL for identities

	// registry: functions exported by discovered modules
	registry   map[string]map[string]any // moduleName -> (funcName -> callable)
	registryMu sync.RWMutex

	// background control for identity reaper
	reaperStop chan struct{}

	// Integration hook: central security system interface (injected)
	// This is a lightweight reference to the system security control plane
	// (e.g., superguard.SuperGuard or a security.Controller facade).
	// It's intentionally optional (may be nil in unit tests / dev).
	SecuritySystem *security.CentralSecurityInterface
}

// -----------------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------------
func NewAIOrchestrator(
	rp *aggregation.ResourcePool,
	sched *scheduler.AdvancedScheduler,
	sl *storage.DistributedStorage,
	mtm *microtasking.MicroTaskManager,
	tm *telemetry.TelemetryManager,
	qm *qos.QoSManager,
	approvalChecker func(map[string]interface{}) bool,
	secSys *security.CentralSecurityInterface, // NEW: inject central security system
) *AIOrchestrator {
	ai := &AIOrchestrator{
		ResourcePool:     rp,
		Scheduler:        sched,
		StorageLayer:     sl,
		MicrotaskManager: mtm,
		TelemetryManager: tm,
		QoSManager:       qm,
		Mode:             ProxyMode,
		approvalChecker:  approvalChecker,
		projectIdentities: make(map[string]ProjectIdentity),
		identityTTL:       24 * time.Hour,
		registry:          make(map[string]map[string]any),
		reaperStop:        make(chan struct{}),
		SecuritySystem:    secSys,
	}
	// Auto-bind modules present in fields (Module interface or ExposeFunctions method)
	ai.autoBindFields()

	// Register commonly-present modules if they implement ExposeFunctions
	ai.registerIfModule("resource_pool", rp)
	ai.registerIfModule("scheduler", sched)
	ai.registerIfModule("storage", sl)
	ai.registerIfModule("microtasking", mtm)
	ai.registerIfModule("telemetry", tm)
	ai.registerIfModule("qos", qm)
	ai.registerIfModule("selfhealing", ai.Attestation)
	ai.registerIfModule("communication", nil) // no-op here; allow RegisterModule externally

	// start identity reaper (cleanup expired identities periodically)
	ai.startIdentityReaper(1 * time.Hour)
	return ai
}

// -----------------------------------------------------------------------------
// Module registration utilities
// -----------------------------------------------------------------------------

// RegisterModule allows manual registration of an arbitrary module (module must implement ExposeFunctions()
// either via static type assertion or via a method named ExposeFunctions() that returns map[string]any).
func (ai *AIOrchestrator) RegisterModule(name string, mod any) error {
	if mod == nil {
		return errors.New("mod is nil")
	}
	// direct interface assertion
	if m, ok := mod.(Module); ok {
		funcs := m.ExposeFunctions()
		ai.registryMu.Lock()
		ai.registry[name] = funcs
		ai.registryMu.Unlock()
		if ai.TelemetryManager != nil {
			ai.TelemetryManager.Record(telemetry.MetricCustom, 1.0, map[string]string{"module": name, "event": "registered_manual"})
		}
		return nil
	}
	// try to call ExposeFunctions via reflection: method with zero args returning map[string]any
	v := reflect.ValueOf(mod)
	if !v.IsValid() {
		return errors.New("invalid module")
	}
	method := v.MethodByName("ExposeFunctions")
	if method.IsValid() && method.Type().NumIn() == 0 && method.Type().NumOut() == 1 {
		out := method.Call(nil)
		if len(out) == 1 {
			if fm, ok := out[0].Interface().(map[string]any); ok {
				ai.registryMu.Lock()
				ai.registry[name] = fm
				ai.registryMu.Unlock()
				if ai.TelemetryManager != nil {
					ai.TelemetryManager.Record(telemetry.MetricCustom, 1.0, map[string]string{"module": name, "event": "registered_manual_reflect"})
				}
				return nil
			}
		}
	}
	return errors.New("module does not implement ExposeFunctions")
}

// registerIfModule registers mod if it implements Module or has ExposeFunctions method (reflection).
func (ai *AIOrchestrator) registerIfModule(name string, mod any) {
	if mod == nil {
		return
	}
	if err := ai.RegisterModule(name, mod); err == nil {
		// registered
		return
	}
}

// autoBindFields inspects AIOrchestrator fields and registers any that implement ExposeFunctions (Module)
func (ai *AIOrchestrator) autoBindFields() {
	val := reflect.ValueOf(ai).Elem()
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		f := val.Field(i)
		if !f.IsValid() || f.IsNil() {
			continue
		}
		if f.CanInterface() {
			mi := f.Interface()
			// try interface
			if m, ok := mi.(Module); ok {
				name := typ.Field(i).Name
				ai.registryMu.Lock()
				ai.registry[name] = m.ExposeFunctions()
				ai.registryMu.Unlock()
				continue
			}
			// try reflective ExposeFunctions
			v := reflect.ValueOf(mi)
			method := v.MethodByName("ExposeFunctions")
			if method.IsValid() && method.Type().NumIn() == 0 && method.Type().NumOut() == 1 {
				out := method.Call(nil)
				if len(out) == 1 {
					if fm, ok := out[0].Interface().(map[string]any); ok {
						name := typ.Field(i).Name
						ai.registryMu.Lock()
						ai.registry[name] = fm
						ai.registryMu.Unlock()
						continue
					}
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Identity management (Generate / Get / Expire + reaper)
// -----------------------------------------------------------------------------

func (ai *AIOrchestrator) SetExternalIdentityEndpoint(endpoint string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.externalIdentityEndpoint = endpoint
}

func (ai *AIOrchestrator) SetIdentityTTL(ttl time.Duration) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.identityTTL = ttl
}

func (ai *AIOrchestrator) GenerateProjectIdentity(projectID string) ProjectIdentity {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	var lastErr error

	// Try external endpoint first
	if ai.externalIdentityEndpoint != "" {
		type respT struct{ Address, Key string }
		resp, err := http.Get(fmt.Sprintf("%s?project=%s", ai.externalIdentityEndpoint, projectID))
		if err == nil {
			defer resp.Body.Close()
			var body respT
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				lastErr = fmt.Errorf("decode error: %v", err)
				log.Printf("AIOrchestrator: failed to decode identity from external endpoint: %v", err)
			} else if body.Address != "" && body.Key != "" {
				identity := ProjectIdentity{
					Address:   body.Address,
					Key:       body.Key,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(ai.identityTTL),
				}
				ai.projectIdentities[projectID] = identity
				return identity
			} else {
				lastErr = errors.New("empty address or key from external endpoint")
				log.Printf("AIOrchestrator: external endpoint returned empty address/key")
			}
		} else {
			lastErr = err
			log.Printf("AIOrchestrator: failed to fetch identity from external endpoint: %v", err)
		}
	}

	// Fallback to local generation
	if lastErr != nil {
		log.Printf("AIOrchestrator: fallback to local identity generation due to error: %v", lastErr)
	}
	addr := fmt.Sprintf("http://%s.%s", projectID, "nebulacore.local")
	key := generateSecureKey(48)
	identity := ProjectIdentity{
		Address:   addr,
		Key:       key,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ai.identityTTL),
	}
	ai.projectIdentities[projectID] = identity
	return identity
}

func (ai *AIOrchestrator) GetProjectIdentity(projectID string) ProjectIdentity {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	id, ok := ai.projectIdentities[projectID]
	if ok && (id.ExpiresAt.IsZero() || time.Now().Before(id.ExpiresAt)) {
		return id
	}
	return ai.GenerateProjectIdentity(projectID)
}

// ExpireProjectIdentity removes identity (exposed to model)
func (ai *AIOrchestrator) ExpireProjectIdentity(projectID string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	delete(ai.projectIdentities, projectID)
	log.Printf("AIOrchestrator: expired identity for project %s", projectID)
}

// startIdentityReaper periodically removes expired identities.
func (ai *AIOrchestrator) startIdentityReaper(interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				now := time.Now()
				ai.mu.Lock()
				for k, v := range ai.projectIdentities {
					if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
						delete(ai.projectIdentities, k)
					}
				}
				ai.mu.Unlock()
			case <-ai.reaperStop:
				return
			}
		}
	}()
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
func generateSecureKey(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("AIOrchestrator: secure key generation failed: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// -----------------------------------------------------------------------------
// Top-level Executor API & Handlers (adapters for signatures)
// -----------------------------------------------------------------------------

func (ai *AIOrchestrator) ExecutePlan(plan string) error {
	ai.mu.Lock()
	mode := ai.Mode
	approval := ai.approvalChecker
	ai.mu.Unlock()

	var cmd map[string]interface{}
	if err := json.Unmarshal([]byte(plan), &cmd); err != nil {
		log.Printf("AIOrchestrator: invalid plan JSON: %v", err)
		return err
	}

	if mode == ProxyMode {
		if approval != nil {
			if !approval(cmd) {
				log.Printf("AIOrchestrator: plan rejected by approvalChecker")
				return nil
			}
		} else {
			log.Printf("AIOrchestrator: proxy-mode and no approvalChecker provided -> rejecting plan")
			return nil
		}
	}

	var cType CommandType
	if t, ok := cmd["type"].(string); ok {
		cType = CommandType(t)
	} else {
		cType = CmdCustom
	}

	switch cType {
	case CmdResourceManagement:
		return ai.handleResourceCommand(cmd)
	case CmdFileAPI:
		return ai.handleFileAPI(cmd)
	case CmdAppAPI:
		return ai.handleAppAPI(cmd)
	case CmdWebAPI:
		return ai.handleWebAPI(cmd)
	case CmdCustom:
		fallthrough
	default:
		log.Printf("AIOrchestrator: executing custom command: %v", cmd)
		return ai.handleCustom(cmd)
	}
}

func (ai *AIOrchestrator) HandleAIRequest(request string) error {
	return ai.ExecutePlan(request)
}

// SecureCall is a thin integration helper that delegates a named secure action
// to the injected central security system (if present). This provides a
// canonical, audited entrypoint for models to request security-sensitive actions.
//
// If no SecuritySystem was injected, SecureCall returns an error.
func (ai *AIOrchestrator) SecureCall(action string, params map[string]interface{}) error {
	if ai.SecuritySystem == nil {
		return fmt.Errorf("security system not configured")
	}
	// ExecuteSecureAction is expected to be part of the CentralSecurityInterface
	// and to perform its own authorization, auditing and possibly multi-op approval.
	return ai.SecuritySystem.ExecuteSecureAction(action, params)
}

// Handlers with lightweight adapters to match underlying module signatures.
func (ai *AIOrchestrator) handleResourceCommand(cmd map[string]interface{}) error {
	action := mustString(cmd["action"])
	switch action {
	case "add_node":
		// Build aggregation.ResourceNode (adapt from older ResourceVirtualNode idea)
		node := &aggregation.ResourceNode{
			ID:       mustString(cmd["node_id"]),
			Region:   mustString(cmd["region"]),
			Labels:   map[string]string{},
			Meta:     map[string]any{},
			Resources: map[aggregation.ResourceType]float64{
				aggregation.ResourceCPU: float64(mustInt(cmd["cpu"])),
				aggregation.ResourceGPU: float64(mustInt(cmd["gpu"])),
				aggregation.ResourceRAM: float64(mustInt(cmd["memory"])),
			},
			Status:   aggregation.NODE_ONLINE,
			LastSeen: time.Now(),
		}
		if ai.ResourcePool != nil {
			ai.ResourcePool.AddNode(node)
			log.Printf("AIOrchestrator: added node %s", node.ID)
			return nil
		}
		return errors.New("ResourcePool not initialized")
	case "schedule_job":
		task := &scheduler.Task{
			ID:         mustString(cmd["job_id"]),
			Type:       mustString(cmd["job_type"]),
			Payload:    mustMap(cmd["payload"]),
			Priority:   mustInt(cmd["priority"]),
			Deadline:   time.Time{},
			Region:     mustString(cmd["region"]),
			Status:     "pending",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			Owner:      mustString(cmd["owner"]),
		}
		if ai.Scheduler != nil {
			ai.Scheduler.AddTask(task)
			if err := ai.Scheduler.Schedule(nil); err != nil {
				// Schedule returns map in AdvancedScheduler; here we ignore error (method doesn't return error in our AdvancedScheduler)
			}
			log.Printf("AIOrchestrator: scheduled task %s", task.ID)
			return nil
		}
		return errors.New("Scheduler not initialized")
	case "partition_job":
		// adapt to microtasking.SliceTask(rootID string, payload map[string]any, numSlices int)
		taskID := mustString(cmd["job_id"])
		payload := mustMap(cmd["payload"])
		numSlices := mustInt(cmd["num_slices"])
		if ai.MicrotaskManager != nil {
			if _, err := ai.MicrotaskManager.SliceTask(taskID, payload, numSlices); err != nil {
				log.Printf("AIOrchestrator: SliceTask error: %v", err)
				return err
			}
			log.Printf("AIOrchestrator: partitioned task %s into %d microtasks", taskID, numSlices)
			return nil
		}
		return errors.New("MicrotaskManager not initialized")
	default:
		log.Printf("AIOrchestrator: unknown resource action: %s", action)
	}
	return nil
}

func (ai *AIOrchestrator) handleFileAPI(cmd map[string]interface{}) error {
	action := mustString(cmd["action"])
	switch action {
	case "upload_file":
		name := mustString(cmd["file_name"])
		dataStr := mustString(cmd["data"])
		if ai.StorageLayer != nil {
			// Storage.Upload(ctx, name, data []byte, opts map[string]any)
			if err := ai.StorageLayer.Upload(context.Background(), name, []byte(dataStr), nil); err != nil {
				log.Printf("AIOrchestrator: upload error: %v", err)
				return err
			}
			log.Printf("AIOrchestrator: uploaded file %s", name)
			return nil
		}
		return errors.New("StorageLayer not initialized")
	case "download_file":
		name := mustString(cmd["file_name"])
		if ai.StorageLayer != nil {
			_, err := ai.StorageLayer.Download(context.Background(), name)
			if err != nil {
				log.Printf("AIOrchestrator: download error: %v", err)
				return err
			}
			log.Printf("AIOrchestrator: downloaded file %s", name)
			return nil
		}
		return errors.New("StorageLayer not initialized")
	default:
		log.Printf("AIOrchestrator: unknown file action: %s", action)
		return errors.New("unknown file action")
	}
}

func (ai *AIOrchestrator) handleAppAPI(cmd map[string]interface{}) error {
	action := mustString(cmd["action"])
	switch action {
	case "start_app":
		app := mustString(cmd["app_name"])
		log.Printf("AIOrchestrator: start app %s", app)
		return nil
	case "stop_app":
		app := mustString(cmd["app_name"])
		log.Printf("AIOrchestrator: stop app %s", app)
		return nil
	default:
		log.Printf("AIOrchestrator: unknown app action: %s", action)
		return errors.New("unknown app action")
	}
}

func (ai *AIOrchestrator) handleWebAPI(cmd map[string]interface{}) error {
	action := mustString(cmd["action"])
	switch action {
	case "fetch_url":
		url := mustString(cmd["url"])
		log.Printf("AIOrchestrator: fetch url %s", url)
		return nil
	case "post_content":
		content := mustString(cmd["content"])
		log.Printf("AIOrchestrator: post content length=%d", len(content))
		return nil
	default:
		log.Printf("AIOrchestrator: unknown web action: %s", action)
		return errors.New("unknown web action")
	}
}

func (ai *AIOrchestrator) handleCustom(cmd map[string]interface{}) error {
	if subsystem := mustString(cmd["subsystem"]); subsystem == "auto_dev" && ai.AutoDev != nil {
		if err := ai.AutoDev.RunTask(mustMap(cmd["params"])); err != nil {
			return err
		}
		return nil
	}
	log.Printf("AIOrchestrator: executing custom command: %v", cmd)
	return nil
}

// -----------------------------------------------------------------------------
// ExposeFunctions: expose API for model; merges AIOrchestrator functions + registry
// -----------------------------------------------------------------------------

func (ai *AIOrchestrator) ExposeFunctions() map[string]any {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	exposed := map[string]any{}

	// always available read functions
	exposed["get_project_identity"] = ai.GetProjectIdentity

	// expose expire identity
	exposed["expire_project_identity"] = ai.ExpireProjectIdentity

	// Functions available only in DirectMode
	if ai.Mode == DirectMode {
		// Lazy-init advanced modules if nil (safe defaults)
		if ai.Monitor == nil {
			ai.Monitor = monitoring.NewServiceMonitor()
		}
		if ai.Predictive == nil {
			ai.Predictive = scaling.NewPredictiveScaler(ai.Monitor)
		}
		if ai.AutoDev == nil {
			ai.AutoDev = auto_development.NewAutoDevEngine(nil, nil, nil)
		}
		if ai.IdentityFed == nil {
			ai.IdentityFed = identity.NewIdentityFederation()
		}
		if ai.Marketplace == nil {
			ai.Marketplace = marketplace.NewMarketplace()
		}
		if ai.PolicySim == nil {
			ai.PolicySim = policy.NewSimulatorPolicyEngine()
		}
		if ai.QuantumAccel == nil {
			ai.QuantumAccel = quantum.NewQSA()
		}
		if ai.SDNController == nil {
			ai.SDNController = network.NewSDNController()
		}
		if ai.Attestation == nil {
			ai.Attestation = security.NewIsolationManager("")
		}
		if ai.BillingEngine == nil {
			ai.BillingEngine = billing.NewBillingEngine()
		}
		if ai.DataResidency == nil {
			ai.DataResidency = policy.NewDataResidencyEnforcer()
		}
		if ai.GeoManager == nil {
			ai.GeoManager = geo.NewLocationManager()
		}

		// direct function bindings (adapters where necessary)
		if ai.ResourcePool != nil {
			// wrap potentially sensitive calls through safe wrappers if desired
			exposed["add_node"] = func(node *aggregation.ResourceNode) error {
				// prefer using SecureCall for sensitive operations if SecuritySystem is configured
				if ai.SecuritySystem != nil {
					params := map[string]interface{}{
						"node_id": node.ID, "region": node.Region, "resources": node.Resources,
					}
					if err := ai.SecureCall("add_node", params); err == nil {
						// optionally reflect change into ResourcePool after security approval
						ai.ResourcePool.AddNode(node)
						return nil
					} else {
						return err
					}
				}
				// fallback direct call in environments where security system not injected
				ai.ResourcePool.AddNode(node)
				return nil
			}
			exposed["allocate"] = ai.ResourcePool.Allocate
			exposed["free"] = ai.ResourcePool.Free
			exposed["list_reservations"] = ai.ResourcePool.ListReservations
		}
		if ai.Scheduler != nil {
			exposed["add_task"] = ai.Scheduler.AddTask
			exposed["schedule"] = ai.Scheduler.Schedule
			// AdvancedScheduler does not expose ListTasks in original; preserve behavior
			exposed["list_tasks"] = func() []scheduler.Task {
				// return a snapshot if available via method or leave placeholder
				return []scheduler.Task{}
			}
		}
		if ai.MicrotaskManager != nil {
			// expose slice_task wrapper for scheduler.Task and for raw params
			exposed["slice_task"] = func(rootID string, payload map[string]any, num int) (any, error) {
				return ai.MicrotaskManager.SliceTask(rootID, payload, num)
			}
		}
		if ai.StorageLayer != nil {
			exposed["upload_file"] = func(name string, data []byte) error {
				return ai.StorageLayer.Upload(context.Background(), name, data, nil)
			}
			exposed["download_file"] = func(name string) ([]byte, error) {
				return ai.StorageLayer.Download(context.Background(), name)
			}
		}

		exposed["start_app"] = ai.handleAppAPI
		exposed["stop_app"] = ai.handleAppAPI
		exposed["fetch_url"] = ai.handleWebAPI
		exposed["post_content"] = ai.handleWebAPI

		// attach raw modules as well
		exposed["auto_dev"] = ai.AutoDev
		exposed["service_monitor"] = ai.Monitor
		exposed["location_manager"] = ai.GeoManager
		exposed["predictive_scaler"] = ai.Predictive
		exposed["identity_federation"] = ai.IdentityFed
		exposed["marketplace"] = ai.Marketplace
		exposed["simulator_policy"] = ai.PolicySim
		exposed["quantum_accelerator"] = ai.QuantumAccel
		exposed["sdn_controller"] = ai.SDNController
		exposed["attestation_manager"] = ai.Attestation
		exposed["billing_engine"] = ai.BillingEngine
		exposed["data_residency"] = ai.DataResidency
		exposed["generate_project_identity"] = ai.GenerateProjectIdentity
	}

	// Merge registered module functions into exposed map (without overwriting existing keys).
	ai.registryMu.RLock()
	for modName, funcs := range ai.registry {
		for fname, fn := range funcs {
			if _, exists := exposed[fname]; !exists {
				exposed[fname] = fn
			} else {
				// avoid overwriting; expose under module-prefixed name
				exposed[modName+"."+fname] = fn
			}
		}
	}
	ai.registryMu.RUnlock()

	// connectors registry if available
	if ai.connectorManager != nil {
		exposed["connectors_registry"] = ai.connectorManager
	}
	return exposed
}

// -----------------------------------------------------------------------------
// Utilities: safe parsing helpers (defensive)
// -----------------------------------------------------------------------------
func mustString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mustInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case float32:
		return int(t)
	default:
		return 0
	}
}

func mustMap(v interface{}) map[string]interface{} {
	if v == nil {
		return map[string]interface{}{}
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}
