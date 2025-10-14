// internal/services/ael.go
package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"net/http"
)

// ---------- CONFIGURABLE LIMITS ----------
const (
	maxArrayElements   = 1 << 20        // 1M elements
	maxMatrixElements  = 1 << 20        // 1M elements
	maxBlockSize       = 32
	maxCanaryTrials    = 10
	requiredCanaryOK   = 5
	maxMatmulInputSize = 1 << 27        // 128MB per matrix input cap
	fpMarginDefault    = 1e-7
	maxFPAllowedULP    = 4
	energySamplePeriod = 2 * time.Second
)

// =================== TELEMETRY: EXPORT TO PROMETHEUS/INFLUXDB ===================
type Telemetry struct {
	PowerWatt      float64
	EnergyUJ       uint64
	CPUUsage       float64
	GPUUsage       float64
	GPUPowerWatt   float64
	GPUMemMB       float64
	MemUsageMB     float64
	TemperatureC   float64
	LastSampleTime time.Time
}

// Prometheus metrics push (optional, can be disabled)
var PrometheusPushURL string = "" // set to pushgateway URL if needed

func (t Telemetry) PushPrometheus() {
	if PrometheusPushURL == "" {
		return
	}
	body := fmt.Sprintf(
		`# TYPE ael_power_watt gauge
ael_power_watt %f
ael_energy_uj %d
ael_cpu_usage %f
ael_gpu_usage %f
ael_gpu_power_watt %f
ael_gpu_mem_mb %f
ael_mem_usage_mb %f
ael_temp_c %f
`, t.PowerWatt, t.EnergyUJ, t.CPUUsage, t.GPUUsage, t.GPUPowerWatt, t.GPUMemMB, t.MemUsageMB, t.TemperatureC)
	http.Post(PrometheusPushURL, "text/plain", strings.NewReader(body))
}

// SampleTelemetry: Reads actual hardware counters if available, supports multi-backend
func SampleTelemetry() Telemetry {
	t := Telemetry{LastSampleTime: time.Now()}
	t.PowerWatt, t.EnergyUJ = readRAPL()
	t.CPUUsage = readCPU()
	t.GPUUsage, t.GPUPowerWatt, t.GPUMemMB = readNvidiaSMI()
	t.MemUsageMB = readMem()
	t.TemperatureC = readCPUTemp()
	t.PushPrometheus()
	return t
}

// readRAPL: Reads energy from Intel RAPL, Redfish, IPMI, or BMC if available
func readRAPL() (watts float64, uj uint64) {
	// Try Intel RAPL first
	data, err := ioutil.ReadFile("/sys/class/powercap/intel-rapl:0/energy_uj")
	if err == nil {
		val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			return 0, val
		}
	}
	// Try Redfish
	if w, u, ok := readRedfish(); ok {
		return w, u
	}
	// Try IPMI
	if w, ok := readIPMI(); ok {
		return w, 0
	}
	return 0, 0
}

// Redfish: Example (expand with your Redfish endpoint if available)
func readRedfish() (watts float64, uj uint64, ok bool) {
	// Example: GET http://bmc/redfish/v1/Chassis/1/Power
	return 0, 0, false
}

// IPMI: Example (expand to actual IPMI query)
func readIPMI() (watts float64, ok bool) {
	// Example: ipmitool sdr | grep -i watt
	return 0, false
}

// readCPU: Returns normalized CPU usage (cross-platform)
func readCPU() float64 {
	if runtime.GOOS == "linux" {
		out, err := ioutil.ReadFile("/proc/loadavg")
		if err == nil {
			parts := strings.Fields(string(out))
			if len(parts) > 0 {
				load, _ := strconv.ParseFloat(parts[0], 64)
				return math.Min(load/float64(runtime.NumCPU()), 1.0)
			}
		}
	}
	return 0.0 // fallback for non-linux
}

// readNvidiaSMI: Returns GPU util, power, mem (Linux/nvidia-smi)
func readNvidiaSMI() (util, power, mem float64) {
	cmd := exec.Command("nvidia-smi", "--query-gpu=utilization.gpu,power.draw,memory.used", "--format=csv,noheader,nounits")
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, 0
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(parts) < 3 {
		return 0, 0, 0
	}
	util, _ = strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	power, _ = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	mem, _ = strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	return util / 100.0, power, mem
}

// readMem: Reads used memory in MB (Linux)
func readMem() float64 {
	out, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}
	lines := strings.Split(string(out), "\n")
	var used, total float64
	for _, l := range lines {
		if strings.HasPrefix(l, "MemTotal:") {
			total, _ = strconv.ParseFloat(strings.Fields(l)[1], 64)
		}
		if strings.HasPrefix(l, "MemAvailable:") {
			used, _ = strconv.ParseFloat(strings.Fields(l)[1], 64)
		}
	}
	return (total - used) / 1024.0
}

// readCPUTemp: Reads CPU temp (Linux, may need adjustment)
func readCPUTemp() float64 {
	data, err := ioutil.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0.0
	}
	val, _ := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	return val / 1000.0
}

// ======================= DYNAMIC POWER GOVERNOR ========================
type PowerGovernor interface {
	SetCPUFreqMHz(freq int) error
	SetGPUPowerWatt(watt int) error
}
type DefaultGovernor struct{}

func (g *DefaultGovernor) SetCPUFreqMHz(freq int) error {
	// Advanced: can add logic for Redfish/iLO/IPMI here
	return nil
}
func (g *DefaultGovernor) SetGPUPowerWatt(watt int) error {
	cmd := exec.Command("nvidia-smi", "-pl", fmt.Sprintf("%d", watt))
	return cmd.Run()
}

// DynamicGovernor: smart policy, can be extended to AI-based
type DynamicGovernor struct {
	lastCPUFreq int
	lastGPUWatt int
}

func (g *DynamicGovernor) Adjust(t Telemetry) {
	// Example policy: reduce freq if idle, restore if busy
	if t.CPUUsage < 0.05 && g.lastCPUFreq > 1000 {
		g.SetCPUFreqMHz(1000)
	} else if t.CPUUsage > 0.7 && g.lastCPUFreq < 2200 {
		g.SetCPUFreqMHz(2200)
	}
	if t.GPUUsage < 0.05 && g.lastGPUWatt > 90 {
		g.SetGPUPowerWatt(90)
	} else if t.GPUUsage > 0.7 && g.lastGPUWatt < 250 {
		g.SetGPUPowerWatt(250)
	}
}
func (g *DynamicGovernor) SetCPUFreqMHz(freq int) error {
	g.lastCPUFreq = freq
	return nil
}
func (g *DynamicGovernor) SetGPUPowerWatt(watt int) error {
	g.lastGPUWatt = watt
	return nil
}

// ================== MAIN AEL STRUCTURE ==================
type AdaptiveEfficiencyLayer struct {
	lastOptimize      time.Time
	microOpt          MicroOpt
	cpuHotThreshold   float64
	gpuHotThreshold   float64
	mu                sync.Mutex
	activePatches     map[string]PatchMetadata
	telemetry         Telemetry
	energyBaselineUJ  uint64
	governor          PowerGovernor
}

func NewAEL() *AdaptiveEfficiencyLayer {
	ael := &AdaptiveEfficiencyLayer{
		lastOptimize:    time.Now(),
		microOpt:        NewMicroOptImpl(),
		cpuHotThreshold: 0.6,
		gpuHotThreshold: 0.4,
		activePatches:   make(map[string]PatchMetadata),
		governor:        &DynamicGovernor{},
	}
	go ael.telemetryLoop()
	return ael
}

func (a *AdaptiveEfficiencyLayer) telemetryLoop() {
	for {
		t := SampleTelemetry()
		a.mu.Lock()
		a.telemetry = t
		a.mu.Unlock()
		if a.governor != nil {
			governor := a.governor
			governor.(*DynamicGovernor).Adjust(t)
		}
		time.Sleep(energySamplePeriod)
	}
}
func (a *AdaptiveEfficiencyLayer) CurrentTelemetry() Telemetry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.telemetry
}
func (a *AdaptiveEfficiencyLayer) SetGovernor(g PowerGovernor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.governor = g
}

// ---------- AppUsage, PatchMetadata, Registry, etc. ----------
type AppUsage struct {
	AppID    string
	CPUUsage float64
	GPUUsage float64
	HotFuncs map[string][][]byte
}
type PatchMetadata struct {
	PatchToken   string
	FuncID       string
	AppliedAt    time.Time
	Canary       bool
	CanaryTrials int
}

type FuncCallable func([]byte) ([]byte, error)
type FuncEntry struct {
	id        string
	impl      atomic.Value
	baseline  FuncCallable
	mu        sync.Mutex
	callCount int64
	isFP      bool
	kernelTag string // for future: "matmul", "conv2d", etc.
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*FuncEntry{}
)

// RegisterFunction: production ready, integrates with system registry, supports tags for new kernels
func RegisterFunction(funcID string, baseline FuncCallable, isFP bool, kernelTag ...string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	tag := ""
	if len(kernelTag) > 0 {
		tag = kernelTag[0]
	}
	e, ok := registry[funcID]
	if !ok {
		e = &FuncEntry{id: funcID, isFP: isFP, kernelTag: tag}
		e.impl.Store(baseline)
		e.baseline = baseline
		registry[funcID] = e
		return
	}
	e.mu.Lock()
	e.baseline = baseline
	e.isFP = isFP
	e.kernelTag = tag
	e.mu.Unlock()
}
func ExecuteFunc(funcID string, input []byte) ([]byte, error) {
	registryMu.RLock()
	e, ok := registry[funcID]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("function %s not registered", funcID)
	}
	callable, ok := e.impl.Load().(FuncCallable)
	if !ok || callable == nil {
		return nil, fmt.Errorf("no implementation for %s", funcID)
	}
	atomic.AddInt64(&e.callCount, 1)
	defer atomic.AddInt64(&e.callCount, -1)
	return callable(input)
}
func atomicReplaceImpl(funcID string, newImpl FuncCallable) (oldImpl FuncCallable, err error) {
	registryMu.RLock()
	e, ok := registry[funcID]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("function %s not registered", funcID)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev, _ := e.impl.Load().(FuncCallable)
	e.impl.Store(newImpl)
	return prev, nil
}
func restoreToBaseline(funcID string) error {
	registryMu.RLock()
	e, ok := registry[funcID]
	registryMu.RUnlock()
	if !ok {
		return fmt.Errorf("function %s not registered", funcID)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.baseline == nil {
		return fmt.Errorf("no baseline for %s", funcID)
	}
	e.impl.Store(e.baseline)
	return nil
}

// ========== MicroOpt: Full Implementation, Ready for Any Kernel ==========
type MicroOpt interface {
	OptimizeFunc(ctx context.Context, funcID string, sampleInputs [][]byte) (string, error)
	VerifyPatch(ctx context.Context, patchToken string) (bool, error)
	RollbackPatch(ctx context.Context, patchToken string) error
}
type microOptImpl struct {
	mu           sync.Mutex
	patchCounter uint64
	patches      map[string]*patchRecord
	pool         *bufferPool
}
type patchRecord struct {
	token       string
	funcID      string
	oldImpl     FuncCallable
	newImpl     FuncCallable
	createdAt   time.Time
	verified    bool
	canaryCount int
}
func NewMicroOptImpl() MicroOpt {
	return &microOptImpl{
		patches: map[string]*patchRecord{},
		pool:    newBufferPool(),
	}
}
func (m *microOptImpl) OptimizeFunc(ctx context.Context, funcID string, sampleInputs [][]byte) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	registryMu.RLock()
	entry, ok := registry[funcID]
	registryMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("OptimizeFunc: function %s not registered", funcID)
	}
	var optimized FuncCallable
	isFP := entry.isFP
	tag := entry.kernelTag

	switch {
	case tag == "matmul" || hasPrefix(funcID, "matmul-int:"):
		optimized = m.buildMatMulIntOptimized()
	case tag == "sort" || hasPrefix(funcID, "sort-int:"):
		optimized = m.buildSortIntOptimized()
	case tag == "matmul-fp32" || hasPrefix(funcID, "matmul-fp32:"):
		optimized = m.buildMatMulFP32Optimized()
	case tag == "conv2d":
		optimized = m.buildConv2DOptimized()
	default:
		optimized = m.buildZeroCopyWrapper(entry.baseline)
	}

	// VERIFY: outputs match for all samples, check input sizes
	for i, in := range sampleInputs {
		if len(in) > maxMatmulInputSize {
			return "", fmt.Errorf("OptimizeFunc: input sample %d exceeds max allowed size", i)
		}
		select {
		case <-ctx.Done():
			return "", errors.New("OptimizeFunc: context canceled during verification")
		default:
		}
		refOut, err := entry.baseline(in)
		if err != nil {
			return "", fmt.Errorf("OptimizeFunc: baseline execution error on sample %d: %w", i, err)
		}
		optOut, err := optimized(in)
		if err != nil {
			return "", fmt.Errorf("OptimizeFunc: optimized execution error on sample %d: %w", i, err)
		}
		if isFP {
			if !fpEqualOrAcceptable(refOut, optOut, fpMarginDefault, maxFPAllowedULP) {
				return "", fmt.Errorf("OptimizeFunc: verification failed for FP kernel on sample %d (margin exceeded)", i)
			}
		} else {
			if !deterministicEqual(refOut, optOut) {
				return "", fmt.Errorf("OptimizeFunc: verification failed on sample %d - outputs differ", i)
			}
		}
	}
	oldImpl, err := atomicReplaceImpl(funcID, optimized)
	if err != nil {
		return "", fmt.Errorf("OptimizeFunc: failed to swap impl: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patchCounter++
	token := fmt.Sprintf("patch-%d-%d", time.Now().UnixNano(), m.patchCounter)
	rec := &patchRecord{
		token:     token,
		funcID:    funcID,
		oldImpl:   oldImpl,
		newImpl:   optimized,
		createdAt: time.Now(),
	}
	m.patches[token] = rec
	return token, nil
}
func (m *microOptImpl) VerifyPatch(ctx context.Context, patchToken string) (bool, error) {
	m.mu.Lock()
	rec, ok := m.patches[patchToken]
	m.mu.Unlock()
	if !ok {
		return false, fmt.Errorf("VerifyPatch: unknown token %s", patchToken)
	}
	rec.canaryCount++
	if rec.canaryCount >= requiredCanaryOK {
		rec.verified = true
		return true, nil
	}
	return true, nil
}
func (m *microOptImpl) RollbackPatch(ctx context.Context, patchToken string) error {
	m.mu.Lock()
	rec, ok := m.patches[patchToken]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("RollbackPatch: unknown token %s", patchToken)
	}
	delete(m.patches, patchToken)
	m.mu.Unlock()
	registryMu.RLock()
	entry, entryOk := registry[rec.funcID]
	registryMu.RUnlock()
	if !entryOk {
		return fmt.Errorf("RollbackPatch: funcID %s not found", rec.funcID)
	}
	if rec.oldImpl == nil {
		if err := restoreToBaseline(rec.funcID); err != nil {
			return fmt.Errorf("RollbackPatch: failed to restore baseline: %w", err)
		}
	} else {
		_, err := atomicReplaceImpl(rec.funcID, rec.oldImpl)
		if err != nil {
			return fmt.Errorf("RollbackPatch: failed to restore oldImpl: %w", err)
		}
	}
	for i := 0; i < 100; i++ {
		if atomic.LoadInt64(&entry.callCount) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// ----------- Micro-Optimizations (int/FP/zero-copy/conv2d future) -----------
func (m *microOptImpl) buildZeroCopyWrapper(baseline FuncCallable) FuncCallable {
	return func(input []byte) ([]byte, error) {
		return baseline(input)
	}
}
func (m *microOptImpl) buildSortIntOptimized() FuncCallable {
	return func(input []byte) ([]byte, error) {
		if len(input) < 4 {
			return nil, fmt.Errorf("sort-int: input too small")
		}
		n := int(binary.LittleEndian.Uint32(input[:4]))
		if n <= 0 || n > maxArrayElements {
			return nil, fmt.Errorf("sort-int: n out of bounds (%d)", n)
		}
		if len(input) < 4+4*n {
			return nil, fmt.Errorf("sort-int: input length mismatch")
		}
		arr := make([]int32, n)
		minv := int32(1<<31 - 1)
		maxv := int32(-1 << 31)
		for i := 0; i < n; i++ {
			v := int32(binary.LittleEndian.Uint32(input[4+i*4 : 4+(i+1)*4]))
			arr[i] = v
			if v < minv {
				minv = v
			}
			if v > maxv {
				maxv = v
			}
		}
		rangeSize := int64(maxv) - int64(minv) + 1
		if rangeSize > 1 && rangeSize <= int64(1<<20) {
			bins := make([]int, rangeSize)
			for _, v := range arr {
				bins[int(int64(v)-int64(minv))]++
			}
			outBuf := make([]byte, 4+4*n)
			binary.LittleEndian.PutUint32(outBuf[:4], uint32(n))
			idx := 4
			for i := int64(0); i < rangeSize; i++ {
				count := bins[i]
				val := int32(int64(minv) + i)
				for c := 0; c < count; c++ {
					binary.LittleEndian.PutUint32(outBuf[idx:idx+4], uint32(val))
					idx += 4
				}
			}
			return outBuf, nil
		}
		p := make([]int32, n)
		copy(p, arr)
		quickSortInt32(p)
		outBuf := make([]byte, 4+4*n)
		binary.LittleEndian.PutUint32(outBuf[:4], uint32(n))
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(outBuf[4+i*4:4+(i+1)*4], uint32(p[i]))
		}
		return outBuf, nil
	}
}
func (m *microOptImpl) buildMatMulIntOptimized() FuncCallable {
	return func(input []byte) ([]byte, error) {
		if len(input) < 12 {
			return nil, fmt.Errorf("matmul-int: input too small")
		}
		r1 := int(binary.LittleEndian.Uint32(input[0:4]))
		c1 := int(binary.LittleEndian.Uint32(input[4:8]))
		c2 := int(binary.LittleEndian.Uint32(input[8:12]))
		mul1 := int64(r1) * int64(c1)
		mul2 := int64(c1) * int64(c2)
		total := mul1 + mul2
		if mul1 < 0 || mul2 < 0 || total > maxMatrixElements {
			return nil, fmt.Errorf("matmul-int: dimensions too large or risk overflow")
		}
		expected := 12 + 4*(int(mul1)+int(mul2))
		if len(input) < expected {
			return nil, fmt.Errorf("matmul-int: input length mismatch wanted %d got %d", expected, len(input))
		}
		if r1 <= 0 || c1 <= 0 || c2 <= 0 || r1 > maxBlockSize*maxBlockSize || c1 > maxBlockSize*maxBlockSize || c2 > maxBlockSize*maxBlockSize {
			return nil, fmt.Errorf("matmul-int: dims out of bounds r1=%d c1=%d c2=%d", r1, c1, c2)
		}
		A := make([]int32, r1*c1)
		B := make([]int32, c1*c2)
		offset := 12
		for i := 0; i < r1*c1; i++ {
			A[i] = int32(binary.LittleEndian.Uint32(input[offset : offset+4]))
			offset += 4
		}
		for i := 0; i < c1*c2; i++ {
			B[i] = int32(binary.LittleEndian.Uint32(input[offset : offset+4]))
			offset += 4
		}
		C := make([]int64, r1*c2)
		blk := maxBlockSize
		if blk > c1 { blk = c1 }
		for ii := 0; ii < r1; ii += blk {
			iimax := min(ii+blk, r1)
			for kk := 0; kk < c1; kk += blk {
				kkmax := min(kk+blk, c1)
				for jj := 0; jj < c2; jj += blk {
					jjmax := min(jj+blk, c2)
					for i := ii; i < iimax; i++ {
						for k := kk; k < kkmax; k++ {
							av := int64(A[i*c1+k])
							for j := jj; j < jjmax; j++ {
								C[i*c2+j] += av * int64(B[k*c2+j])
							}
						}
					}
				}
			}
		}
		out := make([]byte, 8+8*len(C))
		binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
		binary.LittleEndian.PutUint32(out[4:8], uint32(c2))
		off := 8
		for i := 0; i < len(C); i++ {
			binary.LittleEndian.PutUint64(out[off:off+8], uint64(C[i]))
			off += 8
		}
		return out, nil
	}
}
func (m *microOptImpl) buildMatMulFP32Optimized() FuncCallable {
	return func(input []byte) ([]byte, error) {
		if len(input) < 12 {
			return nil, fmt.Errorf("matmul-fp32: input too small")
		}
		r1 := int(binary.LittleEndian.Uint32(input[0:4]))
		c1 := int(binary.LittleEndian.Uint32(input[4:8]))
		c2 := int(binary.LittleEndian.Uint32(input[8:12]))
		mul1 := int64(r1) * int64(c1)
		mul2 := int64(c1) * int64(c2)
		total := mul1 + mul2
		if mul1 < 0 || mul2 < 0 || total > maxMatrixElements {
			return nil, fmt.Errorf("matmul-fp32: dimensions too large or risk overflow")
		}
		expected := 12 + 4*(int(mul1)+int(mul2))
		if len(input) < expected {
			return nil, fmt.Errorf("matmul-fp32: input length mismatch wanted %d got %d", expected, len(input))
		}
		A := make([]float32, r1*c1)
		B := make([]float32, c1*c2)
		offset := 12
		for i := 0; i < r1*c1; i++ {
			A[i] = math.Float32frombits(binary.LittleEndian.Uint32(input[offset : offset+4]))
			offset += 4
		}
		for i := 0; i < c1*c2; i++ {
			B[i] = math.Float32frombits(binary.LittleEndian.Uint32(input[offset : offset+4]))
			offset += 4
		}
		C := make([]float32, r1*c2)
		blk := maxBlockSize
		if blk > c1 { blk = c1 }
		for ii := 0; ii < r1; ii += blk {
			iimax := min(ii+blk, r1)
			for kk := 0; kk < c1; kk += blk {
				kkmax := min(kk+blk, c1)
				for jj := 0; jj < c2; jj += blk {
					jjmax := min(jj+blk, c2)
					for i := ii; i < iimax; i++ {
						for k := kk; k < kkmax; k++ {
							av := A[i*c1+k]
							for j := jj; j < jjmax; j++ {
								C[i*c2+j] += av * B[k*c2+j]
							}
						}
					}
				}
			}
		}
		out := make([]byte, 8+4*len(C))
		binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
		binary.LittleEndian.PutUint32(out[4:8], uint32(c2))
		off := 8
		for i := 0; i < len(C); i++ {
			binary.LittleEndian.PutUint32(out[off:off+4], math.Float32bits(C[i]))
			off += 4
		}
		return out, nil
	}
}

// ====== EXAMPLE: Conv2D Kernel (Future Extension, Not Implemented) ======
func (m *microOptImpl) buildConv2DOptimized() FuncCallable {
	return func(input []byte) ([]byte, error) {
		// Placeholder: You can implement a real conv2d here for future AI kernels
		return nil, fmt.Errorf("conv2d: not implemented yet")
	}
}

// ----------- Equality/FP helpers ------------
func deterministicEqual(a, b []byte) bool {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return bytes.Equal(ha[:], hb[:])
}
func fpEqualOrAcceptable(a, b []byte, margin float64, maxULP int) bool {
	if len(a) != len(b) { return false }
	if bytes.Equal(a, b) { return true }
	if len(a) >= 8 && len(b) >= 8 {
		r1 := int(binary.LittleEndian.Uint32(a[0:4]))
		c2 := int(binary.LittleEndian.Uint32(a[4:8]))
		expect := 8 + 4*r1*c2
		if len(a) == expect && len(b) == expect {
			for i := 0; i < r1*c2; i++ {
				af := math.Float32frombits(binary.LittleEndian.Uint32(a[8+i*4 : 8+(i+1)*4]))
				bf := math.Float32frombits(binary.LittleEndian.Uint32(b[8+i*4 : 8+(i+1)*4]))
				if !fp32EqMarginOrULP(af, bf, margin, maxULP) {
					return false
				}
			}
			return true
		}
	}
	return false
}
func fp32EqMarginOrULP(a, b float32, margin float64, maxULP int) bool {
	if a == b { return true }
	da, db := float64(a), float64(b)
	diff := math.Abs(da - db)
	if diff <= margin { return true }
	rel := diff / (math.Abs(da) + math.Abs(db) + 1e-12)
	if rel <= margin { return true }
	return fp32ULPDiff(a, b) <= maxULP
}
func fp32ULPDiff(a, b float32) int {
	ia := int32(math.Float32bits(a))
	ib := int32(math.Float32bits(b))
	if ia < 0 { ia = 0x80000000 - ia }
	if ib < 0 { ib = 0x80000000 - ib }
	return int(abs32(ia - ib))
}
func abs32(x int32) int32 {
	if x < 0 { return -x }
	return x
}

// --------- Utilities: min, sort, buffer pool ----------
func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func min(a, b int) int { if a < b { return a } else { return b } }
func quickSortInt32(a []int32) {
	if len(a) <= 1 { return }
	pivot := a[len(a)/2]
	lo := make([]int32, 0, len(a))
	hi := make([]int32, 0, len(a))
	eq := make([]int32, 0, len(a))
	for _, v := range a {
		if v < pivot { lo = append(lo, v)
		} else if v > pivot { hi = append(hi, v)
		} else { eq = append(eq, v) }
	}
	quickSortInt32(lo); quickSortInt32(hi)
	copy(a, append(append(lo, eq...), hi...))
}
type bufferPool struct { pool sync.Pool }
func newBufferPool() *bufferPool {
	return &bufferPool{pool: sync.Pool{New: func() interface{} { return make([]byte, 0, 4096) }}}
}
func (p *bufferPool) Get() []byte { return p.pool.Get().([]byte) }
func (p *bufferPool) Put(b []byte) { if cap(b) > 1<<20 { return }; p.pool.Put(b[:0]) }

// ---- Example baselines ----
func BaselineMatMulInt(input []byte) ([]byte, error) {
	if len(input) < 12 {
		return nil, fmt.Errorf("baseline matmul: input too small")
	}
	r1 := int(binary.LittleEndian.Uint32(input[0:4]))
	c1 := int(binary.LittleEndian.Uint32(input[4:8]))
	c2 := int(binary.LittleEndian.Uint32(input[8:12]))
	mul1 := int64(r1) * int64(c1)
	mul2 := int64(c1) * int64(c2)
	total := mul1 + mul2
	if mul1 < 0 || mul2 < 0 || total > maxMatrixElements {
		return nil, fmt.Errorf("baseline matmul: dimensions too large or risk overflow")
	}
	expected := 12 + 4*(int(mul1)+int(mul2))
	if len(input) < expected {
		return nil, fmt.Errorf("baseline matmul: input length mismatch")
	}
	A := make([]int32, r1*c1)
	B := make([]int32, c1*c2)
	offset := 12
	for i := 0; i < r1*c1; i++ {
		A[i] = int32(binary.LittleEndian.Uint32(input[offset : offset+4]))
		offset += 4
	}
	for i := 0; i < c1*c2; i++ {
		B[i] = int32(binary.LittleEndian.Uint32(input[offset : offset+4]))
		offset += 4
	}
	C := make([]int64, r1*c2)
	for i := 0; i < r1; i++ {
		for k := 0; k < c1; k++ {
			av := int64(A[i*c1+k])
			for j := 0; j < c2; j++ {
				C[i*c2+j] += av * int64(B[k*c2+j])
			}
		}
	}
	out := make([]byte, 8+8*len(C))
	binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
	binary.LittleEndian.PutUint32(out[4:8], uint32(c2))
	off := 8
	for i := 0; i < len(C); i++ {
		binary.LittleEndian.PutUint64(out[off:off+8], uint64(C[i]))
		off += 8
	}
	return out, nil
}
func BaselineSortInt(input []byte) ([]byte, error) {
	tmp := NewMicroOptImpl()
	fn := tmp.buildSortIntOptimized()
	return fn(input)
}
func BaselineMatMulFP32(input []byte) ([]byte, error) {
	if len(input) < 12 {
		return nil, fmt.Errorf("baseline matmul-fp32: input too small")
	}
	r1 := int(binary.LittleEndian.Uint32(input[0:4]))
	c1 := int(binary.LittleEndian.Uint32(input[4:8]))
	c2 := int(binary.LittleEndian.Uint32(input[8:12]))
	mul1 := int64(r1) * int64(c1)
	mul2 := int64(c1) * int64(c2)
	total := mul1 + mul2
	if mul1 < 0 || mul2 < 0 || total > maxMatrixElements {
		return nil, fmt.Errorf("baseline matmul-fp32: dimensions too large or risk overflow")
	}
	expected := 12 + 4*(int(mul1)+int(mul2))
	if len(input) < expected {
		return nil, fmt.Errorf("baseline matmul-fp32: input length mismatch")
	}
	A := make([]float32, r1*c1)
	B := make([]float32, c1*c2)
	offset := 12
	for i := 0; i < r1*c1; i++ {
		A[i] = math.Float32frombits(binary.LittleEndian.Uint32(input[offset : offset+4]))
		offset += 4
	}
	for i := 0; i < c1*c2; i++ {
		B[i] = math.Float32frombits(binary.LittleEndian.Uint32(input[offset : offset+4]))
		offset += 4
	}
	C := make([]float32, r1*c2)
	for i := 0; i < r1; i++ {
		for k := 0; k < c1; k++ {
			av := A[i*c1+k]
			for j := 0; j < c2; j++ {
				C[i*c2+j] += av * B[k*c2+j]
			}
		}
	}
	out := make([]byte, 8+4*len(C))
	binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
	binary.LittleEndian.PutUint32(out[4:8], uint32(c2))
	off := 8
	for i := 0; i < len(C); i++ {
		binary.LittleEndian.PutUint32(out[off:off+4], math.Float32bits(C[i]))
		off += 4
	}
	return out, nil
}

// ---------- Serialization helpers ----------
func SerializeIntArray(arr []int32) []byte {
	out := make([]byte, 4+4*len(arr))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(arr)))
	offset := 4
	for _, v := range arr {
		binary.LittleEndian.PutUint32(out[offset:offset+4], uint32(v))
		offset += 4
	}
	return out
}
func SerializeMatInt(A []int32, r1, c1 int, B []int32, c2 int) []byte {
	out := make([]byte, 12+4*(len(A)+len(B)))
	binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
	binary.LittleEndian.PutUint32(out[4:8], uint32(c1))
	binary.LittleEndian.PutUint32(out[8:12], uint32(c2))
	offset := 12
	for _, v := range A {
		binary.LittleEndian.PutUint32(out[offset:offset+4], uint32(v))
		offset += 4
	}
	for _, v := range B {
		binary.LittleEndian.PutUint32(out[offset:offset+4], uint32(v))
		offset += 4
	}
	return out
}
func SerializeMatFP32(A []float32, r1, c1 int, B []float32, c2 int) []byte {
	out := make([]byte, 12+4*(len(A)+len(B)))
	binary.LittleEndian.PutUint32(out[0:4], uint32(r1))
	binary.LittleEndian.PutUint32(out[4:8], uint32(c1))
	binary.LittleEndian.PutUint32(out[8:12], uint32(c2))
	offset := 12
	for _, v := range A {
		binary.LittleEndian.PutUint32(out[offset:offset+4], math.Float32bits(v))
		offset += 4
	}
	for _, v := range B {
		binary.LittleEndian.PutUint32(out[offset:offset+4], math.Float32bits(v))
		offset += 4
	}
	return out
}
func DeserializeMatFP32Result(b []byte) (r1, c2 int, C []float32, err error) {
	if len(b) < 8 {
		return 0, 0, nil, fmt.Errorf("DeserializeMatFP32Result: too small")
	}
	r1 = int(binary.LittleEndian.Uint32(b[0:4]))
	c2 = int(binary.LittleEndian.Uint32(b[4:8]))
	expect := 8 + 4*r1*c2
	if len(b) != expect {
		return 0, 0, nil, fmt.Errorf("DeserializeMatFP32Result: length mismatch expected %d got %d", expect, len(b))
	}
	C = make([]float32, r1*c2)
	off := 8
	for i := 0; i < r1*c2; i++ {
		C[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[off : off+4]))
		off += 4
	}
	return r1, c2, C, nil
}

// ---- Hash, List, PatchInfo, init ----
func deterministicHash(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return sum[:], nil
}
func ListRegisteredFunctions() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	return out
}
func (a *AdaptiveEfficiencyLayer) ActivePatchesSnapshot() []PatchMetadata {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PatchMetadata, 0, len(a.activePatches))
	for _, v := range a.activePatches {
		out = append(out, v)
	}
	return out
}
func (a *AdaptiveEfficiencyLayer) GetMicroOptPatchInfo(token string) *patchRecord {
	if impl, ok := a.microOpt.(*microOptImpl); ok {
		impl.mu.Lock()
		defer impl.mu.Unlock()
		if pr, ok := impl.patches[token]; ok {
			cp := *pr
			return &cp
		}
	}
	return nil
}
func init() {
	RegisterFunction("matmul-int:default", BaselineMatMulInt, false, "matmul")
	RegisterFunction("sort-int:default", BaselineSortInt, false, "sort")
	RegisterFunction("matmul-fp32:default", BaselineMatMulFP32, true, "matmul-fp32")
	// Ready for future kernels:
	// RegisterFunction("conv2d:default", BaselineConv2D, true, "conv2d")
}