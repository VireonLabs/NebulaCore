// internal/quantum/qsa.go
// Meta-Quantum Engine — Unified single-file implementation.
// - MetaQuantumEngine (job manager, planner)
// - LocalStatevectorBackend (pure-Go statevector simulator)
// - Builders: QFT, Grover, QAOA, VQE
// - SurrogateInProc (lightweight in-process surrogate model: vectorize/train/predict)
// - cuQuantum stub (non-accelerated safe fallback)
//
// NOTE: Educational / pragmatic implementation. Not a physical QPU.
// For production/high-qubit count integrate a real accelerated backend.

package quantum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/cmplx"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
	"runtime"
)

// ---------------- Types & Interfaces ----------------

type TaskType string

const (
	TaskSearch       TaskType = "search"
	TaskOptimization TaskType = "optimization"
	TaskFactoring    TaskType = "factoring"
	TaskSimulation   TaskType = "simulation"
)

// Gate describes a primitive gate in a circuit
type Gate struct {
	Name   string            `json:"name"`
	Qubits []int             `json:"qubits"`
	Params []float64         `json:"params,omitempty"`
	Matrix [][]complex128    `json:"matrix,omitempty"`
}

// Backend interface - pluggable engines
type Backend interface {
	Name() string
	Supports(qubits int) bool
	RunCircuit(ctx context.Context, nQubits int, gates []Gate, shots int) (map[int]int, error)
	RunStatevector(ctx context.Context, nQubits int, gates []Gate) ([]complex128, error)
}

// SurrogateClient defines an in-process or remote surrogate
type SurrogateClient interface {
	Predict(circuit []Gate) (pred map[string]float64, confidence float64, err error)
	Train(batch []SurrogateDatum) error
	Name() string
}

type SurrogateDatum struct {
	Circuit []Gate                 `json:"circuit"`
	Labels  map[string]float64     `json:"labels"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// Job & engine
type QuantumJob struct {
	ID        string                 `json:"id"`
	Task      TaskType               `json:"task"`
	Input     map[string]float64     `json:"input,omitempty"`
	NQubits   int                    `json:"n_qubits"`
	Circuit   []Gate                 `json:"circuit,omitempty"`
	Backend   string                 `json:"backend,omitempty"`
	Shots     int                    `json:"shots,omitempty"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Status    string                 `json:"status,omitempty"` // pending,running,done,failed
	Started   time.Time              `json:"started,omitempty"`
	Completed time.Time              `json:"completed,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

type MetaQuantumEngine struct {
	mu             sync.RWMutex
	backends       map[string]Backend
	jobs           map[string]*QuantumJob
	surrogates     map[string]SurrogateClient
	rng            *rand.Rand
	MaxWorkers     int
	defaultBackend string
}

// ---------------- Constructor ----------------

func NewMetaQuantumEngine() *MetaQuantumEngine {
	e := &MetaQuantumEngine{
		backends:       make(map[string]Backend),
		jobs:           make(map[string]*QuantumJob),
		surrogates:     make(map[string]SurrogateClient),
		rng:            rand.New(rand.NewSource(time.Now().UnixNano())),
		MaxWorkers:     runtime.GOMAXPROCS(0),
		defaultBackend: "local-statevector",
	}
	// register local backend
	local := NewLocalStatevectorBackend()
	e.RegisterBackend(local)
	// register inproc surrogate by default (optional)
	surr := NewSurrogateInProc("inproc-surrogate")
	e.RegisterSurrogate(surr.Name(), surr)
	return e
}

// ---------------- Backend registration ----------------

func (m *MetaQuantumEngine) RegisterBackend(b Backend) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backends[b.Name()] = b
}

func (m *MetaQuantumEngine) RegisterSurrogate(name string, s SurrogateClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.surrogates[name] = s
	// also expose as backend adapter
	m.backends["surrogate-"+name] = &surrogateBackendAdapter{name: "surrogate-" + name, client: s}
}

func (m *MetaQuantumEngine) ListBackends() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.backends))
	for k := range m.backends {
		out = append(out, k)
	}
	return out
}

// chooseBackend picks a backend (simple cost model)
func (m *MetaQuantumEngine) chooseBackend(nQubits int) Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// prefer non-local capable backends if support
	for _, b := range m.backends {
		if b.Name() != "local-statevector" && b.Supports(nQubits) {
			return b
		}
	}
	// fallback to local
	if b, ok := m.backends[m.defaultBackend]; ok {
		return b
	}
	// pick any that supports
	for _, b := range m.backends {
		if b.Supports(nQubits) {
			return b
		}
	}
	return nil
}

// ---------------- Submit & run jobs ----------------

func (m *MetaQuantumEngine) SubmitJob(ctx context.Context, task TaskType, nQubits int, circuit []Gate, shots int, input map[string]float64) (string, error) {
	id := fmt.Sprintf("qj-%d", time.Now().UnixNano())
	job := &QuantumJob{
		ID:      id,
		Task:    task,
		Input:   input,
		NQubits: nQubits,
		Circuit: circuit,
		Shots:   shots,
		Status:  "pending",
		Started: time.Now(),
	}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	go m.runJob(ctx, id)
	return id, nil
}

func (m *MetaQuantumEngine) runJob(ctx context.Context, id string) {
	m.mu.Lock()
	job, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	job.Status = "running"
	m.mu.Unlock()

	// meta planner decision: use surrogate if available & confident (simple policy)
	if sName, sClient, ok := m.findConfidentSurrogate(job); ok && job.NQubits > 20 {
		// delegate to surrogate backend adapter (registered as backend)
		if b, exists := m.backends["surrogate-"+sName]; exists {
			job.Backend = b.Name()
			counts, err := b.RunCircuit(ctx, job.NQubits, job.Circuit, job.Shots)
			m.mu.Lock()
			if err != nil {
				job.Status = "failed"
				job.Error = err.Error()
			} else {
				job.Status = "done"
				job.Result = map[string]interface{}{"counts": counts, "surrogate": sName}
			}
			job.Completed = time.Now()
			m.mu.Unlock()
			return
		} else {
			_ = sClient // keep logic placeholder
		}
	}

	backend := m.chooseBackend(job.NQubits)
	if backend == nil {
		m.mu.Lock()
		job.Status = "failed"
		job.Error = "no suitable backend"
		job.Completed = time.Now()
		m.mu.Unlock()
		return
	}
	job.Backend = backend.Name()

	// run with timeout per job
	jobCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	if job.Shots > 0 {
		counts, err := backend.RunCircuit(jobCtx, job.NQubits, job.Circuit, job.Shots)
		m.mu.Lock()
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
		} else {
			job.Status = "done"
			job.Result = map[string]interface{}{"counts": counts}
		}
		job.Completed = time.Now()
		m.mu.Unlock()
		return
	}

	state, err := backend.RunStatevector(jobCtx, job.NQubits, job.Circuit)
	m.mu.Lock()
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else {
		// encode statevector as slice of complex numbers
		job.Status = "done"
		// we convert to []interface{} for JSON-friendliness: represent each amplitude as [real,imag]
		vout := make([][2]float64, len(state))
		for i, c := range state {
			vout[i] = [2]float64{real(c), imag(c)}
		}
		job.Result = map[string]interface{}{"statevector": vout}
	}
	job.Completed = time.Now()
	m.mu.Unlock()
}

// GetJob retrieves job metadata & result
func (m *MetaQuantumEngine) GetJob(id string) (*QuantumJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, errors.New("job not found")
	}
	return j, nil
}

// ---------------- Surrogate selection helper ----------------

func (m *MetaQuantumEngine) findConfidentSurrogate(job *QuantumJob) (string, SurrogateClient, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// simple policy: return first surrogate if any
	for name, s := range m.surrogates {
		_ = s
		return name, s, true
	}
	return "", nil, false
}

// ---------------- surrogateBackendAdapter (delegates to SurrogateClient) ---------

type surrogateBackendAdapter struct {
	name   string
	client SurrogateClient
}

func (s *surrogateBackendAdapter) Name() string { return s.name }
func (s *surrogateBackendAdapter) Supports(qubits int) bool {
	// surrogate approximate supports large qubits conceptually
	return true
}
func (s *surrogateBackendAdapter) RunCircuit(ctx context.Context, nQubits int, gates []Gate, shots int) (map[int]int, error) {
	pred, conf, err := s.client.Predict(gates)
	if err != nil {
		return nil, err
	}
	if conf < 0.40 {
		return nil, fmt.Errorf("surrogate confidence too low: %f", conf)
	}
	// pred is expected to be map[string->prob], keys as "prob_<idx>"
	out := make(map[int]int)
	totalShots := shots
	if totalShots <= 0 {
		totalShots = 1024
	}
	// collect probs
	type kv struct {
		idx int
		p   float64
	}
	var arr []kv
	sum := 0.0
	for k, v := range pred {
		if strings.HasPrefix(k, "prob_") {
			var idx int
			fmt.Sscanf(k, "prob_%d", &idx)
			arr = append(arr, kv{idx: idx, p: v})
			sum += v
		}
	}
	if len(arr) == 0 {
		// no distribution given
		return out, nil
	}
	// normalize
	if sum == 0 {
		for i := range arr {
			arr[i].p = 1.0 / float64(len(arr))
		}
	} else {
		for i := range arr {
			arr[i].p = arr[i].p / sum
		}
	}
	// build cumulative and sample
	cum := make([]float64, len(arr))
	acc := 0.0
	for i := range arr {
		acc += arr[i].p
		cum[i] = acc
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for sshot := 0; sshot < totalShots; sshot++ {
		p := rnd.Float64()
		lo, hi := 0, len(cum)-1
		for lo < hi {
			mid := (lo + hi) / 2
			if cum[mid] < p {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		out[arr[lo].idx]++
	}
	return out, nil
}

// ---------------- In-process Surrogate (lightweight ML) ----------------

// SurrogateInProc: simple vectorizer + linear softmax model trained with SGD.
// Designed to be self-contained (no PyTorch dependency). Produces "prob_<i>" outputs.
type SurrogateInProc struct {
	name   string
	inDim  int
	outDim int
	// weights: outDim x inDim
	weights [][]float64
	lr      float64
	mu      sync.RWMutex
}

func NewSurrogateInProc(name string) *SurrogateInProc {
	in := 64
	out := 32
	w := make([][]float64, out)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < out; i++ {
		row := make([]float64, in)
		for j := 0; j < in; j++ {
			row[j] = (r.Float64()*2 - 1) * 0.01
		}
		w[i] = row
	}
	return &SurrogateInProc{
		name:   name,
		inDim:  in,
		outDim: out,
		weights: w,
		lr:     0.05,
	}
}

func (s *SurrogateInProc) Name() string { return s.name }

// vectorize circuit (simple heuristic similar to python earlier)
func (s *SurrogateInProc) vectorize(circuit []Gate) []float64 {
	vec := make([]float64, s.inDim)
	types := map[string]int{"H": 1, "X": 2, "CNOT": 3, "RX": 4, "RZ": 5, "SWAP": 6, "CPHASE": 7, "MEASURE": 8, "DIFFUSION": 9, "COST_LAYER": 10, "RX_PARAM": 11}
	i := 0
	for _, g := range circuit {
		idx := 0
		if v, ok := types[g.Name]; ok {
			idx = v
		}
		vec[i % s.inDim] += float64(len(g.Qubits)) * float64(idx)
		i++
		if i >= s.inDim {
			break
		}
	}
	// normalize
	sum := 0.0
	for _, v := range vec {
		sum += v
	}
	if sum > 0 {
		for i := range vec {
			vec[i] = vec[i] / sum
		}
	}
	return vec
}

func softmax(xs []float64) []float64 {
	max := xs[0]
	for _, v := range xs {
		if v > max {
			max = v
		}
	}
	exp := make([]float64, len(xs))
	sum := 0.0
	for i, v := range xs {
		ev := math.Exp(v - max)
		exp[i] = ev
		sum += ev
	}
	out := make([]float64, len(xs))
	for i := range xs {
		out[i] = exp[i] / sum
	}
	return out
}

func entropy(probs []float64) float64 {
	ent := 0.0
	for _, p := range probs {
		if p > 0 {
			ent -= p * math.Log(p)
		}
	}
	return ent
}

func (s *SurrogateInProc) Predict(circuit []Gate) (map[string]float64, float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vec := s.vectorize(circuit)
	// linear logits
	logits := make([]float64, s.outDim)
	for i := 0; i < s.outDim; i++ {
		sum := 0.0
		for j := 0; j < s.inDim; j++ {
			sum += s.weights[i][j] * vec[j]
		}
		logits[i] = sum
	}
	probs := softmax(logits)
	// build output map
	out := make(map[string]float64)
	for i, p := range probs {
		out[fmt.Sprintf("prob_%d", i)] = p
	}
	// confidence heuristic: 1 - normalized entropy
	ent := entropy(probs)
	maxEnt := math.Log(float64(len(probs)))
	conf := 0.0
	if maxEnt > 0 {
		conf = math.Max(0.0, 1.0 - ent/maxEnt)
	}
	return out, conf, nil
}

func (s *SurrogateInProc) Train(batch []SurrogateDatum) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// prepare X, Y
	if len(batch) == 0 {
		return errors.New("empty batch")
	}
	X := make([][]float64, 0, len(batch))
	Y := make([][]float64, 0, len(batch))
	for _, d := range batch {
		vec := s.vectorize(d.Circuit)
		X = append(X, vec)
		tgt := make([]float64, s.outDim)
		for k, v := range d.Labels {
			if strings.HasPrefix(k, "prob_") {
				var idx int
				fmt.Sscanf(k, "prob_%d", &idx)
				if idx >= 0 && idx < s.outDim {
					tgt[idx] = v
				}
			}
		}
		// normalize target if sum>0
		sum := 0.0
		for _, val := range tgt {
			sum += val
		}
		if sum > 0 {
			for i := range tgt {
				tgt[i] = tgt[i] / sum
			}
		} else {
			// fallback: uniform
			for i := range tgt {
				tgt[i] = 1.0 / float64(s.outDim)
			}
		}
		Y = append(Y, tgt)
	}
	// simple SGD for few epochs
	epochs := 12
	for e := 0; e < epochs; e++ {
		for i := 0; i < len(X); i++ {
			x := X[i]
			t := Y[i]
			// forward logits
			logits := make([]float64, s.outDim)
			for r := 0; r < s.outDim; r++ {
				sum := 0.0
				for j := 0; j < s.inDim; j++ {
					sum += s.weights[r][j] * x[j]
				}
				logits[r] = sum
			}
			preds := softmax(logits)
			// gradient for cross-entropy: grad = pred - target
			for r := 0; r < s.outDim; r++ {
				grad := preds[r] - t[r]
				// update weights
				for j := 0; j < s.inDim; j++ {
					s.weights[r][j] -= s.lr * grad * x[j]
				}
			}
		}
	}
	return nil
}

// ---------------- Local Statevector Backend (pure Go) ----------------

// LocalStatevectorBackend: supports gates: H, X, Z, RX, RZ, CNOT, CPHASE, SWAP, CNOT, RY (approx via RX/RZ).
type LocalStatevectorBackend struct {
	name string
}

func NewLocalStatevectorBackend() *LocalStatevectorBackend {
	return &LocalStatevectorBackend{name: "local-statevector"}
}

func (l *LocalStatevectorBackend) Name() string { return l.name }
func (l *LocalStatevectorBackend) Supports(qubits int) bool {
	// conservative limit to avoid OOM - default ~24 qubits (16M amplitudes)
	return qubits <= 24
}

func (l *LocalStatevectorBackend) RunCircuit(ctx context.Context, nQubits int, gates []Gate, shots int) (map[int]int, error) {
	state, err := l.RunStatevector(ctx, nQubits, gates)
	if err != nil {
		return nil, err
	}
	// sample shots from distribution
	n := 1 << uint(nQubits)
	probs := make([]float64, n)
	for i := 0; i < n; i++ {
		probs[i] = cmplx.Abs(state[i]) * cmplx.Abs(state[i])
	}
	// normalize
	sum := 0.0
	for _, p := range probs {
		sum += p
	}
	if sum == 0 {
		return nil, errors.New("zero probability vector")
	}
	for i := range probs {
		probs[i] = probs[i] / sum
	}
	out := make(map[int]int)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// cumulative
	cum := make([]float64, n)
	acc := 0.0
	for i := 0; i < n; i++ {
		acc += probs[i]
		cum[i] = acc
	}
	if shots <= 0 {
		shots = 1024
	}
	for s := 0; s < shots; s++ {
		p := rnd.Float64()
		lo, hi := 0, n-1
		for lo < hi {
			mid := (lo + hi) / 2
			if cum[mid] < p {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		out[lo]++
	}
	return out, nil
}

func (l *LocalStatevectorBackend) RunStatevector(ctx context.Context, nQubits int, gates []Gate) ([]complex128, error) {
	if nQubits <= 0 {
		return nil, errors.New("nQubits must be >0")
	}
	if nQubits > 24 {
		return nil, fmt.Errorf("nQubits too large for local backend: %d", nQubits)
	}
	N := 1 << uint(nQubits)
	state := make([]complex128, N)
	// start in |0...0>
	state[0] = complex(1, 0)
	// apply gates in order
	for _, g := range gates {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		switch strings.ToUpper(g.Name) {
		case "H":
			if len(g.Qubits) != 1 {
				return nil, fmt.Errorf("H requires 1 qubit")
			}
			applySingleQubitUnitary(state, nQubits, g.Qubits[0], [2][2]complex128{
				{complex(1/math.Sqrt2, 0), complex(1/math.Sqrt2, 0)},
				{complex(1/math.Sqrt2, 0), complex(-1/math.Sqrt2, 0)},
			})
		case "X":
			if len(g.Qubits) != 1 {
				return nil, fmt.Errorf("X requires 1 qubit")
			}
			applySingleQubitUnitary(state, nQubits, g.Qubits[0], [2][2]complex128{
				{0, 1},
				{1, 0},
			})
		case "Z":
			if len(g.Qubits) != 1 {
				return nil, fmt.Errorf("Z requires 1 qubit")
			}
			applySingleQubitUnitary(state, nQubits, g.Qubits[0], [2][2]complex128{
				{1, 0},
				{0, -1},
			})
		case "RX":
			if len(g.Qubits) != 1 {
				return nil, fmt.Errorf("RX requires 1 qubit")
			}
			theta := 0.0
			if len(g.Params) > 0 {
				theta = g.Params[0]
			}
			// RX = exp(-i X theta/2) = cos(t/2) I - i sin(t/2) X
			c := math.Cos(theta/2)
			sn := -math.Sin(theta/2)
			applySingleQubitUnitary(state, nQubits, g.Qubits[0], [2][2]complex128{
				{complex(c, 0), complex(0, sn)},
				{complex(0, sn), complex(c, 0)},
			})
		case "RZ":
			if len(g.Qubits) != 1 {
				return nil, fmt.Errorf("RZ requires 1 qubit")
			}
			phi := 0.0
			if len(g.Params) > 0 {
				phi = g.Params[0]
			}
			applySingleQubitUnitary(state, nQubits, g.Qubits[0], [2][2]complex128{
				{complex(math.Cos(phi/2), -math.Sin(phi/2)), 0},
				{0, complex(math.Cos(phi/2), math.Sin(phi/2))},
			})
		case "CNOT":
			if len(g.Qubits) != 2 {
				return nil, fmt.Errorf("CNOT requires 2 qubits")
			}
			applyCNOT(state, nQubits, g.Qubits[0], g.Qubits[1])
		case "CPHASE":
			if len(g.Qubits) != 2 {
				return nil, fmt.Errorf("CPHASE requires 2 qubits")
			}
			angle := 0.0
			if len(g.Params) > 0 {
				angle = g.Params[0]
			}
			applyControlledPhase(state, nQubits, g.Qubits[0], g.Qubits[1], angle)
		case "SWAP":
			if len(g.Qubits) != 2 {
				return nil, fmt.Errorf("SWAP requires 2 qubits")
			}
			applySWAP(state, nQubits, g.Qubits[0], g.Qubits[1])
		case "DIFFUSION":
			// naive diffusion: apply H^n, X^n, multi-controlled Z, X^n, H^n
			// Implementing full multi-controlled Z is heavy; approximate by inversion about mean via amplitudes.
			inversionAboutMean(state)
		default:
			// unsupported gate: ignore or error
			// we'll ignore unknown gates to allow placeholders (COST_LAYER etc.)
		}
	}
	return state, nil
}

// ---------------- low-level state manipulations ----------------

func applySingleQubitUnitary(state []complex128, nQubits int, target int, M [2][2]complex128) {
	N := len(state)
	mask := 1 << uint(target)
	// iterate in blocks
	for i := 0; i < N; i++ {
		if i&mask == 0 {
			j := i | mask
			a := state[i]
			b := state[j]
			state[i] = M[0][0]*a + M[0][1]*b
			state[j] = M[1][0]*a + M[1][1]*b
		}
	}
}

func applyCNOT(state []complex128, nQubits int, control int, target int) {
	N := len(state)
	cmask := 1 << uint(control)
	tmask := 1 << uint(target)
	for i := 0; i < N; i++ {
		if i&cmask != 0 {
			// flip target bit
			j := i ^ tmask
			// swap amplitudes between i and j if target bit differs?
			// correct operation: amplitude at basis index with control=1 and target=0 moves to control=1,target=1, etc.
			// Implementation: if target bit is 0, move amplitude to flipped index
			if i&tmask == 0 {
				// swap state[i] and state[i|tmask]
				tmp := state[i]
				state[i] = state[i|tmask]
				state[i|tmask] = tmp
			}
		}
	}
}

func applyControlledPhase(state []complex128, nQubits int, control int, target int, angle float64) {
	N := len(state)
	mask := (1 << uint(control)) | (1 << uint(target))
	phase := complex(math.Cos(angle), math.Sin(angle))
	for i := 0; i < N; i++ {
		if i&mask == mask {
			// both control and target are 1
			state[i] *= phase
		}
	}
}

func applySWAP(state []complex128, nQubits int, a int, b int) {
	if a == b {
		return
	}
	N := len(state)
	amask := 1 << uint(a)
	bmask := 1 << uint(b)
	for i := 0; i < N; i++ {
		// indices differing in bits a and b
		bita := (i >> uint(a)) & 1
		bitb := (i >> uint(b)) & 1
		if bita != bitb {
			j := i ^ amask ^ bmask
			if i < j {
				tmp := state[i]
				state[i] = state[j]
				state[j] = tmp
			}
		}
	}
}

func inversionAboutMean(state []complex128) {
	N := len(state)
	// compute mean amplitude
	sum := complex(0.0, 0.0)
	for i := 0; i < N; i++ {
		sum += state[i]
	}
	mean := sum / complex(float64(N), 0)
	for i := 0; i < N; i++ {
		state[i] = complex(2, 0)*mean - state[i]
	}
}

// ---------------- cuQuantum stub (safe) ----------------

// CUQuantumStub used as placeholder when accelerated backend not integrated
type CUQuantumStub struct {
	name string
}

func NewCUQuantumStub() *CUQuantumStub { return &CUQuantumStub{name: "cuquantum-stub"} }
func (c *CUQuantumStub) Name() string { return c.name }
func (c *CUQuantumStub) Supports(qubits int) bool {
	return false // not available
}
func (c *CUQuantumStub) RunCircuit(ctx context.Context, nQubits int, gates []Gate, shots int) (map[int]int, error) {
	return nil, errors.New("cuQuantum backend stub: not available in this build")
}
func (c *CUQuantumStub) RunStatevector(ctx context.Context, nQubits int, gates []Gate) ([]complex128, error) {
	return nil, errors.New("cuQuantum backend stub: not available in this build")
}

// ---------------- Circuit builders (QFT, Grover, QAOA, VQE) ----------------

func BuildQFT(n int) []Gate {
	gates := []Gate{}
	for j := 0; j < n; j++ {
		gates = append(gates, Gate{Name: "H", Qubits: []int{j}})
		for k := 2; j+k-1 < n+1; k++ {
			target := j + k - 1
			angle := math.Pi / math.Pow(2, float64(k-1))
			gates = append(gates, Gate{Name: "CPHASE", Qubits: []int{j, target}, Params: []float64{angle}})
		}
	}
	for i := 0; i < n/2; i++ {
		gates = append(gates, Gate{Name: "SWAP", Qubits: []int{i, n - i - 1}})
	}
	return gates
}

func BuildGroverSkeleton(n int, target int) []Gate {
	g := []Gate{}
	for i := 0; i < n; i++ {
		g = append(g, Gate{Name: "H", Qubits: []int{i}})
	}
	g = append(g, Gate{Name: "DIFFUSION", Qubits: []int{}})
	return g
}

func BuildQAOASkeleton(n int, p int) []Gate {
	g := []Gate{}
	for i := 0; i < n; i++ {
		g = append(g, Gate{Name: "H", Qubits: []int{i}})
	}
	for layer := 0; layer < p; layer++ {
		g = append(g, Gate{Name: "COST_LAYER", Qubits: []int{}})
		for i := 0; i < n; i++ {
			g = append(g, Gate{Name: "RX", Qubits: []int{i}, Params: []float64{0.1}})
		}
	}
	return g
}

func BuildVQESkeleton(n int, depth int) []Gate {
	g := []Gate{}
	for d := 0; d < depth; d++ {
		for i := 0; i < n; i++ {
			g = append(g, Gate{Name: "RX", Qubits: []int{i}, Params: []float64{0.2}})
			g = append(g, Gate{Name: "RZ", Qubits: []int{i}, Params: []float64{0.3}})
		}
		for i := 0; i < n-1; i++ {
			g = append(g, Gate{Name: "CNOT", Qubits: []int{i, i + 1}})
		}
	}
	return g
}

// ---------------- Example HTTP wrapper (optional) ----------------

// Minimal HTTP wrapper exposing a few endpoints so an AI or remote component can call the engine.
// This is provided as a convenience; you may integrate with your own HTTP/gRPC layer.

type HTTPBridge struct {
	Engine *MetaQuantumEngine
	mux    *http.ServeMux
	srv    *http.Server
}

func NewHTTPBridge(engine *MetaQuantumEngine, addr string) *HTTPBridge {
	mux := http.NewServeMux()
	h := &HTTPBridge{Engine: engine, mux: mux}
	mux.HandleFunc("/submit", h.handleSubmit)   // POST JSON {task,n_qubits,circuit,shots}
	mux.HandleFunc("/status", h.handleStatus)   // GET ?id=
	mux.HandleFunc("/list_backends", h.handleListBackends) // GET
	srv := &http.Server{Addr: addr, Handler: mux}
	h.srv = srv
	return h
}

func (h *HTTPBridge) Start() error {
	go h.srv.ListenAndServe()
	return nil
}
func (h *HTTPBridge) Stop(ctx context.Context) error {
	return h.srv.Shutdown(ctx)
}

type submitReq struct {
	Task    TaskType   `json:"task"`
	NQubits int        `json:"n_qubits"`
	Circuit []Gate     `json:"circuit"`
	Shots   int        `json:"shots"`
	Input   map[string]float64 `json:"input,omitempty"`
}

func (h *HTTPBridge) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req submitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := h.Engine.SubmitJob(r.Context(), req.Task, req.NQubits, req.Circuit, req.Shots, req.Input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"job_id": id})
}

func (h *HTTPBridge) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	job, err := h.Engine.GetJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(job)
}

func (h *HTTPBridge) handleListBackends(w http.ResponseWriter, r *http.Request) {
	list := h.Engine.ListBackends()
	json.NewEncoder(w).Encode(map[string]interface{}{"backends": list})
}

/*
---------------- USAGE EXAMPLE (Go):

ctx := context.Background()
engine := quantum.NewMetaQuantumEngine()

// optional: register cuQuantum accelerated backend if implemented
// engine.RegisterBackend(NewCUQuantumBackend(...))

// create a circuit
circuit := quantum.BuildQAOASkeleton(8, 1)

// Submit
jobID, _ := engine.SubmitJob(ctx, quantum.TaskOptimization, 8, circuit, 1024, nil)

// Poll
for {
    j, _ := engine.GetJob(jobID)
    fmt.Println("status:", j.Status)
    if j.Status == "done" || j.Status == "failed" { break }
    time.Sleep(300 * time.Millisecond)
}
j, _ := engine.GetJob(jobID)
fmt.Printf("result: %+v\n", j.Result)

----------------
*/

// End of file
  