package services

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"
	"nebula/internal/store"
)

type ResourceMetadata struct {
	Provider        string
	AccountID       uint
	CPU             int
	RAM             int
	GPU             int
	Region          string
	Latency         int
	Type            string
	CostPerHour     float64
	UptimePercent   float64
	PowerEfficiency float64
	AvailableCPU    int
	AvailableRAM    int
	AvailableGPU    int
	LastUpdated     time.Time
}

type ResourceMatch struct {
	Meta  ResourceMetadata
	Score float64
}

type Requirements struct {
	CPU      int
	GPU      int
	RAM      int
	Region   string
	Type     string
	MaxCost  float64
	MinUptime float64
}

var (
	cacheTTLSeconds = func() int {
		if v := os.Getenv("SRM_CACHE_TTL"); v != "" {
			if t, err := strconv.Atoi(v); err == nil && t > 0 {
				return t
			}
		}
		return 10
	}()
)

type cacheEntry struct {
	metas  []ResourceMetadata
	expire time.Time
}

var (
	resourceCache   = cacheEntry{}
	cacheLock       sync.RWMutex
	reservationLock sync.Mutex
	reservations    = map[uint]reservation{} // accountID -> reservation totals
)

type reservation struct {
	CPU int
	GPU int
	RAM int
	At  time.Time
}

func fetchResourcesFromDB(db *gorm.DB) ([]ResourceMetadata, error) {
	var providers []store.ProviderAccount
	if err := db.Find(&providers).Error; err != nil {
		return nil, err
	}
	metas := make([]ResourceMetadata, 0, len(providers))
	for _, p := range providers {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(p.QuotaJSON), &raw)
		meta := ResourceMetadata{
			Provider:    p.Provider,
			AccountID:   p.ID,
			CPU:         toInt(raw["cpu"]),
			RAM:         toInt(raw["ram"]),
			GPU:         toInt(raw["gpu"]),
			Region:      toString(raw["region"]),
			Latency:     toInt(raw["latency"]),
			Type:        toString(raw["type"]),
			CostPerHour: toFloat(raw["cost_per_hour"]),
			UptimePercent: toFloat(raw["uptime_percent"]),
			PowerEfficiency: toFloat(raw["power_efficiency"]),
			LastUpdated: time.Now(),
		}
		res := currentReservation(p.ID)
		meta.AvailableCPU = max(0, meta.CPU-res.CPU)
		meta.AvailableRAM = max(0, meta.RAM-res.RAM)
		meta.AvailableGPU = max(0, meta.GPU-res.GPU)
		metas = append(metas, meta)
	}
	return metas, nil
}

func GetResources(db *gorm.DB) ([]ResourceMetadata, error) {
	cacheLock.RLock()
	if time.Now().Before(resourceCache.expire) && resourceCache.metas != nil {
		cached := resourceCache.metas
		cacheLock.RUnlock()
		return cloneMetas(cached), nil
	}
	cacheLock.RUnlock()

	cacheLock.Lock()
	defer cacheLock.Unlock()
	metas, err := fetchResourcesFromDB(db)
	if err != nil {
		return nil, err
	}
	resourceCache.metas = metas
	resourceCache.expire = time.Now().Add(time.Duration(cacheTTLSeconds) * time.Second)
	return cloneMetas(metas), nil
}

func MatchResources(db *gorm.DB, req map[string]interface{}) ([]ResourceMetadata, error) {
	parsed := parseReq(req)
	matches, err := MatchResourcesAdvanced(db, parsed)
	if err != nil {
		return nil, err
	}
	out := make([]ResourceMetadata, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Meta)
	}
	return out, nil
}

func MatchResourcesAdvanced(db *gorm.DB, req Requirements) ([]ResourceMatch, error) {
	metas, err := GetResources(db)
	if err != nil {
		return nil, err
	}
	candidates := make([]ResourceMatch, 0, len(metas))
	for _, m := range metas {
		if req.CPU > 0 && m.AvailableCPU < req.CPU {
			continue
		}
		if req.GPU > 0 && m.AvailableGPU < req.GPU {
			continue
		}
		if req.RAM > 0 && m.AvailableRAM < req.RAM {
			continue
		}
		if req.Region != "" && m.Region != req.Region {
			continue
		}
		if req.Type != "" && m.Type != req.Type {
			continue
		}
		if req.MaxCost > 0 && m.CostPerHour > 0 && m.CostPerHour > req.MaxCost {
			continue
		}
		if req.MinUptime > 0 && m.UptimePercent < req.MinUptime {
			continue
		}
		score := computeScore(m, req)
		candidates = append(candidates, ResourceMatch{Meta: m, Score: score})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})
	return candidates, nil
}

func computeScore(m ResourceMetadata, req Requirements) float64 {
	score := 0.0
	if req.CPU > 0 {
		score += float64(min(m.AvailableCPU, req.CPU)) * 2.0
	} else {
		score += float64(m.AvailableCPU) * 0.5
	}
	if req.GPU > 0 {
		score += float64(min(m.AvailableGPU, req.GPU)) * 4.0
	} else {
		score += float64(m.AvailableGPU) * 1.0
	}
	if req.RAM > 0 {
		score += float64(min(m.AvailableRAM, req.RAM)) * 0.5
	} else {
		score += float64(m.AvailableRAM) * 0.2
	}
	latencyScore := 100.0 - float64(m.Latency)
	if latencyScore < 0 {
		latencyScore = 0
	}
	score += latencyScore * 0.3
	if m.CostPerHour > 0 {
		costScore := 1.0 / (1.0 + m.CostPerHour)
		score += costScore * 50.0
	}
	score += m.UptimePercent * 0.2
	score += m.PowerEfficiency * 0.1
	if req.Region != "" && req.Region == m.Region {
		score += 20.0
	}
	if req.Type != "" && req.Type == m.Type {
		score += 10.0
	}
	score = score - math.Log1p(math.Max(0, float64(max(0, (req.CPU-m.AvailableCPU))))) * 5.0
	return score
}

func ReserveResource(db *gorm.DB, accountID uint, cpu int, gpu int, ram int) error {
	reservationLock.Lock()
	defer reservationLock.Unlock()
	res := reservations[accountID]
	if res.CPU+cpu > getTotalCPU(db, accountID) {
		return errors.New("insufficient cpu")
	}
	if res.GPU+gpu > getTotalGPU(db, accountID) {
		return errors.New("insufficient gpu")
	}
	if res.RAM+ram > getTotalRAM(db, accountID) {
		return errors.New("insufficient ram")
	}
	res.CPU += cpu
	res.GPU += gpu
	res.RAM += ram
	res.At = time.Now()
	reservations[accountID] = res
	invalidateCache()
	return nil
}

func ReleaseResource(accountID uint, cpu int, gpu int, ram int) {
	reservationLock.Lock()
	defer reservationLock.Unlock()
	res := reservations[accountID]
	res.CPU = max(0, res.CPU-cpu)
	res.GPU = max(0, res.GPU-gpu)
	res.RAM = max(0, res.RAM-ram)
	res.At = time.Now()
	if res.CPU == 0 && res.GPU == 0 && res.RAM == 0 {
		delete(reservations, accountID)
	} else {
		reservations[accountID] = res
	}
	invalidateCache()
}

func currentReservation(accountID uint) reservation {
	reservationLock.Lock()
	defer reservationLock.Unlock()
	if r, ok := reservations[accountID]; ok {
		return r
	}
	return reservation{}
}

func getTotalCPU(db *gorm.DB, accountID uint) int {
	var p store.ProviderAccount
	if err := db.First(&p, accountID).Error; err != nil {
		return 0
	}
	var raw map[string]interface{}
	_ = json.Unmarshal([]byte(p.QuotaJSON), &raw)
	return toInt(raw["cpu"])
}

func getTotalGPU(db *gorm.DB, accountID uint) int {
	var p store.ProviderAccount
	if err := db.First(&p, accountID).Error; err != nil {
		return 0
	}
	var raw map[string]interface{}
	_ = json.Unmarshal([]byte(p.QuotaJSON), &raw)
	return toInt(raw["gpu"])
}

func getTotalRAM(db *gorm.DB, accountID uint) int {
	var p store.ProviderAccount
	if err := db.First(&p, accountID).Error; err != nil {
		return 0
	}
	var raw map[string]interface{}
	_ = json.Unmarshal([]byte(p.QuotaJSON), &raw)
	return toInt(raw["ram"])
}

func invalidateCache() {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	resourceCache.metas = nil
	resourceCache.expire = time.Time{}
}

func cloneMetas(src []ResourceMetadata) []ResourceMetadata {
	out := make([]ResourceMetadata, len(src))
	copy(out, src)
	return out
}

func parseReq(req map[string]interface{}) Requirements {
	r := Requirements{}
	if v, ok := req["cpu"]; ok {
		r.CPU = toInt(v)
	}
	if v, ok := req["gpu"]; ok {
		r.GPU = toInt(v)
	}
	if v, ok := req["ram"]; ok {
		r.RAM = toInt(v)
	}
	if v, ok := req["region"]; ok {
		r.Region = toString(v)
	}
	if v, ok := req["type"]; ok {
		r.Type = toString(v)
	}
	if v, ok := req["max_cost"]; ok {
		r.MaxCost = toFloat(v)
	}
	if v, ok := req["min_uptime"]; ok {
		r.MinUptime = toFloat(v)
	}
	return r
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case float32:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func toFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0.0
	}
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}