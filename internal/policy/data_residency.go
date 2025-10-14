// internal/policy/data_residency.go
// Data Residency Enforcer — Intelligent Geo-Legal Compliance Engine
// يفرض سياسات بقاء البيانات داخل المناطق القانونية المسموح بها (GDPR، قوانين البيانات الوطنية)
// مزود بقدرات تحليل مخاطر لحظية، سجل تدقيق، تنبيهات، وتوصية بالمنطقة الآمنة.
// يتكامل مع internal/geo.LocationManager (يقرأ المواقع المسجلة للعقد/الخدمات).

package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"internal/geo"
)

// ---------------- Types ----------------

// ResidencyRule: تم توسيعها لتشمل دول، مراجع قانونية، ومستوى حساسية بيانات افتراضي
type ResidencyRule struct {
	ID          string            `json:"id"`
	Region      string            `json:"region"`                 // مثال: "EU", "US", "MENA"
	Countries   []string          `json:"countries,omitempty"`    // دول داخل المنطقة (ISO codes)؛ إن كانت فارغة => كل دول المنطقة
	DataTypes   []string          `json:"data_types"`             // ["user_data","logs",...]
	Strict      bool              `json:"strict"`                 // true => لا يسمح بالخروج إطلاقًا
	Notes       string            `json:"notes,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	LegalRefs   map[string]string `json:"legal_refs,omitempty"`   // مثال: {"GDPR":"Art.44"}
	Sensitivity float64           `json:"sensitivity,omitempty"`  // 0.0..1.0 (biometrics ~0.9)
}

// EnforcementLog: سجل عملية فحص/قرار
type EnforcementLog struct {
	ID          string                 `json:"id"`
	SourceID    string                 `json:"source_id,omitempty"`
	TargetID    string                 `json:"target_id,omitempty"`
	RegionFrom  string                 `json:"region_from"`
	RegionTo    string                 `json:"region_to"`
	CountryFrom string                 `json:"country_from"`
	CountryTo   string                 `json:"country_to"`
	DataType    string                 `json:"data_type"`
	Action      string                 `json:"action"`     // "allowed", "blocked", "warn"
	Reason      string                 `json:"reason"`
	RiskScore   float64                `json:"risk_score"` // 0.0..1.0
	Timestamp   time.Time              `json:"timestamp"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// Notifier callback type: يستدعى عند حدوث block/warn/allow
type Notifier func(log EnforcementLog)

// ---------------- Engine ----------------

type DataResidencyEnforcer struct {
	mu                 sync.RWMutex
	rules              map[string]ResidencyRule
	history            []EnforcementLog
	notifiers          []Notifier
	countryRisk        map[string]float64
	defaultSensitivity map[string]float64
	maxHistorySize     int
	locationManager    *geo.LocationManager
}

// NewDataResidencyEnforcer — يُنشئ المحرك مع إمكانية تمرير LocationManager (يمكن أن يكون nil)
func NewDataResidencyEnforcer(locMgr *geo.LocationManager) *DataResidencyEnforcer {
	return &DataResidencyEnforcer{
		rules:   make(map[string]ResidencyRule),
		history: make([]EnforcementLog, 0, 1024),
		notifiers: make([]Notifier, 0),
		countryRisk: map[string]float64{
			"US": 0.20, "GB": 0.25, "DE": 0.20, "FR": 0.25,
			"CN": 0.80, "RU": 0.80, "IR": 0.90, "BR": 0.40,
			"IN": 0.50, "AE": 0.35,
		},
		defaultSensitivity: map[string]float64{
			"biometrics": 0.95,
			"user_data":  0.60,
			"payments":   0.90,
			"logs":       0.20,
			"health":     0.95,
		},
		maxHistorySize:  10000,
		locationManager: locMgr,
	}
}

// ---------------- Helpers ----------------

func (d *DataResidencyEnforcer) pushLog(l EnforcementLog) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// maintain bounded history
	if d.maxHistorySize <= 0 {
		d.maxHistorySize = 10000
	}
	if len(d.history) >= d.maxHistorySize {
		// drop oldest
		d.history = d.history[1:]
	}
	d.history = append(d.history, l)
	// notify asynchronously
	for _, n := range d.notifiers {
		go func(nn Notifier, lg EnforcementLog) {
			defer func() { _ = recover() }()
			nn(lg)
		}(n, l)
	}
}

func containsIgnoreCase(arr []string, v string) bool {
	for _, x := range arr {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func mathMin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// resolveLocationByID: uses LocationManager.ListAll to find service by ID (safe if LocationManager has no Get)
func (d *DataResidencyEnforcer) resolveLocationByID(id string) (geo.ServiceLocation, bool) {
	if d.locationManager == nil {
		return geo.ServiceLocation{}, false
	}
	locs := d.locationManager.ListAll()
	for _, l := range locs {
		if l.ID == id {
			return l, true
		}
	}
	return geo.ServiceLocation{}, false
}

// ---------------- Rules CRUD (يحافظ على الواجهات الأصلية) ----------------

func (d *DataResidencyEnforcer) AddOrUpdateRule(rule ResidencyRule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	// sanitize sensitivity
	if rule.Sensitivity < 0 || rule.Sensitivity > 1 {
		rule.Sensitivity = 0 // يعني استخدم الافتراضي لاحقاً
	}
	d.rules[rule.ID] = rule
}

func (d *DataResidencyEnforcer) RemoveRule(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.rules, id)
}

func (d *DataResidencyEnforcer) GetRule(id string) (ResidencyRule, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.rules[id]
	return r, ok
}

func (d *DataResidencyEnforcer) ListRules() []ResidencyRule {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]ResidencyRule, 0, len(d.rules))
	for _, v := range d.rules {
		out = append(out, v)
	}
	return out
}

// ---------------- Notifications & Config ----------------

func (d *DataResidencyEnforcer) RegisterNotifier(n Notifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifiers = append(d.notifiers, n)
}

func (d *DataResidencyEnforcer) UpdateCountryRisk(countryCode string, risk float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.countryRisk == nil {
		d.countryRisk = make(map[string]float64)
	}
	if risk < 0 {
		risk = 0
	}
	if risk > 1 {
		risk = 1
	}
	d.countryRisk[strings.ToUpper(countryCode)] = risk
}

// ---------------- Risk Evaluation (التحليل اللحظي) ----------------

// EvaluateRisk يحسب درجة مخاطر نقل البيانات من -> إلى بالنسبة لنوع بيانات معين
// يعيد score (0..1) و explanation موجز
func (d *DataResidencyEnforcer) EvaluateRisk(regionFrom, regionTo, countryFrom, countryTo, dataType string) (float64, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// حساسية افتراضية
	sensitivity := 0.5
	if r := d.findRuleForDataInRegion(regionFrom, dataType); r != nil {
		if r.Sensitivity > 0 {
			sensitivity = r.Sensitivity
		} else if v, ok := d.defaultSensitivity[dataType]; ok {
			sensitivity = v
		}
	} else {
		if v, ok := d.defaultSensitivity[dataType]; ok {
			sensitivity = v
		}
	}

	// مخاطرة الوجهة
	crisk := 0.5
	if v, ok := d.countryRisk[strings.ToUpper(countryTo)]; ok {
		crisk = v
	}

	// سجل الحوادث (آخر 30 يوم) — حساب عدد التحذيرات/الحظر الأخيرة
	events := d.recentEventsCount(regionFrom, 30*24*time.Hour)
	hfactor := float64(events)
	if hfactor > 10 {
		hfactor = 10
	}
	hfactor = hfactor / 10.0 // 0..1

	// عقوبة عبور المناطق
	cross := 0.0
	if !strings.EqualFold(regionFrom, regionTo) {
		cross = 0.25
	}

	// strict rule penalty
	strictPenalty := 0.0
	if r := d.findRuleForDataInRegion(regionFrom, dataType); r != nil && r.Strict {
		if !strings.EqualFold(regionFrom, regionTo) {
			strictPenalty = 0.6
		}
		if r.Countries != nil && len(r.Countries) > 0 && !containsIgnoreCase(r.Countries, countryTo) {
			strictPenalty = mathMin(1.0, strictPenalty+0.25)
		}
	}

	// combine weights
	base := sensitivity*0.6 + crisk*0.3 + hfactor*0.1
	score := base + cross + strictPenalty
	if score > 1.0 {
		score = 1.0
	}

	expl := fmt.Sprintf("sensitivity=%.2f, countryRisk=%.2f, history=%.2f, cross=%.2f, strict=%.2f => score=%.3f",
		sensitivity, crisk, hfactor, cross, strictPenalty, score)
	return score, expl
}

func (d *DataResidencyEnforcer) recentEventsCount(region string, window time.Duration) int {
	cut := time.Now().Add(-window)
	cnt := 0
	d.mu.RLock()
	defer d.mu.RUnlock()
	for i := len(d.history) - 1; i >= 0; i-- {
		if d.history[i].Timestamp.Before(cut) {
			break
		}
		if strings.EqualFold(d.history[i].RegionFrom, region) && (d.history[i].Action == "blocked" || d.history[i].Action == "warn") {
			cnt++
		}
	}
	return cnt
}

func (d *DataResidencyEnforcer) findRuleForDataInRegion(region, dataType string) *ResidencyRule {
	for _, r := range d.rules {
		if strings.EqualFold(r.Region, region) && containsIgnoreCase(r.DataTypes, dataType) {
			rr := r // copy
			return &rr
		}
	}
	return nil
}

// ---------------- EnforceTransfer (الإصدار المحسن) ----------------

// EnforceTransfer: النسخة الموسعة للتحقق من نقل بيانات من منطقة/دولة إلى أخرى.
// تعيد: allowed?, reason, riskScore
func (d *DataResidencyEnforcer) EnforceTransfer(regionFrom, regionTo, countryFrom, countryTo, dataType string) (bool, string, float64) {
	score, explanation := d.EvaluateRisk(regionFrom, regionTo, countryFrom, countryTo, dataType)

	action := "allowed"
	if score >= 0.75 {
		action = "blocked"
	} else if score >= 0.5 {
		action = "warn"
	}

	// check strict rules first
	if r := d.findRuleForDataInRegion(regionFrom, dataType); r != nil {
		if r.Strict && !strings.EqualFold(regionFrom, regionTo) {
			reason := fmt.Sprintf("قاعدة %s تمنع خروج %s من %s (صارمة)", r.ID, dataType, regionFrom)
			log := EnforcementLog{
				ID:          fmt.Sprintf("log-%d", time.Now().UnixNano()),
				RegionFrom:  regionFrom,
				RegionTo:    regionTo,
				CountryFrom: countryFrom,
				CountryTo:   countryTo,
				DataType:    dataType,
				Action:      "blocked",
				Reason:      reason,
				RiskScore:   score,
				Timestamp:   time.Now(),
			}
			d.pushLog(log)
			return false, reason, score
		}
		if len(r.Countries) > 0 && !containsIgnoreCase(r.Countries, countryTo) {
			reason := fmt.Sprintf("الوجهة %s غير واردة في قائمة الدول المسموحة في القاعدة %s", countryTo, r.ID)
			log := EnforcementLog{
				ID:          fmt.Sprintf("log-%d", time.Now().UnixNano()),
				RegionFrom:  regionFrom,
				RegionTo:    regionTo,
				CountryFrom: countryFrom,
				CountryTo:   countryTo,
				DataType:    dataType,
				Action:      action,
				Reason:      reason,
				RiskScore:   score,
				Timestamp:   time.Now(),
			}
			d.pushLog(log)
			allowed := action == "allowed"
			return allowed, reason, score
		}
	}

	// default
	reason := fmt.Sprintf("Risk eval: %s", explanation)
	log := EnforcementLog{
		ID:          fmt.Sprintf("log-%d", time.Now().UnixNano()),
		RegionFrom:  regionFrom,
		RegionTo:    regionTo,
		CountryFrom: countryFrom,
		CountryTo:   countryTo,
		DataType:    dataType,
		Action:      action,
		Reason:      reason,
		RiskScore:   score,
		Timestamp:   time.Now(),
		Meta:        map[string]interface{}{"explanation": explanation},
	}
	d.pushLog(log)
	allowed := action == "allowed"
	return allowed, reason, score
}

// ---------------- EnforceBetweenServices (يتكامل مع geo.LocationManager) ----------------

// EnforceBetweenServices: تحقّق قانوني قبل نقل بيانات بين خدمتين/عقدتين معرفتيْن بالـID.
// يعيد: allowed?, reason, riskScore
func (d *DataResidencyEnforcer) EnforceBetweenServices(sourceID, targetID, dataType string) (bool, string, float64) {
	// ensure location manager present
	if d.locationManager == nil {
		reason := "LocationManager غير مهيّأ في DataResidencyEnforcer"
		return false, reason, 1.0
	}
	// resolve locations
	src, ok1 := d.resolveLocationByID(sourceID)
	dst, ok2 := d.resolveLocationByID(targetID)
	if !ok1 || !ok2 {
		reason := "تعذر إيجاد موقع إحدى العقد (source/target) في LocationManager"
		return false, reason, 1.0
	}
	// get countries from Meta if available (fallback to empty)
	countryFrom := ""
	countryTo := ""
	if v, ok := src.Meta["country"].(string); ok {
		countryFrom = v
	}
	if v, ok := dst.Meta["country"].(string); ok {
		countryTo = v
	}
	allowed, reason, score := d.EnforceTransfer(src.Region, dst.Region, countryFrom, countryTo, dataType)

	// augment log with source/target IDs
	// last pushLog already added a log; we add one more with IDs for traceability
	log := EnforcementLog{
		ID:          fmt.Sprintf("log-%d", time.Now().UnixNano()),
		SourceID:    sourceID,
		TargetID:    targetID,
		RegionFrom:  src.Region,
		RegionTo:    dst.Region,
		CountryFrom: countryFrom,
		CountryTo:   countryTo,
		DataType:    dataType,
		Action:      map[bool]string{true: "allowed", false: "blocked"}[allowed],
		Reason:      reason,
		RiskScore:   score,
		Timestamp:   time.Now(),
	}
	d.pushLog(log)

	return allowed, reason, score
}

// ---------------- Backwards-compatible Enforce ----------------

// Enforce(region, dataType) bool — يحافظ على الواجهة القديمة
func (d *DataResidencyEnforcer) Enforce(region, dataType string) bool {
	allowed, _, _ := d.EnforceTransfer(region, region, "", "", dataType)
	return allowed
}

// ---------------- Audit / Export / Utilities ----------------

func (d *DataResidencyEnforcer) History() []EnforcementLog {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]EnforcementLog, len(d.history))
	copy(out, d.history)
	return out
}

func (d *DataResidencyEnforcer) ClearHistory() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.history = make([]EnforcementLog, 0)
}

func (d *DataResidencyEnforcer) ExportRulesJSON() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rules := make([]ResidencyRule, 0, len(d.rules))
	for _, r := range d.rules {
		rules = append(rules, r)
	}
	return json.MarshalIndent(rules, "", "  ")
}

func (d *DataResidencyEnforcer) LoadRulesJSON(raw []byte) error {
	var rules []ResidencyRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range rules {
		if r.CreatedAt.IsZero() {
			r.CreatedAt = time.Now()
		}
		r.UpdatedAt = time.Now()
		d.rules[r.ID] = r
	}
	return nil
}

// RecommendSafeRegion يقترح منطقة أقل مخاطرة لتخزين نوع بيانات معين استنادًا لقواعد متاحة
func (d *DataResidencyEnforcer) RecommendSafeRegion(dataType string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, r := range d.rules {
		if containsIgnoreCase(r.DataTypes, dataType) && !r.Strict {
			return r.Region
		}
	}
	// fallback الى أقل دولة مخاطرة
	best := "GLOBAL"
	bestRisk := 2.0
	for c, r := range d.countryRisk {
		if r < bestRisk {
			bestRisk = r
			best = c
		}
	}
	return best
}
  