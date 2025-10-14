package billing

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ----------------- أنواع السجلات والفواتير -----------------

type UsageRecord struct {
	ProjectID   string                 `json:"project_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	Resource    string                 `json:"resource"` // "cpu"/"gpu"/"storage"/"net"
	Amount      float64                `json:"amount"`   // unit depends (e.g., seconds for cpu/gpu, bytes for storage/net)
	Unit        string                 `json:"unit,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
	CostPerUnit float64                `json:"cost_per_unit,omitempty"` // optional override for cost estimation
}

type Invoice struct {
	ID        string        `json:"id"`
	UserID    string        `json:"user_id"`
	Period    string        `json:"period"` // "2025-09"
	Total     float64       `json:"total"`
	Status    string        `json:"status"` // "pending", "paid"
	Records   []UsageRecord `json:"records"`
	CreatedAt time.Time     `json:"created_at"`
}

// Project aggregate summary (مبسط)
type ProjectAggregate struct {
	ProjectID     string             `json:"project_id"`
	ByResource    map[string]float64 `json:"by_resource"`
	EstimatedKWh  float64            `json:"estimated_kwh"`
	EstimatedCost float64            `json:"estimated_cost"`
	RecordsCount  int                `json:"records_count"`
	LastUpdated   time.Time          `json:"last_updated"`
}

// ----------------- المحرك -----------------

type BillingEngine struct {
	mu         sync.RWMutex
	records    []UsageRecord
	invoices   map[string]Invoice
	byProject  map[string]*ProjectAggregate
	persistPath string

	// energy & cost profiles (قابلة للتعديل)
	energyProfile map[string]float64
	costProfile   map[string]float64
}

// NewBillingEngine returns a new engine with sane defaults.
func NewBillingEngine() *BillingEngine {
	b := &BillingEngine{
		records:   make([]UsageRecord, 0, 1024),
		invoices:  make(map[string]Invoice),
		byProject: make(map[string]*ProjectAggregate),
		energyProfile: map[string]float64{
			// multipliers (kWh per unit) - افتراضية وقابلة للتعديل لاحقًا
			"cpu_seconds":    0.00005,        // kWh per CPU-second (~0.05 Wh/s as example)
			"gpu_seconds":    0.00025,        // kWh per GPU-second
			"storage_byte_s": 0.0000000002778, // kWh per byte-second (heuristic)
			"net_bytes":      0.0000000000833, // kWh per byte transferred (heuristic)
		},
		costProfile: map[string]float64{
			// default cost per unit (currency arbitrary) - تعديل حسب حاجتك
			"cpu_seconds":    0.000002,
			"gpu_seconds":    0.00002,
			"storage_byte_s": 0.00000000001,
			"net_bytes":      0.000000000005,
		},
	}
	return b
}

// ----------------- إعدادات قابلة للتهيئة -----------------

// SetPersistFile يحدد ملف الحفظ/التحميل
func (b *BillingEngine) SetPersistFile(path string) {
	b.mu.Lock()
	b.persistPath = path
	b.mu.Unlock()
}

// SetEnergyProfile يسمح بتعديل معاملات الطاقة (kWh per unit)
func (b *BillingEngine) SetEnergyProfile(profile map[string]float64) {
	b.mu.Lock()
	for k, v := range profile {
		b.energyProfile[k] = v
	}
	b.mu.Unlock()
}

// SetCostProfile يسمح بتعديل تكلفة الوحدة الافتراضية
func (b *BillingEngine) SetCostProfile(profile map[string]float64) {
	b.mu.Lock()
	for k, v := range profile {
		b.costProfile[k] = v
	}
	b.mu.Unlock()
}

// ----------------- الوظائف الأساسية المتوافقة -----------------

// AddUsage يضيف سجل استهلاك - هذه الواجهة متوافقة مع الكود القديم
func (b *BillingEngine) AddUsage(rec UsageRecord) {
	// ضمان الطابع الزمني
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	// استنتاج الوحدة إن لم تُعطَ
	if rec.Unit == "" {
		switch rec.Resource {
		case "cpu", "gpu":
			rec.Unit = "seconds"
		case "storage", "net":
			rec.Unit = "bytes"
		default:
			rec.Unit = "units"
		}
	}
	b.mu.Lock()
	b.records = append(b.records, rec)
	// تحديث التجميع السريع per-project
	if rec.ProjectID != "" {
		pa, ok := b.byProject[rec.ProjectID]
		if !ok {
			pa = &ProjectAggregate{
				ProjectID:  rec.ProjectID,
				ByResource: make(map[string]float64),
			}
			b.byProject[rec.ProjectID] = pa
		}
		pa.ByResource[rec.Resource] += rec.Amount
		pa.RecordsCount++
		pa.LastUpdated = time.Now().UTC()
		// نضيف تقديرات بسيطة الآن (تراكمية)
		k := b.estimateEnergyForRecordUnlocked(rec)
		c := b.estimateCostForRecordUnlocked(rec)
		pa.EstimatedKWh += k
		pa.EstimatedCost += c
	}
	b.mu.Unlock()
}

// AddUsageForProject اختصار لإضافة استخدام مرتبط بمشروع
func (b *BillingEngine) AddUsageForProject(projectID, userID, resource string, amount float64, unit string, meta map[string]interface{}, costPerUnit float64) {
	rec := UsageRecord{
		ProjectID:   projectID,
		UserID:      userID,
		Resource:    resource,
		Amount:      amount,
		Unit:        unit,
		Timestamp:   time.Now().UTC(),
		Meta:        meta,
		CostPerUnit: costPerUnit,
	}
	b.AddUsage(rec)
}

// GenerateInvoice — واجهة قديمة متوافقة.
// يبني Invoice كما في النسخة الأصلية، لكن إن وُجدت CostPerUnit سيُجمَع التكلفة بدل جمع الـAmount.
func (b *BillingEngine) GenerateInvoice(userID, period string) Invoice {
	b.mu.Lock()
	defer b.mu.Unlock()

	var invoice Invoice
	var total float64
	var recs []UsageRecord
	for _, r := range b.records {
		if r.UserID == userID && r.Timestamp.Format("2006-01") == period {
			// إذا وُجدت تكاليف معرّفة، نجمعها؛ وإلا نججمع الـAmount (للتوافق العكسي)
			if r.CostPerUnit > 0 {
				total += r.Amount * r.CostPerUnit
			} else {
				total += r.Amount
			}
			recs = append(recs, r)
		}
	}
	invoice = Invoice{
		ID:        userID + "-" + period,
		UserID:    userID,
		Period:    period,
		Total:     total,
		Status:    "pending",
		Records:   recs,
		CreatedAt: time.Now().UTC(),
	}
	b.invoices[invoice.ID] = invoice
	return invoice
}

// GetInvoice — يعيد الفاتورة إن وُجدت
func (b *BillingEngine) GetInvoice(id string) (Invoice, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	inv, ok := b.invoices[id]
	return inv, ok
}

// ----------------- استعلامات وتصدير -----------------

// GetProjectUsageSummary (نطاق زمني اختياري — if from==zero => منذ البداية)
func (b *BillingEngine) GetProjectUsageSummary(projectID string, from, to time.Time) (ProjectAggregate, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	agg := ProjectAggregate{
		ProjectID:  projectID,
		ByResource: make(map[string]float64),
	}
	var totalKwh float64
	var totalCost float64
	count := 0
	for _, r := range b.records {
		if r.ProjectID != projectID {
			continue
		}
		if !from.IsZero() && r.Timestamp.Before(from) {
			continue
		}
		if !to.IsZero() && r.Timestamp.After(to) {
			continue
		}
		agg.ByResource[r.Resource] += r.Amount
		totalKwh += b.estimateEnergyForRecordUnlocked(r)
		totalCost += b.estimateCostForRecordUnlocked(r)
		count++
	}
	agg.EstimatedKWh = totalKwh
	agg.EstimatedCost = totalCost
	agg.RecordsCount = count
	agg.LastUpdated = time.Now().UTC()
	return agg, nil
}

// ExportProjectJSON يحفظ تقرير JSON لفترة معينة
func (b *BillingEngine) ExportProjectJSON(path, projectID string, from, to time.Time) error {
	inv, err := b.generateInvoiceLikeUnlocked(projectID, from, to)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}

// ExportProjectCSV يصدّر سجلات المشروع كـ CSV مع تقديرات الطاقة والتكلفة
func (b *BillingEngine) ExportProjectCSV(path, projectID string, from, to time.Time) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()
	_ = writer.Write([]string{"timestamp", "project_id", "user_id", "resource", "amount", "unit", "estimated_kwh", "estimated_cost"})
	for _, r := range b.records {
		if r.ProjectID != projectID {
			continue
		}
		if !from.IsZero() && r.Timestamp.Before(from) {
			continue
		}
		if !to.IsZero() && r.Timestamp.After(to) {
			continue
		}
		k := b.estimateEnergyForRecordUnlocked(r)
		c := b.estimateCostForRecordUnlocked(r)
		row := []string{
			r.Timestamp.Format(time.RFC3339),
			r.ProjectID,
			r.UserID,
			r.Resource,
			fmt.Sprintf("%f", r.Amount),
			r.Unit,
			fmt.Sprintf("%f", k),
			fmt.Sprintf("%f", c),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// ----------------- حفظ/تحميل الحالة -----------------

// SaveToFile يحفظ السجلات وملف التعريفات
func (b *BillingEngine) SaveToFile(path string) error {
	b.mu.RLock()
	tmp := struct {
		Records       []UsageRecord          `json:"records"`
		Invoices      map[string]Invoice     `json:"invoices"`
		EnergyProfile map[string]float64     `json:"energy_profile"`
		CostProfile   map[string]float64     `json:"cost_profile"`
	}{
		Records:       b.records,
		Invoices:      b.invoices,
		EnergyProfile: b.energyProfile,
		CostProfile:   b.costProfile,
	}
	b.mu.RUnlock()

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(tmp)
}

// LoadFromFile يحمّل الحالة (دمج بسيط)
func (b *BillingEngine) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	tmp := struct {
		Records       []UsageRecord      `json:"records"`
		Invoices      map[string]Invoice `json:"invoices"`
		EnergyProfile map[string]float64 `json:"energy_profile"`
		CostProfile   map[string]float64 `json:"cost_profile"`
	}{}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&tmp); err != nil {
		return err
	}
	b.mu.Lock()
	// دمج السجلات
	b.records = append(b.records, tmp.Records...)
	if b.invoices == nil {
		b.invoices = make(map[string]Invoice)
	}
	for k, v := range tmp.Invoices {
		b.invoices[k] = v
	}
	for k, v := range tmp.EnergyProfile {
		b.energyProfile[k] = v
	}
	for k, v := range tmp.CostProfile {
		b.costProfile[k] = v
	}
	b.mu.Unlock()
	return nil
}

// ----------------- مجمع دوري بسيط -----------------

// StartAggregator يشغّل goroutine يقوم بتحديث ملخصات المشاريع كل فترة interval.
// يمكن إيقافه بتمرير ctx ملغى.
func (b *BillingEngine) StartAggregator(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.runAggregationOnce()
			}
		}
	}()
}

// runAggregationOnce يعيد بناء byProject من السجلات الحالية
func (b *BillingEngine) runAggregationOnce() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byProject = make(map[string]*ProjectAggregate)
	for _, r := range b.records {
		pa, ok := b.byProject[r.ProjectID]
		if !ok {
			pa = &ProjectAggregate{
				ProjectID:  r.ProjectID,
				ByResource: make(map[string]float64),
			}
			b.byProject[r.ProjectID] = pa
		}
		pa.ByResource[r.Resource] += r.Amount
		pa.RecordsCount++
		pa.EstimatedKWh += b.estimateEnergyForRecordUnlocked(r)
		pa.EstimatedCost += b.estimateCostForRecordUnlocked(r)
		pa.LastUpdated = time.Now().UTC()
	}
}

// GetProjectAggregate يعيد الملخّص المحسوب إن وُجد
func (b *BillingEngine) GetProjectAggregate(projectID string) (*ProjectAggregate, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	pa, ok := b.byProject[projectID]
	return pa, ok
}

// ----------------- دوال داخلية للمساعدة -----------------

// generateInvoiceLikeUnlocked (يُفترض caller لديه lock read) — يُنشئ تمثيلاً لفترة معينة
func (b *BillingEngine) generateInvoiceLikeUnlocked(projectID string, from, to time.Time) (Invoice, error) {
	var recs []UsageRecord
	var total float64
	for _, r := range b.records {
		if r.ProjectID != projectID {
			continue
		}
		if !from.IsZero() && r.Timestamp.Before(from) {
			continue
		}
		if !to.IsZero() && r.Timestamp.After(to) {
			continue
		}
		recs = append(recs, r)
		// تقدير التكلفة (إن وجدت CostPerUnit نستخدمها، وإلا نستخدم Amount كقيمة بديلة)
		if r.CostPerUnit > 0 {
			total += r.Amount * r.CostPerUnit
		} else {
			total += r.Amount
		}
	}
	if len(recs) == 0 {
		return Invoice{}, errors.New("no records")
	}
	periodLabel := from.Format("2006-01-02") + "_" + to.Format("2006-01-02")
	inv := Invoice{
		ID:        projectID + "-" + periodLabel,
		UserID:    "", // غير مرتبط بالمستخدم هنا؛ يمكن تعديل إذا لزم
		Period:    periodLabel,
		Total:     total,
		Status:    "pending",
		Records:   recs,
		CreatedAt: time.Now().UTC(),
	}
	return inv, nil
}

// estimateEnergyForRecordUnlocked مساعدة تقديرية (يُفترض caller داخل lock)
func (b *BillingEngine) estimateEnergyForRecordUnlocked(r UsageRecord) float64 {
	switch r.Resource {
	case "cpu":
		// r.Amount assumed seconds
		return r.Amount * b.energyProfile["cpu_seconds"]
	case "gpu":
		return r.Amount * b.energyProfile["gpu_seconds"]
	case "storage":
		// if amount is bytes assume one-second window (heuristic) or treat amount as byte-seconds
		return r.Amount * b.energyProfile["storage_byte_s"]
	case "net":
		return r.Amount * b.energyProfile["net_bytes"]
	default:
		return 0.0
	}
}
func (b *BillingEngine) estimateCostForRecordUnlocked(r UsageRecord) float64 {
	if r.CostPerUnit > 0 {
		return r.Amount * r.CostPerUnit
	}
	switch r.Resource {
	case "cpu":
		return r.Amount * b.costProfile["cpu_seconds"]
	case "gpu":
		return r.Amount * b.costProfile["gpu_seconds"]
	case "storage":
		return r.Amount * b.costProfile["storage_byte_s"]
	case "net":
		return r.Amount * b.costProfile["net_bytes"]
	default:
		return 0.0
	}
}

// EstimateEnergyForRecord واجهة عامة لحساب kWh لمسجل
func (b *BillingEngine) EstimateEnergyForRecord(r UsageRecord) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.estimateEnergyForRecordUnlocked(r)
}

// EstimateCostForRecord واجهة عامة لتقدير التكلفة لمسجل
func (b *BillingEngine) EstimateCostForRecord(r UsageRecord) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.estimateCostForRecordUnlocked(r)
}