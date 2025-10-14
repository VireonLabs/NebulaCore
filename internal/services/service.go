package services

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nebula/internal/store"
)

type Service struct {
	DB          *gorm.DB
	engine      *gin.Engine
	ai          *AIService
	policy      *PolicyEngine
	metrics     *MetricsCollector
	jobLock     sync.Mutex
	jobAttempts map[uint]int
}

func NewService(db *gorm.DB, r *gin.Engine) *Service {
	s := &Service{
		DB:          db,
		engine:      r,
		jobAttempts: make(map[uint]int),
	}
	s.ai = NewAIService()
	s.policy = NewPolicyEngine(db)
	s.metrics = NewMetricsCollector()
	return s
}

func (s *Service) CreateProvider(c *gin.Context) {
	var req struct {
		Provider string                 `json:"provider"`
		Name     string                 `json:"name"`
		Config   map[string]interface{} `json:"config"`
		Quota    map[string]interface{} `json:"quota"`
		Expires  *string                `json:"expires"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfgb, _ := json.Marshal(req.Config)
	qb, _ := json.Marshal(req.Quota)
	var exp *time.Time
	pa := store.ProviderAccount{
		Provider:  req.Provider,
		Name:      req.Name,
		Config:    string(cfgb),
		QuotaJSON: string(qb),
		Enabled:   true,
		ExpiresAt: exp,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.DB.Create(&pa).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": pa.ID})
}

func (s *Service) ListProviders(c *gin.Context) {
	var ps []store.ProviderAccount
	if err := s.DB.Find(&ps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ps)
}

func (s *Service) RegisterAgent(c *gin.Context) {
	var req struct {
		AgentID  string `json:"agent_id"`
		Address  string `json:"address"`
		Capacity int    `json:"capacity"`
		Labels   string `json:"labels"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ag := store.Agent{
		AgentID:   req.AgentID,
		Address:   req.Address,
		Capacity:  req.Capacity,
		Labels:    req.Labels,
		LastSeen:  time.Now(),
		Status:    "online",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.DB.Where(store.Agent{AgentID: req.AgentID}).FirstOrCreate(&ag).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"agent_id": ag.AgentID})
}

func (s *Service) ListAgents(c *gin.Context) {
	var a []store.Agent
	if err := s.DB.Find(&a).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, a)
}

func (s *Service) CreateJob(c *gin.Context) {
	var req struct {
		Type     string `json:"type"`
		Payload  string `json:"payload"`
		Priority int    `json:"priority"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	j := store.Job{
		Type:      req.Type,
		Payload:   req.Payload,
		Status:    "pending",
		Priority:  req.Priority,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.DB.Create(&j).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.metrics.IncJobsCreated()
	c.JSON(http.StatusCreated, gin.H{"job_id": j.ID})
}

func (s *Service) ListJobs(c *gin.Context) {
	var js []store.Job
	if err := s.DB.Find(&js).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, js)
}

func (s *Service) ProcessPendingJobsWithRetry() {
	var jobs []store.Job
	if err := s.DB.Where("status = ?", "pending").Order("priority DESC, created_at ASC").Find(&jobs).Error; err != nil {
		return
	}
	for _, job := range jobs {
		go s.executeJobWithRetry(job)
	}
}

func (s *Service) executeJobWithRetry(job store.Job) {
	const maxRetries = 5
	s.jobLock.Lock()
	attempt := s.jobAttempts[job.ID]
	s.jobAttempts[job.ID] = attempt + 1
	s.jobLock.Unlock()

	err := s.executeJob(job)
	if err != nil && attempt < maxRetries {
		delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		time.AfterFunc(delay, func() { s.executeJobWithRetry(job) })
		return
	}
	if err == nil {
		s.jobLock.Lock()
		delete(s.jobAttempts, job.ID)
		s.jobLock.Unlock()
	}
}

func (s *Service) executeJob(job store.Job) error {
	// Dynamic optimization: AI may split/merge jobs
	actionSuggested, _ := s.ai.OptimizeJob(job.Payload)
	if actionSuggested != "" {
		// For POC, just note suggestion; actual splitting/merging handled later
	}

	job.Status = "completed"
	job.UpdatedAt = time.Now()
	if err := s.DB.Save(&job).Error; err != nil {
		return err
	}
	return nil
}

func (s *Service) CreateApproval(c *gin.Context) {
	var req struct {
		Action string `json:"action"`
		Meta   string `json:"meta"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "pending", "action": req.Action})
}

func (s *Service) ListApprovals(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{})
}

func (s *Service) AIChat(c *gin.Context) {
	var req struct {
		Message string `json:"message"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := s.ai.Chat(req.Message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reply": resp})
}

func (s *Service) Metrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"jobs_created": s.metrics.JobsCreated(),
		"pending_jobs": s.countPendingJobs(),
	})
}

func (s *Service) countPendingJobs() int64 {
	var count int64
	s.DB.Model(&store.Job{}).Where("status = ?", "pending").Count(&count)
	return count
}