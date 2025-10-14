package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nebula/internal/services"
)

type Server struct {
	DB        *gorm.DB
	Router    *gin.Engine
	Svc       *services.Service
	scheduler context.CancelFunc
	wg        sync.WaitGroup
}

func NewServer(db *gorm.DB) *Server {
	r := gin.Default()
	s := &Server{
		DB:     db,
		Router: r,
	}
	s.Svc = services.NewService(db, r)
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	api := s.Router.Group("/api/v1")
	{
		api.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
		api.POST("/providers", s.Svc.CreateProvider)
		api.GET("/providers", s.Svc.ListProviders)
		api.POST("/agents/register", s.Svc.RegisterAgent)
		api.GET("/agents", s.Svc.ListAgents)
		api.POST("/jobs", s.Svc.CreateJob)
		api.GET("/jobs", s.Svc.ListJobs)
		api.POST("/ai/chat", s.Svc.AIChat)
		api.POST("/approvals", s.Svc.CreateApproval)
		api.GET("/approvals", s.Svc.ListApprovals)
		api.GET("/metrics", s.Svc.Metrics)
	}
}

func (s *Server) Run(addr string) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.startScheduler(ctx, 5*time.Second)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- s.Router.Run(addr)
	}()

	select {
	case sig := <-sigs:
		log.Printf("signal received: %v, shutting down", sig)
	case err := <-serverErr:
		if err != nil {
			log.Printf("server error: %v", err)
		}
	}

	cancel()
	s.wg.Wait()
	log.Println("server stopped gracefully")
	return nil
}

func (s *Server) startScheduler(ctx context.Context, interval time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	s.scheduler = cancel
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.executeJobsSafely()
			}
		}
	}()
}

func (s *Server) executeJobsSafely() {
	if s.Svc == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler panic recovered: %v", r)
		}
	}()

	if hasFunc(s.Svc, "ProcessPendingJobsWithRetry") {
		if err := s.Svc.ProcessPendingJobsWithRetry(); err != nil {
			log.Printf("scheduler error with retry: %v", err)
		}
	} else if hasFunc(s.Svc, "ProcessPendingJobs") {
		if err := s.Svc.ProcessPendingJobs(); err != nil {
			log.Printf("scheduler error: %v", err)
		}
	}
}

func hasFunc(svc *services.Service, name string) bool {
	// تحقق آمن إذا كانت الدالة موجودة
	defer func() {
		recover()
	}()
	switch name {
	case "ProcessPendingJobsWithRetry":
		return svc != nil && svc.ProcessPendingJobsWithRetry != nil
	case "ProcessPendingJobs":
		return svc != nil && svc.ProcessPendingJobs != nil
	default:
		return false
	}
}

func (s *Server) StopScheduler() {
	if s.scheduler != nil {
		s.scheduler()
	}
	s.wg.Wait()
}