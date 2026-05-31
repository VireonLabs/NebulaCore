package monitoring

import (
	"context"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/Aurionex/NebulaCore/internal/logging"
	"github.com/Aurionex/NebulaCore/internal/security"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	anomaliesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "laserwall_anomalies_total", Help: "Total anomalies detected",
	})
	anomalyLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "laserwall_anomaly_latency_ms",
		Help:    "Anomaly detection latency ms",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	})
)

func init() {
	prometheus.MustRegister(anomaliesTotal)
	prometheus.MustRegister(anomalyLatency)
}

type Monitor struct {
	enf     *security.EnforcementManager
	entropy *security.EntropyAggregator
	aud     *logging.Auditor
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	mu      sync.Mutex
	stopped bool
}

func NewMonitor(enf *security.EnforcementManager, ent *security.EntropyAggregator, aud *logging.Auditor) *Monitor {
	return &Monitor{enf: enf, entropy: ent, aud: aud}
}

func (m *Monitor) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	// main loop
	m.wg.Add(1)
	go m.loop()

	// start dedicated metrics server
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{Addr: ":9090", Handler: mux}
		log.Println("[monitor] prometheus metrics exposed on :9090/metrics")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server error: %v", err)
		}
	}()
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Monitor) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var ewma float64
	alpha := 0.2
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			val := 0.0
			if m.entropy != nil {
				v := m.entropy.GetRandomInt(1000)
				val = float64(v) / 1000.0
			}
			if ewma == 0 {
				ewma = val
			} else {
				ewma = alpha*val + (1-alpha)*ewma
			}
			z := 0.0
			if math.Abs(val-ewma) > 0.5 {
				z = 1.0
			}
			if z > 0.9 {
				_ = m.aud.AppendEvent(context.Background(), &logging.AuditEvent{Timestamp: time.Now().UTC(), Source: "monitor", Action: "anomaly", Details: map[string]interface{}{"score": val}})
				anomaliesTotal.Inc()
			}
			anomalyLatency.Observe(time.Since(start).Seconds() * 1000.0)
		}
	}
}