package agent

import (
	"github.com/prometheus/client_golang/prometheus"
)

type AgentMetrics struct {
	registerAttempts prometheus.Counter
	registerSuccess  prometheus.Counter
	jobsReceived     prometheus.Counter
	jobsAccepted     prometheus.Counter
	jobsSuccess      prometheus.Counter
	jobsFailed       prometheus.Counter
	jobDuration      prometheus.Histogram
}

func NewMetrics() *AgentMetrics {
	m := &AgentMetrics{
		registerAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_register_attempts_total",
			Help: "Total register attempts to control-plane",
		}),
		registerSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_register_success_total",
			Help: "Successful register attempts",
		}),
		jobsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_received_total",
			Help: "Jobs received",
		}),
		jobsAccepted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_accepted_total",
			Help: "Jobs accepted",
		}),
		jobsSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_success_total",
			Help: "Jobs executed successfully",
		}),
		jobsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agent_jobs_failed_total",
			Help: "Jobs failed",
		}),
		jobDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "agent_job_duration_seconds",
			Help:    "Job execution duration",
			Buckets: prometheus.ExponentialBuckets(0.5, 2.0, 8),
		}),
	}
	prometheus.MustRegister(
		m.registerAttempts,
		m.registerSuccess,
		m.jobsReceived,
		m.jobsAccepted,
		m.jobsSuccess,
		m.jobsFailed,
		m.jobDuration,
	)
	return m
}