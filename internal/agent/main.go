// Production-ready Agent for NebulaCore
// Sandbox: Firecracker (via internal helper: "fc-run")
// Author: NebulaCore

package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	controlURL    string
	agentID       string
	capacity      int
	sandbox       string
	address       string
	labels        string
	agentVersion  = Version
	registerFreq  = 10 * time.Second
	requestLimit  = int64(10 << 20)
	httpTimeout   = 30 * time.Second
	shutdownGrace = 20 * time.Second
)

type Agent struct {
	id        string
	capacity  int
	address   string
	labels    string
	control   string
	sandbox   string
	client    *http.Client
	jobQueue  chan Job
	wg        sync.WaitGroup
	shutdown  chan struct{}
	metrics   *AgentMetrics
	reportMux sync.Mutex
}

func NewAgent(id, control, addr, labels string, cap int, sandbox string) *Agent {
	return &Agent{
		id:       id,
		capacity: cap,
		address:  addr,
		labels:   labels,
		control:  control,
		sandbox:  sandbox,
		client:   &http.Client{Timeout: httpTimeout},
		jobQueue: make(chan Job, cap*4),
		shutdown: make(chan struct{}),
		metrics:  NewMetrics(),
	}
}

// Detect best local IP
func detectLocalAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if iv, err := strconv.Atoi(v); err == nil {
			return iv
		}
	}
	return def
}

func main() {
	controlURL = getenv("CONTROL_URL", "http://localhost:8080")
	agentID = getenv("AGENT_ID", "")
	capacity = getenvInt("AGENT_CAPACITY", 2)
	sandbox = getenv("AGENT_SANDBOX", "firecracker")
	labels = getenv("AGENT_LABELS", "local,default")
	address = getenv("AGENT_ADDRESS", "")

	if agentID == "" {
		agentID = "agent-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	if address == "" {
		ip := detectLocalAddress()
		port := getenv("AGENT_PORT", "9000")
		address = "http://" + ip + ":" + port
	}
	if capacity < 1 {
		capacity = 1
	}

	agent := NewAgent(agentID, controlURL, address, labels, capacity, sandbox)
	port := getenv("AGENT_PORT", "9000")
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":"+port, nil)
	}()
	agent.Run(port)
}