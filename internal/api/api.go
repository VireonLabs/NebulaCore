package api

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Aurionex/NebulaCore/internal/logging"
	"github.com/Aurionex/NebulaCore/internal/monitoring"
	"github.com/Aurionex/NebulaCore/internal/secstore"
	"github.com/Aurionex/NebulaCore/internal/security"
)

type API struct {
	ks      *secstore.SimpleEncryptedStore
	auditor *logging.Auditor
	mon     *monitoring.Monitor
	enf     *security.EnforcementManager
	mux     *http.ServeMux
}

type clientIDKeyType string

const clientIDKey clientIDKeyType = "client_id"

func NewAPI(ks *secstore.SimpleEncryptedStore, auditor *logging.Auditor, mon *monitoring.Monitor, enf *security.EnforcementManager) *API {
	m := http.NewServeMux()
	api := &API{ks: ks, auditor: auditor, mon: mon, enf: enf, mux: m}
	api.routes()
	return api
}

func (a *API) routes() {
	a.mux.Handle("/security/status", a.authMiddleware(http.HandlerFunc(a.handleSecurityStatus)))
	a.mux.Handle("/audit/logs", a.authMiddleware(http.HandlerFunc(a.handleAuditLogs)))
	a.mux.Handle("/attestation/report", a.authMiddleware(http.HandlerFunc(a.handleAttestationReport)))
	a.mux.Handle("/healthz", http.HandlerFunc(a.handleHealth))
	a.mux.Handle("/readyz", http.HandlerFunc(a.handleReady))
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func (a *API) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"time":     time.Now().UTC(),
		"keystore": a.ks != nil,
		"enforcer": a.enf != nil,
		"monitor":  a.mon != nil,
		"auditor":  a.auditor != nil,
	}
	_ = json.NewEncoder(w).Encode(status)
}

func (a *API) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	clientID, _ := r.Context().Value(clientIDKey).(string)
	// authorization: allowed SPIFFE IDs come from env ALLOWED_SPIFFE_IDS (comma-separated) in production
	allowedList := map[string]bool{}
	for _, s := range splitAndTrim(os.Getenv("ALLOWED_SPIFFE_IDS"), ",") {
		if s != "" {
			allowedList[s] = true
		}
	}
	devMode := os.Getenv("DEV_MODE") == "1"
	if !devMode {
		if len(allowedList) == 0 {
			http.Error(w, "forbidden: no allowed SPIFFE IDs configured", http.StatusForbidden)
			return
		}
		if !allowedList[clientID] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	} else {
		// dev mode: allow CN-based dev clients (clientID may be CN)
		if clientID == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	path := "/var/lib/laserwall/audit/audit.jsonl"
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "audit file open error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	stat, _ := f.Stat()
	size := stat.Size()
	var start int64 = 0
	const tailSize = 32 * 1024
	if size > tailSize {
		start = size - tailSize
	}
	_, _ = f.Seek(start, io.SeekStart)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func (a *API) handleAttestationReport(w http.ResponseWriter, r *http.Request) {
	var rpt map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&rpt)
	_ = a.auditor.AppendEvent(context.Background(), &logging.AuditEvent{Timestamp: time.Now().UTC(), Source: "api", Action: "attestation_report", Details: rpt})
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
func (a *API) handleReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// require client cert
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		now := time.Now().UTC()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			http.Error(w, "client cert expired or not yet valid", http.StatusUnauthorized)
			return
		}

		// determine allowed SPIFFE IDs from env
		allowed := splitAndTrim(os.Getenv("ALLOWED_SPIFFE_IDS"), ",")

		// check for SPIFFE URI in SANs
		clientID := ""
		for _, u := range cert.URIs {
			if u.Scheme == "spiffe" {
				clientID = u.String()
				break
			}
		}

		devMode := os.Getenv("DEV_MODE") == "1"
		if clientID == "" {
			// no SPIFFE URI - in dev mode allow CN fallback
			if devMode {
				cn := cert.Subject.CommonName
				if cn == "" {
					http.Error(w, "forbidden: cn empty", http.StatusForbidden)
					return
				}
				clientID = cn
			} else {
				// production: require SPIFFE IDs
				http.Error(w, "forbidden: require SPIFFE ID in client cert", http.StatusForbidden)
				return
			}
		} else {
			// in production ensure clientID in allowed list
			if !devMode {
				found := false
				for _, aID := range allowed {
					if aID == clientID {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "forbidden: spiffe id not allowed", http.StatusForbidden)
					return
				}
			}
		}

		ctx := context.WithValue(r.Context(), clientIDKey, clientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// splitAndTrim splits by sep and trims whitespace.
func splitAndTrim(s string, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			// ensure valid URI (for SPIFFE check) - if invalid keep raw
			if _, err := url.Parse(p); err == nil {
				out = append(out, p)
			} else {
				out = append(out, p)
			}
		}
	}
	return out
}