package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Aurionex/NebulaCore/internal/secstore"
	"github.com/Aurionex/NebulaCore/internal/tlsutil"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type Server struct {
	ks     *secstore.SimpleEncryptedStore
	mux    *http.ServeMux
	server *http.Server
}

// NewServer returns an API server instance; handler can be nil.
func NewServer(ks *secstore.SimpleEncryptedStore, handler http.Handler) *Server {
	var m *http.ServeMux
	if handler != nil {
		if mh, ok := handler.(*http.ServeMux); ok {
			m = mh
		}
	}
	if m == nil {
		m = http.NewServeMux()
	}
	return &Server{ks: ks, mux: m}
}

func (s *Server) StartMTLSServer(ctx context.Context, handler http.Handler) (*http.Server, error) {
	// try SPIFFE
	source, err := workloadapi.NewX509Source(ctx)
	if err == nil {
		// authorize by SPIFFE ID or use AuthorizeAny with additional checking in middleware
		tlsCfg := spiffetls.TLSServerConfig(source, spiffetls.AuthorizeAny())
		srv := &http.Server{
			Addr:      ":8443",
			Handler:   handler,
			TLSConfig: tlsCfg,
		}
		go func() {
			log.Println("[api] starting SPIFFE mTLS server :8443")
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("SPIFFE server failed: %v", err)
			}
		}()
		s.server = srv
		return srv, nil
	}
	// fallback to local CA
	if s.ks == nil {
		return nil, errors.New("keystore required for local mTLS")
	}
	cert, priv, err := tlsutil.LoadOrCreateLocalCA(s.ks)
	if err != nil {
		return nil, err
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)
	servCert, err := tlsutil.GenerateShortLivedCert(&tlsutil.LocalCA{Cert: cert, Priv: priv}, "laserwall-server", 300)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates:             []tls.Certificate{*servCert},
		ClientCAs:                clientPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	go func() {
		log.Println("[api] starting local mTLS server :8443")
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("local mTLS server failed: %v", err)
		}
	}()
	s.server = srv
	// ensure graceful shutdown on context cancel
	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx2)
	}()
	return srv, nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}