// -------------------------------------------------------------
// internal/network/network.go
// طبقة شبكات بسيطة جداً مبنية على HTTP فقط
// -------------------------------------------------------------

package network

import (
    "context"
    "fmt"
    "net/http"
)

type Server struct {
    addr string
}

func NewServer(addr string) *Server {
    return &Server{addr: addr}
}

func (s *Server) Start(ctx context.Context) error {
    mux := http.NewServeMux()

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        w.Write([]byte("NebulaCore Network Layer Active (Minimal Mode)"))
    })

    srv := &http.Server{Addr: s.addr, Handler: mux}

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            fmt.Println("خطأ في السيرفر:", err)
        }
    }()

    <-ctx.Done()
    return srv.Shutdown(context.Background())
}

