// Package web serves a real-time event dashboard over HTTP.
// It is an optional component — enabled by setting web_addr in config.
package web

import (
	"embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
)

//go:embed dashboard.html
var static embed.FS

// Server serves the Vigilo web dashboard.
type Server struct {
	store *buffer.Store
	mux   *http.ServeMux
}

func New(store *buffer.Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/api/events", s.handleEvents)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Listen(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := static.ReadFile("dashboard.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	since := time.Now().Add(-time.Hour)
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	limit := 500
	opts := buffer.QueryOptions{
		Since:    since,
		Severity: q.Get("severity"),
		Limit:    limit,
	}
	if src := q.Get("source"); src != "" {
		opts.Sources = []string{src}
	}

	events, err := s.store.List(opts)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []collector.Event{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(events)
}
