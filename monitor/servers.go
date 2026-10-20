// Package monitor serves explicitly enabled diagnostics on dedicated muxes.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/engine"
)

type Servers struct{ servers []*http.Server }

func Start(c config.Config, nodes []*engine.Node) (*Servers, error) {
	s := &Servers{}
	start := func(address string, port int64, h http.Handler) error {
		if port < 0 || port > 65535 {
			return errors.New("invalid monitoring port")
		}
		// Diagnostic listeners use loopback when no address was specified.
		if address == "" {
			address = "127.0.0.1"
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
		if err != nil {
			return err
		}
		server := &http.Server{Addr: listener.Addr().String(), Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute}
		s.servers = append(s.servers, server)
		go func() { _ = server.Serve(listener) }()
		return nil
	}
	if c.PrometheusEnable {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
			var snapshots []engine.Snapshot
			for _, node := range nodes {
				status, err := node.Snapshot()
				if err != nil {
					http.Error(w, "cannot read counters", http.StatusServiceUnavailable)
					return
				}
				snapshots = append(snapshots, status)
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			fmt.Fprintln(w, "# HELP soga_reconstructed_up Node listener process state.\n# TYPE soga_reconstructed_up gauge")
			for _, status := range snapshots {
				labels := fmt.Sprintf("node_id=%q,protocol=%q", status.NodeID, status.Protocol)
				up := 0
				if status.Listeners > 0 {
					up = 1
				}
				fmt.Fprintf(w, "soga_reconstructed_up{%s} %d\n", labels, up)
				fmt.Fprintf(w, "soga_reconstructed_users{%s} %d\n", labels, status.Users)
				fmt.Fprintf(w, "soga_reconstructed_upload_bytes{%s} %.0f\n", labels, status.Upload)
				fmt.Fprintf(w, "soga_reconstructed_download_bytes{%s} %.0f\n", labels, status.Download)
				fmt.Fprintf(w, "soga_reconstructed_pending_upload_bytes{%s} %.0f\n", labels, status.PendingUpload)
				fmt.Fprintf(w, "soga_reconstructed_pending_download_bytes{%s} %.0f\n", labels, status.PendingDownload)
			}
		})
		if err := start(c.PrometheusAddr, c.PrometheusPort, mux); err != nil {
			return nil, err
		}
	}
	if c.PprofEnable {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		if err := start(c.PprofAddr, c.PprofPort, mux); err != nil {
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = s.Close(ctx)
			return nil, err
		}
	}
	return s, nil
}
func (s *Servers) Addresses() []string {
	var result []string
	for _, server := range s.servers {
		result = append(result, server.Addr)
	}
	return result
}
func (s *Servers) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var err error
	for _, server := range s.servers {
		err = errors.Join(err, server.Shutdown(ctx))
	}
	return err
}
