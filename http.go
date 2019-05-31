package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/logger"
)

// Server represents an HTTP server
type Server struct {
	server      *http.Server
	networkType string
	listenAddr  string
	tlsConfig   *tls.Config
}

// NewServer will serve traffic on HTTP or HTTPS depending on TLS options
func NewServer(handler http.Handler, opts *Options) (*Server, error) {
	rv := &Server{}
	if opts.TLSKeyFile != "" || opts.TLSCertFile != "" {
		rv.listenAddr = opts.HTTPSAddress
		rv.networkType = "tcp"
		rv.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		}
		if rv.tlsConfig.NextProtos == nil {
			rv.tlsConfig.NextProtos = []string{"http/1.1"}
		}

		var err error
		rv.tlsConfig.Certificates = make([]tls.Certificate, 1)
		rv.tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("FATAL: loading tls config (%s, %s) failed - %s", opts.TLSCertFile, opts.TLSKeyFile, err)
		}
	} else {
		HTTPAddress := opts.HTTPAddress
		var scheme string

		i := strings.Index(HTTPAddress, "://")
		if i > -1 {
			scheme = HTTPAddress[0:i]
		}

		switch scheme {
		case "", "http":
			rv.networkType = "tcp"
		default:
			rv.networkType = scheme
		}

		slice := strings.SplitN(HTTPAddress, "//", 2)
		rv.listenAddr = slice[len(slice)-1]
	}

	rv.server = &http.Server{Handler: handler}

	return rv, nil
}

// Used with gcpHealthcheck()
const userAgentHeader = "User-Agent"
const googleHealthCheckUserAgent = "GoogleHC/1.0"
const rootPath = "/"

// gcpHealthcheck handles healthcheck queries from GCP.
func gcpHealthcheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for liveness and readiness:  used for Google App Engine
		if r.URL.EscapedPath() == "/liveness_check" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}
		if r.URL.EscapedPath() == "/readiness_check" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		// Check for GKE ingress healthcheck:  The ingress requires the root
		// path of the target to return a 200 (OK) to indicate the service's good health. This can be quite a challenging demand
		// depending on the application's path structure. This middleware filters out the requests from the health check by
		//
		// 1. checking that the request path is indeed the root path
		// 2. ensuring that the User-Agent is "GoogleHC/1.0", the health checker
		// 3. ensuring the request method is "GET"
		if r.URL.Path == rootPath &&
			r.Header.Get(userAgentHeader) == googleHealthCheckUserAgent &&
			r.Method == http.MethodGet {

			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// ListenAndServe constructs a net.Listener and starts handling HTTP requests
func (s *Server) ListenAndServe() error {
	serverType := "HTTP"
	if s.tlsConfig != nil {
		serverType = "HTTPS"
	}

	listener, err := net.Listen(s.networkType, s.listenAddr)
	if err != nil {
		return fmt.Errorf("FATAL: listen (%s, %s) failed - %s", s.networkType, s.listenAddr, err)
	}
	logger.Printf("%s: listening on %s", serverType, s.listenAddr)

	if s.tlsConfig != nil {
		listener = tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, s.tlsConfig)
	}

	err = s.server.Serve(listener)
	if err != nil && err != http.ErrServerClosed && !strings.Contains(err.Error(), "use of closed network connection") {
		return fmt.Errorf("ERROR: %s.Serve() - %s", strings.ToLower(serverType), err)
	}

	logger.Printf("%s: closing %s", serverType, listener.Addr())
	return nil
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
