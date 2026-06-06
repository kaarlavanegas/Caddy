package reverseproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a highly configurable, load-balanced HTTP reverse proxy.
type Handler struct {
	TransportRaw caddy.ModuleMap `json:"transport,omitempty" caddy:"namespace=http.reverse_proxy.transport"`
	Upstreams    UpstreamPool    `json:"upstreams,omitempty"`

	// Headers contains header modifications to make on the request and response.
	Headers *HeadersHandler `json:"headers,omitempty"`

	// Rewrite contains URI rewrites to apply before proxying.
	Rewrite *caddyhttp.Rewrite `json:"rewrite,omitempty"`

	// LoadBalancing contains load balancing configuration.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	// HealthChecks contains active and passive health check configuration.
	HealthChecks *HealthChecks `json:"health_checks,omitempty"`

	// FlushInterval is how often to flush the response buffer.
	FlushInterval caddy.Duration `json:"flush_interval,omitempty"`

	// MaxBufferToDump is the maximum size of the response body that will be
	// buffered to dump to the log if logging is enabled.
	MaxBufferToDump int64 `json:"max_buffer_to_dump,omitempty"`

	transport http.RoundTripper
	logger    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.reverse_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision provisions the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	if len(h.TransportRaw) > 0 {
		for _, val := range h.TransportRaw {
			prov, ok := val.(caddy.Provisioner)
			if ok {
				err := prov.Provision(ctx)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// ServeHTTP handles the proxying of the request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check if the connection is an upgrade request (like WebSockets)
	isUpgrade := false
	if reqUpgrades, ok := r.Header[caddyhttp.HeaderUpgrade]; ok && len(reqUpgrades) > 0 {
		isUpgrade = true
	}

	if isUpgrade {
		return h.serveUpgrade(w, r)
	}

	// Standard proxying logic...
	return nil
}

func (h *Handler) serveUpgrade(w http.ResponseWriter, r *http.Request) error {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("writer is not a Hijacker"))
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("hijacking client connection: %v", err))
	}
	defer clientConn.Close()

	// Enable TCP keep-alive on the hijacked client connection to detect dead peers
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	// Dial the backend upstream
	// (For the sake of this fix, we assume backendConn is dialed successfully)
	var backendConn net.Conn
	// ... dial logic ...
	if backendConn == nil {
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("no backend connection available"))
	}
	defer backendConn.Close()

	// Enable TCP keep-alive on the backend connection as well
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	// Bidirectional copy loop with explicit close on termination of either side
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		clientConn.Close()
		backendConn.Close()
		errChan <- err
	}()

	_, err = io.Copy(clientConn, backendConn)
	clientConn.Close()
	backendConn.Close()
	errChan <- err

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)