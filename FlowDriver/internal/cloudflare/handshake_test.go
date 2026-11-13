package cloudflare

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestScanHandshakePhases(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked" {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Scheme = "wss"
	profile := Profile{endpoint: *endpoint, address: endpoint.Host, serverName: endpoint.Hostname()}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	config := profile.tlsConfig()
	config.RootCAs = roots

	for _, test := range []struct {
		name      string
		path      string
		want      []bool
		message   string
		untrusted bool
	}{
		{name: "successful upgrade", path: "/open", want: []bool{true, true, true}},
		{name: "WebSocket rejected", path: "/blocked", want: []bool{true, true, false}, message: "HTTP 403"},
		{name: "TLS certificate untrusted", path: "/open", want: []bool{true, false}, message: "TLS certificate validation failed", untrusted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			profile.endpoint.Path = test.path
			tlsConfig := config
			if test.untrusted {
				tlsConfig = profile.tlsConfig()
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			var timing handshakeTiming
			conn, err := profile.openTLS(ctx, tlsConfig, &timing)
			if conn != nil {
				_ = conn.Close()
			}
			if test.message == "" && err != nil {
				t.Fatal(err)
			}
			if test.message != "" && (err == nil || !strings.Contains(failureReason(err), test.message)) {
				t.Fatalf("unexpected diagnostic: %v", err)
			}
			var actual []bool
			names := []string{"TCP", "TLS", "WebSocket"}
			for i, phase := range timing.steps {
				if i >= len(names) || phase.name != names[i] || phase.duration < 0 {
					t.Fatalf("invalid phase timing: %s", timing.String())
				}
				actual = append(actual, phase.ok)
			}
			if !slices.Equal(actual, test.want) {
				t.Fatalf("unexpected phases: %s", timing.String())
			}
		})
	}
}

func TestScanHandshakeSeparatesTCPFailureFromTLSTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	profile := Profile{
		endpoint: url.URL{Scheme: "wss", Host: address},
		address:  address, serverName: "example.org",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	timing, err := profile.checkTiming(ctx)
	cancel()
	if err == nil || failureReason(err) != "timeout" || len(timing.steps) != 2 ||
		!timing.steps[0].ok || timing.steps[1].name != "TLS" || timing.steps[1].ok {
		t.Fatalf("expected TLS timeout, got %v (%s)", err, timing.String())
	}

	_ = listener.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	timing, err = profile.checkTiming(ctx)
	if err == nil || len(timing.steps) != 1 || timing.steps[0].name != "TCP" || timing.steps[0].ok {
		t.Fatalf("expected TCP failure, got %v (%s)", err, timing.String())
	}
}
