package cloudflare

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Profile struct {
	endpoint   url.URL
	address    string
	serverName string
	userID     [16]byte
}

var (
	invalid     = errors.New("invalid VLESS WebSocket TLS profile")
	uuidPattern = regexp.MustCompile(`(?i)^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	dnsLabel    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func Parse(link string) (Profile, error) {
	if len(link) > 8192 {
		return Profile{}, invalid
	}
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "vless" || u.User == nil || (u.Path != "" && u.Path != "/") {
		return Profile{}, invalid
	}
	username := u.User.Username()
	if _, set := u.User.Password(); set || !uuidPattern.MatchString(username) {
		return Profile{}, invalid
	}
	address := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return Profile{}, invalid
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, invalid
	}
	for key, values := range query {
		if len(values) != 1 {
			return Profile{}, invalid
		}
		switch key {
		case "type", "security", "flow", "encryption", "allowInsecure", "sni", "host", "path", "fp", "alpn":
		default:
			return Profile{}, invalid
		}
	}
	switch query.Get("allowInsecure") {
	case "", "0", "false":
	default:
		return Profile{}, invalid
	}
	if query.Get("type") != "ws" || query.Get("security") != "tls" || query.Get("flow") != "" ||
		(query.Get("encryption") != "" && query.Get("encryption") != "none") ||
		(query.Get("alpn") != "" && query.Get("alpn") != "http/1.1") {
		return Profile{}, invalid
	}
	host := strings.ToLower(query.Get("host"))
	name := strings.ToLower(query.Get("sni"))
	if name == "" {
		name = host
	}
	if name == "" {
		name = address
	}
	if !isDomain(name) || (host != "" && host != name) {
		return Profile{}, invalid
	}
	if addr, err := netip.ParseAddr(address); err == nil {
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Zone() != "" {
			return Profile{}, invalid
		}
	} else if address != name {
		return Profile{}, invalid
	}
	path := query.Get("path")
	if path == "" {
		path = "/"
	}
	requestURI, err := url.ParseRequestURI(path)
	if err != nil || len(path) > 2048 || !strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, "//") || strings.ContainsAny(path, "#\r\n") ||
		requestURI.Query().Has("ed") || requestURI.RequestURI() != path {
		return Profile{}, invalid
	}
	requestURI.Scheme = "wss"
	requestURI.Host = net.JoinHostPort(name, port)
	id, _ := hex.DecodeString(strings.ReplaceAll(username, "-", ""))
	return Profile{
		endpoint: *requestURI, address: net.JoinHostPort(address, port),
		serverName: name, userID: [16]byte(id),
	}, nil
}

func isDomain(value string) bool {
	if len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

type handshakeStep struct {
	name     string
	duration time.Duration
	ok       bool
}

type handshakeTiming struct {
	steps []handshakeStep
}

func (t *handshakeTiming) add(name string, started time.Time, err error) {
	t.steps = append(t.steps, handshakeStep{name: name, duration: time.Since(started), ok: err == nil})
}

func (t handshakeTiming) String() string {
	parts := make([]string, 0, len(t.steps))
	for _, step := range t.steps {
		result := "OK"
		if !step.ok {
			result = "failed"
		}
		parts = append(parts, fmt.Sprintf("%s %s %d ms", step.name, result, step.duration.Milliseconds()))
	}
	return strings.Join(parts, " → ")
}

func (p Profile) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: p.serverName, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
}

func (p Profile) open(ctx context.Context) (*websocket.Conn, error) {
	return p.openTLS(ctx, p.tlsConfig(), nil)
}

func (p Profile) openTLS(ctx context.Context, config *tls.Config, timing *handshakeTiming) (*websocket.Conn, error) {
	transport := net.Dialer{Timeout: 8 * time.Second}
	var webSocketStarted time.Time
	if timing != nil {
		var tlsStarted time.Time
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			TLSHandshakeStart: func() { tlsStarted = time.Now() },
			TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
				timing.add("TLS", tlsStarted, err)
				if err == nil {
					webSocketStarted = time.Now()
				}
			},
		})
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if timing == nil {
				return transport.DialContext(ctx, network, p.address)
			}
			started := time.Now()
			raw, err := transport.DialContext(ctx, network, p.address)
			timing.add("TCP", started, err)
			return raw, err
		},
		TLSClientConfig: config,
	}
	conn, response, err := dialer.DialContext(ctx, p.endpoint.String(), http.Header{"Host": []string{p.serverName}})
	if !webSocketStarted.IsZero() {
		timing.add("WebSocket", webSocketStarted, err)
	}
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
			return nil, fmt.Errorf("WebSocket upgrade rejected: HTTP %d", response.StatusCode)
		}
		return nil, fmt.Errorf("WebSocket connection failed: %w", err)
	}
	conn.SetReadLimit(8 << 20)
	return conn, nil
}

func (p Profile) checkTiming(ctx context.Context) (handshakeTiming, error) {
	var timing handshakeTiming
	conn, err := p.openTLS(ctx, p.tlsConfig(), &timing)
	if err == nil {
		_ = conn.Close()
	}
	return timing, err
}

func (p Profile) Check(ctx context.Context) error {
	conn, err := p.open(ctx)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (p Profile) Dial(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("unsupported VLESS command")
	}
	header, err := p.request(target)
	if err != nil {
		return nil, err
	}
	conn, err := p.open(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		stop()
		_ = conn.Close()
		return nil, errors.New("VLESS header write failed")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return &stream{Conn: conn.UnderlyingConn(), ws: conn, stop: stop}, nil
}

func (p Profile) request(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, errors.New("invalid destination")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid destination port")
	}
	header := append([]byte{0}, p.userID[:]...)
	header = binary.BigEndian.AppendUint16(append(header, 0, 1), uint16(port))
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		addr = addr.Unmap()
		if addr.Is4() {
			return append(append(header, 1), addr.AsSlice()...), nil
		}
		return append(append(header, 3), addr.AsSlice()...), nil
	}
	if len(host) > 255 || strings.ContainsAny(host, ":\x00\r\n") {
		return nil, errors.New("invalid destination host")
	}
	return append(append(header, 2, byte(len(host))), host...), nil
}

type stream struct {
	net.Conn
	ws           *websocket.Conn
	stop         func() bool
	reader       io.Reader
	responseRead bool
}

func (s *stream) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if !s.responseRead {
		var reply [2]byte
		frames := frameReader{s}
		if _, err := io.ReadFull(frames, reply[:]); err != nil {
			return 0, err
		}
		if reply != [2]byte{} {
			return 0, errors.New("unsupported VLESS response")
		}
		s.responseRead = true
	}
	return s.readFrame(buffer)
}

type frameReader struct{ stream *stream }

func (r frameReader) Read(b []byte) (int, error) { return r.stream.readFrame(b) }

func (s *stream) readFrame(buffer []byte) (int, error) {
	for {
		if s.reader == nil {
			kind, reader, err := s.ws.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					return 0, io.EOF
				}
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				return 0, errors.New("unexpected WebSocket message")
			}
			s.reader = reader
		}
		n, err := s.reader.Read(buffer)
		if err == io.EOF {
			s.reader = nil
			if n == 0 {
				continue
			}
			return n, nil
		}
		return n, err
	}
}

func (s *stream) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if err := s.ws.WriteMessage(websocket.BinaryMessage, buffer); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (s *stream) Close() error {
	s.stop()
	return s.ws.Close()
}
