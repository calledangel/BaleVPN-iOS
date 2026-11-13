package dnstunnel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const MaxResolvers = 8
const MaxSavedResolvers = 64
const MaxReferenceResolvers = 20_000

var (
	dnsLabel   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	username   = regexp.MustCompile(`^[a-z_][a-z_0-9-]{0,31}$`)
	ErrHostKey = errors.New("SSH host key did not match the profile")
	ErrSSH     = errors.New("SSH authentication or negotiation failed")
	ErrTunnel  = errors.New("DNSTT handshake failed")
)

type Profile struct {
	domain  dns.Name
	key     []byte
	mtu     int
	ssh     *ssh.ClientConfig
	Timeout time.Duration
}

func ParseProfile(raw string) (Profile, error) {
	var input struct {
		Domain      string `json:"domain"`
		ServerKey   string `json:"server_public_key"`
		SSHUser     string `json:"ssh_user"`
		SSHHostKey  string `json:"ssh_host_key"`
		SSHIdentity string `json:"ssh_private_key"`
		Timeout     int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return Profile{}, err
	}
	var labels [][]byte
	for _, label := range strings.Split(strings.TrimSuffix(strings.TrimSpace(input.Domain), "."), ".") {
		if !dnsLabel.MatchString(label) {
			return Profile{}, errors.New("invalid DNSTT domain")
		}
		labels = append(labels, []byte(strings.ToLower(label)))
	}
	domain, err := dns.NewName(labels)
	if err != nil || len(labels) < 2 {
		return Profile{}, errors.New("invalid DNSTT domain")
	}
	// Match upstream dnstt's query name capacity and packet framing.
	capacity := 254
	for _, label := range labels {
		capacity -= len(label) + 1
	}
	mtu := capacity*63/64*5/8 - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return Profile{}, errors.New("DNSTT domain leaves insufficient packet space")
	}
	key, err := hex.DecodeString(strings.TrimSpace(input.ServerKey))
	if err != nil || len(key) != 32 {
		return Profile{}, errors.New("invalid DNSTT public key")
	}
	if !username.MatchString(input.SSHUser) || input.SSHUser == "root" {
		return Profile{}, errors.New("a non-root SSH forwarding account is required")
	}
	host, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(input.SSHHostKey))
	if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
		return Profile{}, errors.New("invalid SSH host key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(input.SSHIdentity))
	if err != nil {
		return Profile{}, errors.New("invalid SSH identity")
	}
	if input.Timeout == 0 {
		input.Timeout = 15
	}
	if input.Timeout < 5 || input.Timeout > 45 {
		return Profile{}, errors.New("timeout must be 5–45 seconds")
	}
	algorithms := []string{host.Type()}
	if host.Type() == ssh.KeyAlgoRSA {
		algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return Profile{
		domain: domain, key: key, mtu: mtu, Timeout: time.Duration(input.Timeout) * time.Second,
		ssh: &ssh.ClientConfig{
			User: input.SSHUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyAlgorithms: algorithms,
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				if err := ssh.FixedHostKey(host)(hostname, remote, key); err != nil {
					return ErrHostKey
				}
				return nil
			},
		},
	}, nil
}

func Resolvers(raw string) ([]netip.AddrPort, error) {
	return parseResolvers(raw, MaxResolvers)
}

func SavedResolvers(raw string) ([]netip.AddrPort, error) {
	return resolverText(raw, MaxSavedResolvers)
}

func ReferenceResolvers(raw string) ([]netip.AddrPort, error) {
	return resolverText(raw, MaxReferenceResolvers)
}

func resolverText(raw string, limit int) ([]netip.AddrPort, error) {
	var lines []string
	raw = strings.TrimPrefix(raw, "\ufeff")
	for _, line := range strings.Split(raw, "\n") {
		text, _, _ := strings.Cut(line, "#")
		lines = append(lines, text)
	}
	return parseResolvers(strings.Join(lines, "\n"), limit)
}

func parseResolvers(raw string, limit int) ([]netip.AddrPort, error) {
	var list []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		addr, err := netip.ParseAddrPort(part)
		if err != nil {
			ip, ipErr := netip.ParseAddr(part)
			if ipErr != nil {
				return nil, errors.New("use resolver IPs or IP:port")
			}
			addr = netip.AddrPortFrom(ip, 53)
		}
		ip := addr.Addr().Unmap()
		if !(ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) || addr.Port() == 0 {
			return nil, errors.New("invalid resolver endpoint")
		}
		addr = netip.AddrPortFrom(ip, addr.Port())
		if !seen[addr] {
			list = append(list, addr)
			seen[addr] = true
		}
	}
	if len(list) > limit {
		return nil, fmt.Errorf("at most %d resolver endpoints are supported", limit)
	}
	return list, nil
}

// A connected UDP socket only accepts responses from the configured resolver.
type resolverSocket struct{ *net.UDPConn }

func (s resolverSocket) WriteTo(p []byte, _ net.Addr) (int, error) { return s.Write(p) }

type Session struct {
	*ssh.Client
	mux         *smux.Session
	kcp         *kcp.UDPSession
	packet      *DNSPacketConn
	keyExchange string
}

func (s *Session) Close() {
	_ = s.Client.Close()
	_ = s.mux.Close()
	_ = s.kcp.Close()
	_ = s.packet.Close()
}

type connectionParameters struct {
	name    string
	udpSize uint16
	mtu     int
	timeout time.Duration
}

func (p Profile) standardParameters() connectionParameters {
	return connectionParameters{name: "standard", udpSize: 4096, mtu: p.mtu, timeout: p.Timeout}
}

func (p Profile) Connect(ctx context.Context, resolver netip.AddrPort) (*Session, error) {
	return p.connect(ctx, resolver, p.standardParameters(), nil)
}

func (p Profile) connect(ctx context.Context, resolver netip.AddrPort, parameters connectionParameters, progress func(string)) (*Session, error) {
	if progress != nil {
		progress("noise")
	}
	ctx, cancel := context.WithTimeout(ctx, parameters.timeout)
	defer cancel()
	addr := net.UDPAddrFromAddrPort(resolver)
	socket, err := (&net.Dialer{}).DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	packet := NewDNSPacketConn(resolverSocket{socket.(*net.UDPConn)}, addr, p.domain, parameters.udpSize)
	var session *Session
	defer func() {
		if session == nil {
			_ = packet.Close()
		}
	}()

	conn, err := kcp.NewConn2(addr, nil, 0, 0, packet)
	if err != nil {
		return nil, err
	}
	defer func() {
		if session == nil {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = packet.Close(); _ = conn.Close() })
	defer stop()
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !conn.SetMtu(parameters.mtu) {
		return nil, ErrTunnel
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	channel, err := noise.NewClient(conn, p.key)
	if err != nil {
		if timeout := connectionTimeout(ctx, err); timeout != nil {
			return nil, timeout
		}
		return nil, fmt.Errorf("%w: %w", ErrTunnel, err)
	}

	config := smux.DefaultConfig()
	config.Version = 2
	config.KeepAliveTimeout = 2 * time.Minute
	config.MaxStreamBuffer = 1024 * 1024
	mux, err := smux.Client(channel, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		if session == nil {
			_ = mux.Close()
		}
	}()
	stream, err := mux.OpenStream()
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(deadline)
	sshConfig := *p.ssh
	var hostVerified atomic.Bool
	if progress != nil {
		progress("ssh")
		checkHost := sshConfig.HostKeyCallback
		sshConfig.HostKeyCallback = func(host string, remote net.Addr, key ssh.PublicKey) error {
			if err := checkHost(host, remote, key); err != nil {
				return err
			}
			hostVerified.Store(true)
			return nil
		}
	}
	var sshStream net.Conn = stream
	var wire *sshWireBytes
	if progress != nil {
		wire = &sshWireBytes{Conn: stream}
		sshStream = wire
	}
	sshConn, channels, requests, err := ssh.NewClientConn(sshStream, addr.String(), &sshConfig)
	if progress != nil && hostVerified.Load() {
		progress("ssh-auth")
	}
	if err != nil {
		if errors.Is(err, ErrHostKey) {
			return nil, ErrHostKey
		}
		failure := connectionTimeout(ctx, err)
		if failure == nil {
			failure = fmt.Errorf("%w: %w", ErrSSH, err)
		}
		if wire != nil {
			failure = &sshExchangeError{err: failure, sent: wire.sent.Load(), received: wire.received.Load()}
		}
		return nil, failure
	}
	if !stop() {
		_ = sshConn.Close()
		return nil, ctx.Err()
	}
	_ = stream.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})
	session = &Session{Client: ssh.NewClient(sshConn, channels, requests), mux: mux, kcp: conn, packet: packet}
	if negotiated, ok := sshConn.(ssh.AlgorithmsConnMetadata); ok {
		session.keyExchange = negotiated.Algorithms().KeyExchange
	}
	return session, nil
}

type sshWireBytes struct {
	net.Conn
	sent, received atomic.Int64
}

func (c *sshWireBytes) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received.Add(int64(n))
	return n, err
}

func (c *sshWireBytes) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent.Add(int64(n))
	return n, err
}

type sshExchangeError struct {
	err            error
	sent, received int64
}

func (e *sshExchangeError) Error() string { return e.err.Error() }
func (e *sshExchangeError) Unwrap() error { return e.err }

func connectionTimeout(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var networkError net.Error
	if errors.Is(err, smux.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return nil
}
