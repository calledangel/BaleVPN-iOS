package dnstunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Diagnostic struct {
	Status       string `json:"status"`
	Line         string `json:"line"`
	Milliseconds int    `json:"milliseconds,omitempty"`
}

func (p Profile) Diagnose(ctx context.Context, resolver netip.AddrPort, deep bool, report func(Diagnostic)) {
	report(Diagnostic{"testing", "Testing configured resolver.", 0})
	if deep {
		p.checkDNS(ctx, resolver, report)
	}
	choice := p.standardParameters()
	attempts := 1
	if deep {
		attempts = 2
	}
	var last Diagnostic
	var forwarded Diagnostic
	for index := range attempts {
		if ctx.Err() != nil {
			return
		}
		phase := "noise"
		start := time.Now()
		session, err := p.connect(ctx, resolver, choice, func(stage string) {
			phase = stage
			switch stage {
			case "noise":
				line := fmt.Sprintf("Attempt %d/%d: %s; DNSTT Noise handshake (EDNS=%d, KCP MTU=%d, deadline %s).",
					index+1, attempts, choice.name, choice.udpSize, choice.mtu, choice.timeout)
				report(Diagnostic{"testing", line, 0})
			case "ssh":
				report(Diagnostic{"testing", "DNSTT authenticated. Starting pinned SSH key exchange.", elapsed(start)})
			case "ssh-auth":
				report(Diagnostic{"testing", "Pinned SSH host key verified; entered user authentication.", 0})
			}
		})
		if err == nil {
			ms := elapsed(start)
			keyExchange := "SSH authenticated"
			if session.keyExchange != "" {
				keyExchange += " (" + session.keyExchange + ")"
			}
			if !deep {
				session.Close()
				report(Diagnostic{"verified", keyExchange + ".", ms})
				return
			}
			report(Diagnostic{"testing", keyExchange + ". Checking HTTPS over the tunnel.", ms})
			code, checkErr := checkForwarding(ctx, session, 10*time.Second)
			session.Close()
			switch {
			case checkErr != nil:
				last = Diagnostic{"ssh_ready", "SSH authenticated; HTTPS transfer failed (" + issue(checkErr) + ").", ms}
			case code != http.StatusOK:
				last = Diagnostic{"ssh_ready", fmt.Sprintf("SSH authenticated; HTTPS probe returned HTTP %d.", code), ms}
			default:
				report(Diagnostic{"verified", "Authenticated tunnel returned HTTPS 200 using " + choice.name + ".", elapsed(start)})
				return
			}
			forwarded = last
			break
		} else {
			if ctx.Err() != nil {
				return
			}
			var exchange *sshExchangeError
			if errors.As(err, &exchange) {
				line := fmt.Sprintf("SSH stream before failure: %d bytes accepted for send, %d bytes received.",
					exchange.sent, exchange.received)
				report(Diagnostic{"testing", line, 0})
			}
			reason := issue(err)
			last = failureAt(phase, reason, elapsed(start))
			switch {
			case errors.Is(err, ErrHostKey):
				report(Diagnostic{"host_key_mismatch", "SSH server key differs from the pinned key.", elapsed(start)})
				return
			case errors.Is(err, ErrSSH):
				if phase == "ssh-auth" {
					last = Diagnostic{"ssh_failed", "SSH user authentication or its transport failed after the pinned host key was verified.", elapsed(start)}
				}
				report(last)
				return
			case reason == "permission denied" || reason == "network unreachable":
				report(last)
				return
			}
		}
		if index+1 < attempts {
			report(Diagnostic{"testing", last.Line + " Trying the next parameter set.", last.Milliseconds})
		}
	}
	if ctx.Err() == nil {
		if forwarded.Status != "" {
			last = forwarded
		}
		report(last)
	}
}

func failureAt(phase, reason string, milliseconds int) Diagnostic {
	switch phase {
	case "ssh-auth":
		return Diagnostic{"ssh_stage_failed", "SSH user authentication failed (" + reason + ").", milliseconds}
	case "ssh":
		return Diagnostic{"ssh_stage_failed", "SSH transport/key exchange failed before host-key verification (" + reason + ").", milliseconds}
	default:
		return Diagnostic{"tunnel_failed", "DNSTT Noise handshake failed (" + reason + ").", milliseconds}
	}
}

func elapsed(since time.Time) int { return max(1, int(time.Since(since).Milliseconds())) }

func issue(err error) string {
	var networkError net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		return "deadline exceeded"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network unreachable"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "permission denied"
	default:
		return "no valid exchange"
	}
}

func (p Profile) checkDNS(ctx context.Context, resolver netip.AddrPort, report func(Diagnostic)) {
	query, err := dnsmessage.NewName(p.domain.String() + ".")
	if err != nil {
		return
	}
	// Test the ordinary resolver path with an SOA query at the configured
	// zone's parent, then query the exact tunnel zone using TXT + EDNS.
	parent := query
	if len(p.domain) > 2 {
		parent, _ = dnsmessage.NewName(p.domain[1:].String() + ".")
	}
	probe := func(network string, name dnsmessage.Name, kind dnsmessage.Type, edns bool, label string) bool {
		if ctx.Err() != nil {
			return false
		}
		start := time.Now()
		header, err := dnsQuery(ctx, network, resolver, name, kind, edns)
		if err != nil {
			report(Diagnostic{"testing", label + ": " + issue(err) + ".", elapsed(start)})
			return false
		}
		report(Diagnostic{"testing", fmt.Sprintf("%s: %s, RA=%t, TC=%t.", label, header.RCode, header.RecursionAvailable, header.Truncated), elapsed(start)})
		return true
	}
	udpOK := probe("udp", parent, dnsmessage.TypeSOA, false, "UDP DNS / SOA")
	txtOK := probe("udp", query, dnsmessage.TypeTXT, true, "UDP DNS / TXT + EDNS")
	if !udpOK && !txtOK && resolver.Port() == 53 {
		probe("tcp", parent, dnsmessage.TypeSOA, false, "TCP/53 DNS / SOA")
	}
}

func dnsQuery(ctx context.Context, network string, resolver netip.AddrPort, name dnsmessage.Name, kind dnsmessage.Type, edns bool) (dnsmessage.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return dnsmessage.Header{}, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(random[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}},
	}
	if edns {
		root := dnsmessage.MustNewName(".")
		msg.Additionals = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232},
			Body:   &dnsmessage.OPTResource{},
		}}
	}
	wire, err := msg.Pack()
	if err != nil {
		return dnsmessage.Header{}, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, resolver.String())
	if err != nil {
		return dnsmessage.Header{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if network == "tcp" {
		wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	if _, err := conn.Write(wire); err != nil {
		return dnsmessage.Header{}, err
	}
	var buffer [4096]byte
	var n int
	if network == "tcp" {
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return dnsmessage.Header{}, err
		}
		n = int(binary.BigEndian.Uint16(size[:]))
		if n > len(buffer) {
			return dnsmessage.Header{}, errors.New("oversize DNS probe response")
		}
		_, err = io.ReadFull(conn, buffer[:n])
	} else {
		n, err = conn.Read(buffer[:])
	}
	if err != nil {
		if ctx.Err() != nil {
			return dnsmessage.Header{}, ctx.Err()
		}
		return dnsmessage.Header{}, err
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(buffer[:n])
	if err != nil || !header.Response || header.ID != msg.ID {
		return dnsmessage.Header{}, errors.New("invalid DNS response")
	}
	question, err := parser.Question()
	if err != nil || question.Type != kind || question.Class != dnsmessage.ClassINET ||
		!strings.EqualFold(question.Name.String(), name.String()) {
		return dnsmessage.Header{}, errors.New("DNS response question did not match")
	}
	return header, nil
}

func checkForwarding(ctx context.Context, session *Session, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{DialContext: session.DialContext, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return 0, err
	}
	reply, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		return reply.StatusCode, nil
	}
	var payload [8]byte
	_, err = io.ReadFull(reply.Body, payload[:])
	return reply.StatusCode, err
}
