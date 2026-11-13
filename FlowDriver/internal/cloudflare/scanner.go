package cloudflare

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Published Cloudflare reverse proxy prefixes. https://www.cloudflare.com/ips/
var prefixes = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

type Result struct {
	IP                 string  `json:"ip"`
	Successes          int     `json:"successes"`
	Attempts           int     `json:"attempts"`
	Milliseconds       int     `json:"milliseconds"`
	Mbps               float64 `json:"mbps"`
	UploadMbps         float64 `json:"uploadMbps,omitempty"`
	UploadSuccesses    int     `json:"uploadSuccesses,omitempty"`
	UploadAttempts     int     `json:"uploadAttempts,omitempty"`
	UploadSizesKiB     []int   `json:"uploadSizesKiB,omitempty"`
	JitterMilliseconds *int    `json:"jitterMilliseconds,omitempty"`
	Stage              string  `json:"stage,omitempty"`
}

type ScanUpdate struct {
	Phase     string            `json:"phase"`
	Done      int               `json:"done"`
	Total     int               `json:"total"`
	Reachable int               `json:"reachable"`
	Results   []Result          `json:"results,omitempty"`
	Log       string            `json:"log,omitempty"`
	Discovery *discoverySummary `json:"discovery,omitempty"`
}

type discoverySummary struct {
	TCPFailures       int `json:"tcpFailures"`
	TLSFailures       int `json:"tlsFailures"`
	WebSocketFailures int `json:"webSocketFailures"`
}

func (s *discoverySummary) record(result candidate) {
	for _, step := range result.timing.steps {
		if step.ok {
			continue
		}
		switch step.name {
		case "TCP":
			s.TCPFailures++
		case "TLS":
			s.TLSFailures++
		case "WebSocket":
			s.WebSocketFailures++
		}
		return
	}
}

func isCloudflare(addr netip.Addr) bool {
	for _, entry := range prefixes {
		if netip.MustParsePrefix(entry).Contains(addr) {
			return true
		}
	}
	return false
}

func (p Profile) withEdge(addr netip.Addr) Profile {
	_, port, _ := net.SplitHostPort(p.address)
	p.address = net.JoinHostPort(addr.String(), port)
	return p
}

// LinkForEdge preserves the profile credentials, real SNI, Host, port and path.
func LinkForEdge(link, ip string, targets Targets) (string, error) {
	profile, err := Parse(link)
	addr, addrErr := netip.ParseAddr(ip)
	if err != nil || addrErr != nil || !targets.allows(addr) {
		return "", invalid
	}
	u := profile.endpoint
	u.Scheme = "vless"
	u.User = profileUser(profile.userID)
	u.Host = profile.withEdge(addr).address
	q := u.Query()
	for key := range q {
		q.Del(key)
	}
	q.Set("type", "ws")
	q.Set("security", "tls")
	q.Set("encryption", "none")
	q.Set("alpn", "http/1.1")
	q.Set("sni", profile.serverName)
	q.Set("host", profile.serverName)
	q.Set("path", profile.endpoint.RequestURI())
	u.Path, u.RawPath, u.ForceQuery = "", "", false
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func candidates(ctx context.Context, profile Profile, deep bool, previous []netip.Addr, targets Targets) (seeds, samples []netip.Addr, dnsLog string) {
	seen := make(map[netip.Addr]bool)
	add := func(list *[]netip.Addr, ip netip.Addr) {
		ip = ip.Unmap()
		if targets.allows(ip) && !seen[ip] {
			*list = append(*list, ip)
			seen[ip] = true
		}
	}
	host, _, _ := net.SplitHostPort(profile.address)
	if addr, err := netip.ParseAddr(host); err == nil {
		add(&seeds, addr)
	}
	dnsStart := time.Now()
	dns, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	addresses, err := net.DefaultResolver.LookupNetIP(dns, "ip", profile.serverName)
	cancel()
	dnsElapsed := time.Since(dnsStart).Milliseconds()
	if err != nil {
		var dnsError *net.DNSError
		reason := "lookup failed"
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsError) && dnsError.Timeout() {
			reason = "timeout"
		} else if errors.As(err, &dnsError) && dnsError.IsNotFound {
			reason = "no DNS record"
		}
		dnsLog = fmt.Sprintf("DNS for configured host: %s after %d ms. IP probes continue independently.", reason, dnsElapsed)
	} else {
		allowed := 0
		for _, addr := range addresses[:min(8, len(addresses))] {
			if targets.allows(addr.Unmap()) {
				allowed++
				add(&seeds, addr)
			}
		}
		dnsLog = fmt.Sprintf("DNS for configured host: %d address(es) in %d ms; %d accepted for priority checks.",
			len(addresses), dnsElapsed, allowed)
	}
	for _, ip := range previous[:min(5, len(previous))] {
		add(&seeds, ip)
	}
	for _, ip := range targets.IPs {
		add(&seeds, ip)
	}
	return seeds, discoverySamples(deep, targets, seen), dnsLog
}

func discoverySamples(deep bool, targets Targets, seen map[netip.Addr]bool) []netip.Addr {
	var samples []netip.Addr
	count := 2
	if deep {
		count = 3
	}
	for _, prefix := range targets.ranges() {
		for _, ip := range spreadSamples(prefix, count) {
			if targets.allows(ip) && !seen[ip] {
				samples = append(samples, ip)
				seen[ip] = true
			}
		}
	}
	mathrand.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	return samples
}

func sample(prefix netip.Prefix) netip.Addr {
	base := prefix.Addr().AsSlice()
	random := make([]byte, len(base))
	_, _ = rand.Read(random)
	for bit := prefix.Bits(); bit < len(base)*8; bit++ {
		mask := byte(128 >> (bit % 8))
		base[bit/8] = (base[bit/8] &^ mask) | (random[bit/8] & mask)
	}
	ip, _ := netip.AddrFromSlice(base)
	return ip
}

type candidate struct {
	timing  handshakeTiming
	ip      netip.Addr
	upgrade time.Duration
	failure string
	noRoute bool
}

func probe(ctx context.Context, profile Profile, transferBytes int64) (time.Duration, float64, error) {
	started := time.Now()
	var firstByte time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte = time.Now() }}
	url := "https://speed.cloudflare.com/__down?bytes=" + strconv.FormatInt(transferBytes, 10)
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	client := speedClient(ctx, profile)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	size, err := io.Copy(io.Discard, io.LimitReader(response.Body, transferBytes+1))
	if err != nil {
		return 0, 0, err
	}
	if response.StatusCode != http.StatusOK || size != transferBytes || firstByte.IsZero() {
		return 0, 0, fmt.Errorf("unexpected HTTPS response: status %d and %d bytes", response.StatusCode, size)
	}
	elapsed := time.Since(firstByte)
	return firstByte.Sub(started), float64(size) * 8 / (elapsed.Seconds() * 1e6), nil
}

func speedClient(ctx context.Context, profile Profile) *http.Client {
	transport := &http.Transport{
		DialContext: func(_ context.Context, network, target string) (net.Conn, error) {
			return profile.Dial(ctx, network, target)
		},
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func probeUpload(ctx context.Context, profile Profile, payload []byte) (float64, error) {
	var timing sync.Mutex
	var start, ack time.Time
	written := make(chan error, 1)
	trace := &httptrace.ClientTrace{
		WroteHeaders: func() {
			timing.Lock()
			start = time.Now()
			timing.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			select {
			case written <- info.Err:
			default:
			}
		},
		GotFirstResponseByte: func() {
			timing.Lock()
			ack = time.Now()
			timing.Unlock()
		},
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost,
		"https://speed.cloudflare.com/__up", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	client := speedClient(ctx, profile)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected upload response: HTTP %d", response.StatusCode)
	}
	select {
	case err := <-written:
		if err != nil {
			return 0, err
		}
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	timing.Lock()
	defer timing.Unlock()
	if start.IsZero() || !ack.After(start) {
		return 0, fmt.Errorf("unexpected upload response timing")
	}
	return float64(len(payload)) * 8 / (ack.Sub(start).Seconds() * 1e6), nil
}

func scanBatch[T any, U any](ctx context.Context, inputs []T, concurrency int, run func(T) U, report func(U, int)) {
	jobs := make(chan T)
	completed := make(chan U, concurrency)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				completed <- run(job)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, job := range inputs {
			select {
			case jobs <- job:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(completed) }()
	done := 0
	for result := range completed {
		done++
		if ctx.Err() == nil {
			report(result, done)
		}
	}
}

func Scan(ctx context.Context, profile Profile, deep bool, previous []netip.Addr, targets Targets, report func(ScanUpdate)) {
	started := time.Now()
	report(ScanUpdate{Phase: "preparing", Log: fmt.Sprintf("Preparing recent results, DNS, %d explicit IPs and randomized samples from %d CIDRs.", len(targets.IPs), len(targets.ranges()))})
	seeds, samples, dnsLog := candidates(ctx, profile, deep, previous, targets)
	if ctx.Err() == nil {
		report(ScanUpdate{Phase: "preparing", Log: dnsLog})
	}

	// The two IPv6 probes share the ordinary discovery batch with known
	// routes. Only explicit no-route errors suppress the remaining IPv6 work.
	initial := slices.Clone(seeds)
	ipv6Prefixes := make(map[netip.Prefix]bool)
	for _, ip := range initial {
		if ip.Is6() {
			ipv6Prefixes[netip.PrefixFrom(ip, 32).Masked()] = true
		}
	}
	for _, ip := range samples {
		if len(ipv6Prefixes) >= 2 {
			break
		}
		if ip.Is6() {
			prefix := netip.PrefixFrom(ip, 32).Masked()
			if !ipv6Prefixes[prefix] {
				ipv6Prefixes[prefix] = true
				initial = append(initial, ip)
			}
		}
	}

	tested := make(map[netip.Addr]bool)
	var reachable []candidate
	failures := make(map[string]int)
	timeouts := make(map[netip.Addr]bool)
	retryable := make(map[netip.Addr]bool)
	retried := make(map[netip.Addr]bool)
	var discovery discoverySummary
	ipv6Routes, ipv6NoRoutes := 0, 0
	check := func(phase string, addresses []netip.Addr, timeout time.Duration, startMessage string) {
		if len(addresses) == 0 || ctx.Err() != nil {
			return
		}
		report(ScanUpdate{Phase: phase, Total: len(addresses), Reachable: len(reachable), Log: startMessage})
		scanBatch(ctx, addresses, 8, func(ip netip.Addr) candidate {
			attempt, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			timing, err := profile.withEdge(ip).checkTiming(attempt)
			if err != nil {
				return candidate{ip: ip, failure: failureReason(err), noRoute: isNoRoute(err), timing: timing}
			}
			return candidate{ip: ip, upgrade: time.Since(start), timing: timing}
		}, func(result candidate, done int) {
			tested[result.ip] = true
			timeouts[result.ip] = result.failure == "timeout"
			retryable[result.ip] = timeouts[result.ip] || result.failure == "TCP connection reset" ||
				result.failure == "connection closed before completing the request"
			detail := fmt.Sprintf("%s · %s.", result.ip, result.failure)
			if result.ip.Is6() {
				ipv6Routes++
				if result.noRoute {
					ipv6NoRoutes++
				}
			}
			if result.upgrade > 0 {
				reachable = append(reachable, result)
				detail = fmt.Sprintf("%s · WebSocket upgrade passed in %d ms.", result.ip, result.upgrade.Milliseconds())
			} else {
				failures[result.failure]++
				discovery.record(result)
			}
			if phases := result.timing.String(); phases != "" {
				detail += " " + phases + "."
			}
			report(ScanUpdate{Phase: phase, Done: done, Total: len(addresses), Reachable: len(reachable), Log: detail})
		})
		slices.SortFunc(reachable, func(a, b candidate) int {
			if a.upgrade < b.upgrade {
				return -1
			}
			if a.upgrade > b.upgrade {
				return 1
			}
			return a.ip.Compare(b.ip)
		})
	}

	priorityTimeout := 2500 * time.Millisecond
	if deep {
		priorityTimeout = 4 * time.Second
	}
	check("checking", initial, priorityTimeout,
		fmt.Sprintf("Priority checks: %d addresses from the saved profile, DNS, recent results, explicit IPs and IPv6 route checks.", len(initial)))
	skipIPv6 := ipv6Routes >= 2 && ipv6NoRoutes == ipv6Routes
	remaining := make([]netip.Addr, 0, len(samples))
	skipped := 0
	for _, ip := range samples {
		if tested[ip] {
			continue
		}
		if skipIPv6 && ip.Is6() && !slices.Contains(targets.IPs, ip) {
			skipped++
			continue
		}
		remaining = append(remaining, ip)
	}
	if skipped > 0 && ctx.Err() == nil {
		report(ScanUpdate{Phase: "checking", Total: len(remaining), Reachable: len(reachable),
			Log: fmt.Sprintf("IPv6: all %d priority probes reported no network route. Skipping %d IPv6 samples for this scan.", ipv6Routes, skipped)})
	}
	sampleTimeout := 2500 * time.Millisecond
	if deep {
		sampleTimeout = 3 * time.Second
	}
	check("checking", remaining, sampleTimeout, fmt.Sprintf("Discovery: checking TLS and WebSocket on %d random addresses.", len(remaining)))

	if len(reachable) == 0 && ctx.Err() == nil {
		priority := make([]netip.Addr, 0, len(seeds))
		for _, ip := range seeds {
			if retryable[ip] {
				priority = append(priority, ip)
				retried[ip] = true
			}
		}
		check("refining", priority, 6*time.Second,
			fmt.Sprintf("Retrying %d priority addresses once after a timeout, reset or early close, with a 6s deadline.", len(priority)))
	}

	if len(reachable) == 0 && ctx.Err() == nil {
		seen := maps.Clone(tested)
		extra := discoverySamples(false, targets, seen)
		retry := make([]netip.Addr, 0, len(extra))
		for _, ip := range extra {
			if !skipIPv6 || ip.Is4() {
				retry = append(retry, ip)
			}
		}
		check("refining", retry, 3500*time.Millisecond,
			fmt.Sprintf("No WebSocket passed yet. Checking %d fresh samples with a 3.5s deadline.", len(retry)))
	}

	if ctx.Err() == nil && len(reachable) > 0 {
		ranges := targets.ranges()
		good := make(map[netip.Prefix]bool)
		for _, route := range reachable {
			if subnet, ok := neighborhood(route.ip, ranges); ok {
				good[subnet] = true
			}
		}
		var retry []netip.Addr
		for _, ip := range targets.IPs {
			if timeouts[ip] && !retried[ip] {
				retry = append(retry, ip)
			}
		}
		neighbors := 0
		for _, ip := range samples {
			if !timeouts[ip] || slices.Contains(retry, ip) {
				continue
			}
			if subnet, ok := neighborhood(ip, ranges); ok && good[subnet] {
				retry = append(retry, ip)
				neighbors++
				if neighbors == 12 {
					break
				}
			}
		}
		check("refining", retry, 4500*time.Millisecond,
			fmt.Sprintf("Retrying %d timed-out explicit IPs or neighbors of working routes.", len(retry)))
	}

	seen := make([]netip.Addr, 0, len(tested))
	for ip := range tested {
		seen = append(seen, ip)
	}
	nearby := refine(seen, reachable, deep, targets)
	check("refining", nearby, sampleTimeout,
		fmt.Sprintf("Refinement: checking %d new addresses in subnet neighborhoods that passed.", len(nearby)))

	shortlist := make([]netip.Addr, 0, len(reachable))
	for _, item := range reachable {
		shortlist = append(shortlist, item.ip)
	}
	qualify := rank(ctx, profile, shortlist, false, deep, len(reachable), report)
	finalAddresses := make([]netip.Addr, 0, len(qualify))
	for _, item := range qualify {
		if item.Successes > 0 {
			finalAddresses = append(finalAddresses, netip.MustParseAddr(item.IP))
		}
	}
	slots := 4
	if deep {
		slots = 6
	}
	finalists := min(slots, len(finalAddresses))
	strict := rank(ctx, profile, finalAddresses[:finalists], true, deep, len(reachable), report)
	if !slices.ContainsFunc(strict, confirmed) && finalists < len(finalAddresses) && ctx.Err() == nil {
		backup := finalAddresses[finalists:min(finalists+3, len(finalAddresses))]
		report(ScanUpdate{Phase: "final", Total: len(backup), Reachable: len(reachable),
			Log: "No finalist passed both directions. Retesting the next qualified addresses."})
		strict = append(strict, rank(ctx, profile, backup, true, deep, len(reachable), report)...)
	}
	ranked := mergeResults(qualify, strict)
	phase := "finished"
	summary := "No address completed every final download and upload. Preliminary results are retained."
	if len(reachable) == 0 {
		summary = "No WebSocket upgrade succeeded."
	} else if len(ranked) != 0 && confirmed(ranked[0]) {
		best := ranked[0]
		summary = fmt.Sprintf("Winner: %s. %d/%d downloads, %d/%d uploads, %d ms median, %s, %.1f Mbps down and %.1f Mbps up.",
			best.IP, best.Successes, best.Attempts, best.UploadSuccesses, best.UploadAttempts,
			best.Milliseconds, jitterText(best.JitterMilliseconds), best.Mbps, best.UploadMbps)
	}
	if ctx.Err() != nil {
		phase, summary = "cancelled", "Scan cancelled."
		ranked = nil
	}
	report(ScanUpdate{Phase: phase, Done: len(ranked), Total: len(tested), Reachable: len(reachable), Results: ranked,
		Discovery: &discovery,
		Log: fmt.Sprintf("%s Checked %d unique IPs in %.1fs. Failed attempts: %d TCP, %d TLS, %d WebSocket. %d timeouts, %d resets. %d WebSocket routes.",
			summary, len(tested), time.Since(started).Seconds(), discovery.TCPFailures, discovery.TLSFailures,
			discovery.WebSocketFailures, failures["timeout"], failures["TCP connection reset"], len(reachable))})
}

func confirmed(result Result) bool {
	return result.Attempts > 0 && result.Successes == result.Attempts &&
		result.UploadAttempts > 0 && result.UploadSuccesses == result.UploadAttempts
}

func mergeResults(qualified, finalists []Result) []Result {
	measured := make(map[string]Result, len(finalists))
	for _, result := range finalists {
		measured[result.IP] = result
	}
	for i, result := range qualified {
		if updated, ok := measured[result.IP]; ok {
			qualified[i] = updated
		}
	}
	sortResults(qualified)
	return qualified
}

func neighborhood(ip netip.Addr, ranges []netip.Prefix) (netip.Prefix, bool) {
	width := 24
	if ip.Is6() {
		width = 64
	}
	found := false
	for _, prefix := range ranges {
		if prefix.Contains(ip) {
			found = true
			width = max(width, prefix.Bits())
		}
	}
	return netip.PrefixFrom(ip, width).Masked(), found
}

func refine(initial []netip.Addr, ranked []candidate, deep bool, targets Targets) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(initial))
	for _, ip := range initial {
		seen[ip] = true
	}
	ranges := targets.ranges()
	seenSubnets := make(map[netip.Prefix]bool)
	var groups [][]netip.Addr
	count, budget := 4, 32
	if deep {
		count, budget = 8, 72
	}
	for _, route := range ranked {
		subnet, allowed := neighborhood(route.ip, ranges)
		if !allowed {
			continue
		}
		if !seenSubnets[subnet] {
			groups = append(groups, spreadSamples(subnet, count))
			seenSubnets[subnet] = true
		}
	}
	var nearby []netip.Addr
	for round := 0; round < count && len(nearby) < budget; round++ {
		for _, group := range groups {
			if round >= len(group) {
				continue
			}
			ip := group[round]
			if targets.allows(ip) && !seen[ip] {
				nearby = append(nearby, ip)
				seen[ip] = true
				if len(nearby) == budget {
					break
				}
			}
		}
	}
	return nearby
}

func rank(ctx context.Context, profile Profile, ips []netip.Addr, final, deep bool, reachable int, report func(ScanUpdate)) []Result {
	if len(ips) == 0 || ctx.Err() != nil {
		return nil
	}
	phase, label := "transfer", "Qualification"
	downloads, uploads := 2, 0
	downSize, upSize := int64(65536), 128*1024
	timeout, concurrency := 7*time.Second, 4
	if final {
		phase, label = "final", "Final download and upload"
		downloads, uploads = 3, 2
		downSize, concurrency = 262144, 3
		if deep {
			upSize = 256 * 1024
		}
	}
	message := fmt.Sprintf("%s: %d IPs, %d × %d KiB downloads, %gs per download.", label, len(ips), downloads, downSize/1024, timeout.Seconds())
	if uploads > 0 {
		message += fmt.Sprintf(" %d adaptive uploads, 5s per upload.", uploads)
	}
	report(ScanUpdate{Phase: phase, Total: len(ips), Reachable: reachable, Log: message})
	var payload []byte
	if uploads > 0 {
		payload = make([]byte, upSize)
		_, _ = rand.Read(payload)
	}
	type measurement struct {
		result   Result
		failures []string
	}
	var ranked []Result
	scanBatch(ctx, ips, concurrency, func(ip netip.Addr) measurement {
		result := Result{IP: ip.String(), Attempts: downloads, UploadAttempts: uploads, Stage: "qualification"}
		if final {
			result.Stage = "final"
		}
		edge := profile.withEdge(ip)
		var latencies []int
		var speeds, uploadSpeeds []float64
		var failures []string
		for i := 0; i < downloads && ctx.Err() == nil; i++ {
			attempt, cancel := context.WithTimeout(ctx, timeout)
			latency, speed, err := probe(attempt, edge, downSize)
			cancel()
			if err != nil {
				failures = append(failures, fmt.Sprintf("download %d: %s", i+1, failureReason(err)))
				continue
			}
			latencies = append(latencies, int(latency.Milliseconds()))
			speeds = append(speeds, speed)
		}
		result.Successes = len(latencies)
		if len(latencies) > 0 {
			result.JitterMilliseconds = responseJitter(latencies)
			result.Milliseconds = median(latencies)
			result.Mbps = median(speeds)
		}
		// A failed download does not rule out a usable uplink. Both
		// directions are measured independently on every finalist.
		size := 16 * 1024
		for i := 0; i < uploads && ctx.Err() == nil; i++ {
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			result.UploadSizesKiB = append(result.UploadSizesKiB, size/1024)
			speed, err := probeUpload(attempt, edge, payload[:size])
			cancel()
			if err != nil {
				failures = append(failures, fmt.Sprintf("upload %d (%d KiB): %s", i+1, size/1024, failureReason(err)))
				size = 4 * 1024
				continue
			}
			uploadSpeeds = append(uploadSpeeds, speed)
			// Choose a second payload estimated to fit within two seconds
			// at the rate the first request actually achieved.
			size = adaptiveUploadSize(speed, len(payload))
		}
		result.UploadSuccesses = len(uploadSpeeds)
		if len(uploadSpeeds) != 0 {
			result.UploadMbps = median(uploadSpeeds)
		}
		return measurement{result, failures}
	}, func(sample measurement, done int) {
		item := sample.result
		ranked = append(ranked, item)
		detail := fmt.Sprintf("%s · %d/%d downloads", item.IP, item.Successes, item.Attempts)
		if item.Successes > 0 {
			detail += fmt.Sprintf(" · median %d ms, %s, %.1f Mbps down", item.Milliseconds, jitterText(item.JitterMilliseconds), item.Mbps)
		}
		if item.UploadAttempts > 0 {
			detail += fmt.Sprintf(" · %d/%d uploads, payloads %v KiB", item.UploadSuccesses, item.UploadAttempts, item.UploadSizesKiB)
			if item.UploadSuccesses > 0 {
				detail += fmt.Sprintf(", %.1f Mbps up", item.UploadMbps)
			}
		}
		if len(sample.failures) != 0 {
			detail += " · " + strings.Join(sample.failures, " | ")
		}
		report(ScanUpdate{Phase: phase, Done: done, Total: len(ips), Reachable: reachable, Log: detail + "."})
	})
	sortResults(ranked)
	return ranked
}

func adaptiveUploadSize(mbps float64, limit int) int {
	estimatedKiB := min(mbps*2e6/(8*1024), float64(limit/1024))
	return max(4, int(estimatedKiB)) * 1024
}

func median[T ~int | ~float64](values []T) T {
	slices.Sort(values)
	n := len(values)
	return (values[(n-1)/2] + values[n/2]) / 2
}

func responseJitter(latencies []int) *int {
	if len(latencies) < 2 {
		return nil
	}
	total := 0
	for i := 1; i < len(latencies); i++ {
		delta := latencies[i] - latencies[i-1]
		total += max(delta, -delta)
	}
	jitter := (total + (len(latencies)-1)/2) / (len(latencies) - 1)
	return &jitter
}

func jitterText(jitter *int) string {
	if jitter == nil {
		return "jitter unavailable"
	}
	return fmt.Sprintf("%d ms jitter", *jitter)
}

func sortResults(results []Result) {
	type group struct{ tier, success int }
	classification := func(result Result) group {
		switch {
		case confirmed(result):
			return group{3, result.Successes}
		case result.Successes == 0:
			return group{0, result.UploadSuccesses}
		case result.Stage == "final":
			return group{2, result.Successes}
		default:
			return group{1, result.Successes}
		}
	}
	fastest := make(map[group]int)
	for _, result := range results {
		key := classification(result)
		minimum, found := fastest[key]
		if !found || result.Milliseconds < minimum {
			fastest[key] = result.Milliseconds
		}
	}
	band := func(result Result, key group) int {
		floor := fastest[key]
		return (result.Milliseconds - floor) / max(75, floor/10)
	}
	jitterBand := func(result Result) int {
		if result.JitterMilliseconds == nil {
			return math.MaxInt
		}
		return *result.JitterMilliseconds / 25
	}
	throughput := func(result Result) float64 {
		if result.UploadSuccesses > 0 {
			return math.Sqrt(result.Mbps * result.UploadMbps)
		}
		return result.Mbps
	}
	slices.SortFunc(results, func(a, b Result) int {
		x, y := classification(a), classification(b)
		if x.tier != y.tier {
			return y.tier - x.tier
		}
		if x.success != y.success {
			return y.success - x.success
		}
		if a.UploadSuccesses != b.UploadSuccesses {
			return b.UploadSuccesses - a.UploadSuccesses
		}
		if band(a, x) != band(b, y) {
			return band(a, x) - band(b, y)
		}
		if jitterBand(a) != jitterBand(b) {
			if jitterBand(a) < jitterBand(b) {
				return -1
			}
			return 1
		}
		if throughput(a) > throughput(b) {
			return -1
		}
		if throughput(a) < throughput(b) {
			return 1
		}
		if a.Milliseconds != b.Milliseconds {
			return a.Milliseconds - b.Milliseconds
		}
		return strings.Compare(a.IP, b.IP)
	})
}

func isNoRoute(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EAFNOSUPPORT)
}

func failureReason(err error) string {
	message := err.Error()
	lower := strings.ToLower(message)
	var certificateError *tls.CertificateVerificationError
	switch {
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline"):
		return "timeout"
	case strings.Contains(message, "WebSocket upgrade rejected: HTTP"):
		return message[strings.Index(message, "WebSocket upgrade rejected: HTTP"):]
	case isNoRoute(err):
		return "no network route"
	case strings.Contains(message, "connection reset"):
		return "TCP connection reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "TCP connection refused"
	case errors.As(err, &certificateError):
		return "TLS certificate validation failed"
	case strings.Contains(message, "EOF"):
		return "connection closed before completing the request"
	case strings.Contains(message, "unexpected HTTPS response"), strings.Contains(message, "unexpected upload response"):
		return message
	case strings.Contains(lower, "tls"), strings.Contains(lower, "x509"):
		return "TLS validation or handshake failed"
	default:
		return "tunnel closed before completing HTTPS"
	}
}

func profileUser(id [16]byte) *url.Userinfo {
	return url.User(fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]))
}
