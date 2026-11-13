package cloudflare

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

const example = "vless://12345678-1234-1234-1234-123456789abc@example.com:8443?security=tls&type=ws&host=example.com&sni=example.com&path=%2Froute%3Fa%3Db"

func TestEdgeSelectionKeepsTLSIdentityAndPath(t *testing.T) {
	link, err := LinkForEdge(example, "2606:4700::1111", Targets{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if profile.address != "[2606:4700::1111]:8443" || profile.serverName != "example.com" ||
		profile.endpoint.RequestURI() != "/route?a=b" {
		t.Fatal("selected edge changed the WebSocket route")
	}
	if _, err := LinkForEdge(example, "1.2.3.4", Targets{}); err == nil {
		t.Fatal("non-Cloudflare address accepted")
	}
	if _, err := Parse(example + "&allowInsecure=true"); err == nil {
		t.Fatal("insecure TLS setting accepted")
	}
	if _, err := Parse(strings.Replace(example, "sni=example.com", "sni=another.example", 1)); err == nil {
		t.Fatal("mismatched SNI accepted")
	}
}

func TestSamplesEveryPublishedPrefix(t *testing.T) {
	profile, err := Parse(example)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, addresses, _ := candidates(ctx, profile, false, nil, Targets{})
	for _, entry := range prefixes {
		prefix := netip.MustParsePrefix(entry)
		count := 0
		for _, ip := range addresses {
			if prefix.Contains(ip) {
				count++
			}
		}
		if count == 0 {
			t.Errorf("no sample for %v", prefix)
		}
	}
}

func TestLiveOwnedProfile(t *testing.T) {
	filename := os.Getenv("BALE_CDN_TEST_PROFILE")
	if filename == "" {
		t.Skip("requires the user's existing VLESS profile")
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal("failed to read private test profile")
	}
	profile, err := Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()
	attempt, end := context.WithTimeout(ctx, 12*time.Second)
	latency, speed, probeError := probe(attempt, profile, 65536)
	end()
	if probeError == nil {
		t.Logf("profile: %v response time, %.1f Mbps sample", latency, speed)
	} else {
		t.Logf("initial profile: %v", probeError)
	}
	var final ScanUpdate
	Scan(ctx, profile, false, nil, Targets{}, func(update ScanUpdate) { final = update })
	if final.Phase != "finished" || len(final.Results) == 0 || !confirmed(final.Results[0]) {
		t.Fatalf("no verified transfer (phase %s, %d WebSocket routes)", final.Phase, final.Reachable)
	}
	for rank, result := range final.Results {
		if confirmed(result) {
			t.Logf("%d %s %d/%d down %d/%d up %d ms %s %.1f Mbps down %.1f Mbps up", rank+1,
				result.IP, result.Successes, result.Attempts, result.UploadSuccesses, result.UploadAttempts,
				result.Milliseconds, jitterText(result.JitterMilliseconds), result.Mbps, result.UploadMbps)
		}
	}
	t.Logf("sampled %d addresses, %d opened WebSocket", final.Total, final.Reachable)
}

func TestRankUsesThroughputOnlyWithinLatencyBand(t *testing.T) {
	result := []Result{
		{IP: "fast", Successes: 3, Milliseconds: 1200, Mbps: 5},
		{IP: "balanced", Successes: 3, Milliseconds: 1270, Mbps: 8},
		{IP: "high-latency", Successes: 3, Milliseconds: 1500, Mbps: 20},
		{IP: "flaky", Successes: 2, Milliseconds: 900, Mbps: 25},
	}
	sortResults(result)
	for i, want := range []string{"balanced", "fast", "high-latency", "flaky"} {
		if result[i].IP != want {
			t.Fatalf("rank %d = %s, want %s", i+1, result[i].IP, want)
		}
	}
}

func TestCustomTargetsNormalizeAndLimitRefinement(t *testing.T) {
	targets, err := ParseTargets("8.8.8.8, 8.8.8.8/32 9.9.9.13/30")
	if err != nil || targets.Canonical != "8.8.8.8\n9.9.9.12/30" {
		t.Fatalf("targets = %+v, %v", targets, err)
	}
	ip := netip.MustParseAddr("9.9.9.13")
	prefix := netip.MustParsePrefix("9.9.9.12/30")
	neighbors := refine([]netip.Addr{ip}, []candidate{{ip: ip}}, true, targets)
	if len(neighbors) != 3 {
		t.Fatalf("expected three untested neighbors, got %v", neighbors)
	}
	for _, neighbor := range neighbors {
		if !prefix.Contains(neighbor) || neighbor == ip {
			t.Fatalf("invalid neighbor %s", neighbor)
		}
	}
	if _, err := LinkForEdge(example, "9.9.9.13", targets); err != nil {
		t.Fatal(err)
	}
	if _, err := LinkForEdge(example, "9.9.9.16", targets); err == nil {
		t.Fatal("address outside supplied CIDR accepted")
	}
	if _, err := ParseTargets("1.1.1.1 10.0.0.0/8"); err == nil {
		t.Fatal("private network accepted")
	}
}

func TestJitterUsesTimeOrderAndPreliminaryRoutesAreRetained(t *testing.T) {
	jitter := responseJitter([]int{100, 160, 110})
	if jitter == nil || *jitter != 55 {
		t.Fatalf("jitter = %v", jitter)
	}
	qualified := []Result{{IP: "a", Attempts: 2, Successes: 2}, {IP: "b", Attempts: 2, Successes: 0}}
	final := []Result{{IP: "a", Attempts: 3, Successes: 3, UploadAttempts: 2, UploadSuccesses: 2}}
	ranked := mergeResults(qualified, final)
	if len(ranked) != 2 || !confirmed(ranked[0]) || ranked[1].IP != "b" {
		t.Fatalf("unexpected ranked results %+v", ranked)
	}
}

func TestAdaptiveUploadSizeFollowsMeasuredRate(t *testing.T) {
	if got := adaptiveUploadSize(0.01, 128*1024); got != 4*1024 {
		t.Fatalf("slow route sample = %d", got)
	}
	if got := adaptiveUploadSize(0.1, 128*1024); got != 24*1024 {
		t.Fatalf("measured route sample = %d", got)
	}
	if got := adaptiveUploadSize(60, 128*1024); got != 128*1024 {
		t.Fatalf("fast route sample = %d", got)
	}
}
