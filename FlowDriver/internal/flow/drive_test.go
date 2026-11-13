package flow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDriveRelayHTTPS(t *testing.T) {
	path := os.Getenv("FLOWDRIVER_TEST_PROFILE")
	if path == "" {
		t.Skip("set FLOWDRIVER_TEST_PROFILE to test an active relay")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("profile could not be read")
	}
	profile, err := ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := profile.Backend()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	if err := backend.Login(ctx); err != nil {
		t.Fatal("Drive folder access failed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- StartClient(ctx, profile.Engine(backend, true, hex.EncodeToString(id)), listener) }()
	defer func() { cancel(); <-done }()
	command := exec.CommandContext(ctx, "curl", "--silent", "--show-error", "--fail", "--noproxy", "",
		"--socks5-hostname", listener.Addr().String(), "--max-time", "45",
		"--output", "/dev/null", "--write-out", "%{http_code}", "https://example.com/")
	output, err := command.Output()
	if err != nil || string(output) != "200" {
		t.Fatalf("HTTPS via FlowDriver failed, HTTP %s: %v", output, err)
	}
}
