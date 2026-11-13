package flow

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NullLatency/flow-driver/internal/storage"
)

func TestEncryptedStorageRejectsAlteredAndUnencryptedObjects(t *testing.T) {
	dir := t.TempDir()
	raw, err := storage.NewLocalBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	first, err := storage.Encrypted(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := storage.Encrypted(raw, bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const name = "req-a-mux-100.bin"
	plaintext := []byte("sample proxy destination and payload")
	if err := first.Upload(ctx, name, bytes.NewReader(plaintext)); err != nil {
		t.Fatal(err)
	}
	names, err := raw.ListQuery(ctx, "flow-v1-")
	if err != nil || len(names) != 1 {
		t.Fatalf("expected one encrypted object, got %d (%v)", len(names), err)
	}
	prefix := strings.TrimSuffix(names[0], name)
	path := filepath.Join(dir, names[0])
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, plaintext) {
		t.Fatal("plaintext in storage")
	}
	otherNames, err := other.ListQuery(ctx, "req-")
	if err != nil || len(otherNames) != 0 {
		t.Fatalf("objects visible to wrong profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, prefix+"req-b-mux-100.bin"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Download(ctx, "req-b-mux-100.bin"); !errors.Is(err, storage.ErrInvalidObject) {
		t.Fatalf("unexpected error for renamed object: %v", err)
	}
	wire[len(wire)-1] ^= 1
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Download(ctx, name); !errors.Is(err, storage.ErrInvalidObject) {
		t.Fatalf("unexpected error for modified object: %v", err)
	}
}

func TestSOCKSForwardsThroughEncryptedStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, err := storage.NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x32}, 32)
	clientStore, err := storage.Encrypted(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	relayStore, err := storage.Encrypted(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	target := make(chan string, 1)
	profile := Profile{PollMS: 250, FlushMS: 150}
	StartRelay(ctx, profile.Engine(relayStore, false, ""), func(_ context.Context, address string) (net.Conn, error) {
		target <- address
		first, second := net.Pipe()
		go func() {
			defer second.Close()
			data := make([]byte, 4)
			if _, err := io.ReadFull(second, data); err == nil {
				_, _ = second.Write(bytes.ToUpper(data))
			}
		}()
		return first, nil
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- StartClient(ctx, profile.Engine(clientStore, true, "local"), listener) }()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS listener did not shut down")
		}
	}()
	socket, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	exchange := func(send []byte, length int) []byte {
		t.Helper()
		if _, err := socket.Write(send); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, length)
		if _, err := io.ReadFull(socket, reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if got := exchange([]byte{5, 1, 0}, 2); !bytes.Equal(got, []byte{5, 0}) {
		t.Fatalf("SOCKS negotiation: %v", got)
	}
	domain := "test.invalid"
	request := append([]byte{5, 1, 0, 3, byte(len(domain))}, []byte(domain)...)
	request = append(request, 1, 187)
	if got := exchange(request, 10); got[1] != 0 {
		t.Fatalf("SOCKS connect: %v", got)
	}
	if got := exchange([]byte("ping"), 4); string(got) != "PING" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if got := <-target; got != "test.invalid:443" {
		t.Fatalf("relay destination: %s", got)
	}
}
