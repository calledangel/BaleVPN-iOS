package main

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef void (*CloudflareScanCallback)(uint64_t, const char *);
static inline void cloudflare_report(CloudflareScanCallback fn, uint64_t id, const char *json) {
    fn(id, json);
}
typedef void (*FlowStateCallback)(uint64_t, int32_t, uint16_t, int32_t);
static inline void flow_notify(FlowStateCallback fn, uint64_t id, int32_t state, uint16_t port, int32_t error) {
    fn(id, state, port, error);
}
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/NullLatency/flow-driver/internal/cloudflare"
	"github.com/NullLatency/flow-driver/internal/localsocks"

	"github.com/NullLatency/flow-driver/internal/flow"
)

var runtimeState struct {
	sync.Mutex
	id     C.uint64_t
	cancel context.CancelFunc
}

func profileFromString(profile *C.char) (flow.Profile, error) {
	if profile == nil {
		return flow.Profile{}, errors.New("missing profile")
	}
	return flow.ParseProfile([]byte(C.GoString(profile)))
}

//export flow_validate_profile
func flow_validate_profile(raw *C.char) C.bool {
	_, err := profileFromString(raw)
	return C.bool(err == nil)
}

//export flow_start
func flow_start(raw *C.char, port C.uint16_t, fallback C.bool, callback C.FlowStateCallback) C.uint64_t {
	profile, err := profileFromString(raw)
	if err != nil || port == 0 || callback == nil {
		return 0
	}
	return start(callback, func(ctx context.Context, id C.uint64_t) (C.int32_t, C.int32_t) {
		return run(ctx, profile, uint16(port), bool(fallback), id, callback)
	})
}

func start(callback C.FlowStateCallback, run func(context.Context, C.uint64_t) (C.int32_t, C.int32_t)) C.uint64_t {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.cancel != nil {
		return 0
	}
	runtimeState.id++
	id := runtimeState.id
	ctx, cancel := context.WithCancel(context.Background())
	runtimeState.cancel = cancel
	go func() {
		status, errno := run(ctx, id)
		cancel()
		runtimeState.Lock()
		runtimeState.cancel = nil
		runtimeState.Unlock()
		C.flow_notify(callback, id, status, 0, errno)
	}()
	return id
}

//export flow_stop
func flow_stop(id C.uint64_t) {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.id == id && runtimeState.cancel != nil {
		runtimeState.cancel()
	}
}

func run(ctx context.Context, profile flow.Profile, port uint16, fallback bool, id C.uint64_t, callback C.FlowStateCallback) (C.int32_t, C.int32_t) {
	backend, err := profile.Backend()
	if err != nil {
		return -6, 0
	}
	C.flow_notify(callback, id, 13, 0, 0)
	login, cancel := context.WithTimeout(ctx, 25*time.Second)
	err = backend.Login(login)
	cancel()
	if ctx.Err() != nil {
		return 0, 0
	}
	if err != nil {
		return -6, 0
	}
	return listen(ctx, port, fallback, id, callback, func(ctx context.Context, listener net.Listener) error {
		var clientID [12]byte
		if _, err := rand.Read(clientID[:]); err != nil {
			return err
		}
		engine := profile.Engine(backend, true, hex.EncodeToString(clientID[:]))
		return flow.StartClient(ctx, engine, listener)
	})
}

func listen(ctx context.Context, port uint16, fallback bool, id C.uint64_t, callback C.FlowStateCallback, serve func(context.Context, net.Listener) error) (C.int32_t, C.int32_t) {
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(int(port)))
	var conflict C.int32_t
	if fallback && errors.Is(err, syscall.EADDRINUSE) {
		conflict = C.int32_t(syscall.EADDRINUSE)
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		var errno syscall.Errno
		errors.As(err, &errno)
		return -4, C.int32_t(errno)
	}
	defer listener.Close()
	C.flow_notify(callback, id, 1, C.uint16_t(listener.Addr().(*net.TCPAddr).Port), conflict)
	if err := serve(ctx, listener); err != nil && ctx.Err() == nil {
		return -4, 0
	}
	return 0, 0
}

func parseCDN(raw *C.char) (cloudflare.Profile, error) {
	if raw == nil {
		return cloudflare.Profile{}, errors.New("missing profile")
	}
	return cloudflare.Parse(C.GoString(raw))
}

//export cloudflare_validate
func cloudflare_validate(raw *C.char) C.bool {
	_, err := parseCDN(raw)
	return C.bool(err == nil)
}

//export cloudflare_start
func cloudflare_start(raw *C.char, port C.uint16_t, fallback C.bool, callback C.FlowStateCallback) C.uint64_t {
	profile, err := parseCDN(raw)
	if err != nil || port == 0 || callback == nil {
		return 0
	}
	return start(callback, func(ctx context.Context, id C.uint64_t) (C.int32_t, C.int32_t) {
		C.flow_notify(callback, id, 14, 0, 0)
		if err := profile.Check(ctx); err != nil {
			if ctx.Err() != nil {
				return 0, 0
			}
			return -7, 0
		}
		return listen(ctx, uint16(port), bool(fallback), id, callback, func(ctx context.Context, listener net.Listener) error {
			return localsocks.Serve(ctx, listener, profile.Dial)
		})
	})
}

var scanState struct {
	sync.Mutex
	id     C.uint64_t
	cancel context.CancelFunc
}

//export cloudflare_scan_start
func cloudflare_scan_start(raw, seeds, custom *C.char, deep C.bool, callback C.CloudflareScanCallback) C.uint64_t {
	profile, err := parseCDN(raw)
	if err != nil || callback == nil {
		return 0
	}
	var input string
	if custom != nil {
		input = C.GoString(custom)
	}
	targets, err := cloudflare.ParseTargets(input)
	if err != nil {
		return 0
	}
	scanState.Lock()
	defer scanState.Unlock()
	if scanState.cancel != nil {
		return 0
	}
	scanState.id++
	id := scanState.id
	ctx, cancel := context.WithCancel(context.Background())
	scanState.cancel = cancel
	var previous []netip.Addr
	if seeds != nil {
		for _, token := range strings.Split(C.GoString(seeds), ",") {
			if ip, err := netip.ParseAddr(token); err == nil {
				previous = append(previous, ip)
			}
		}
	}
	go cloudflare.Scan(ctx, profile, bool(deep), previous, targets, func(update cloudflare.ScanUpdate) {
		if update.Phase == "finished" || update.Phase == "cancelled" {
			cancel()
			scanState.Lock()
			scanState.cancel = nil
			scanState.Unlock()
		}
		encoded, err := json.Marshal(update)
		if err != nil {
			return
		}
		payload := C.CString(string(encoded))
		defer C.free(unsafe.Pointer(payload))
		C.cloudflare_report(callback, id, payload)
	})
	return id
}

//export cloudflare_scan_stop
func cloudflare_scan_stop(id C.uint64_t) {
	scanState.Lock()
	defer scanState.Unlock()
	if scanState.id == id && scanState.cancel != nil {
		scanState.cancel()
	}
}

//export cloudflare_targets_check
func cloudflare_targets_check(raw *C.char) *C.char {
	if raw == nil {
		return nil
	}
	targets, err := cloudflare.ParseTargets(C.GoString(raw))
	result := struct {
		Canonical string `json:"canonical"`
		IPs       int    `json:"ips"`
		Subnets   int    `json:"subnets"`
		Error     string `json:"error,omitempty"`
	}{Canonical: targets.Canonical, IPs: len(targets.IPs), Subnets: len(targets.Subnets)}
	if err != nil {
		result.Error = err.Error()
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	return C.CString(string(payload))
}

//export cloudflare_link_for_ip
func cloudflare_link_for_ip(raw, ip, custom *C.char) *C.char {
	if raw == nil || ip == nil {
		return nil
	}
	var input string
	if custom != nil {
		input = C.GoString(custom)
	}
	targets, err := cloudflare.ParseTargets(input)
	if err != nil {
		return nil
	}
	link, err := cloudflare.LinkForEdge(C.GoString(raw), C.GoString(ip), targets)
	if err != nil {
		return nil
	}
	return C.CString(link)
}

//export cloudflare_free
func cloudflare_free(raw *C.char) { C.free(unsafe.Pointer(raw)) }

func main() {}
