package main

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef void (*FlowStateCallback)(uint64_t, int32_t, uint16_t, int32_t);
typedef void (*DNSScanCallback)(uint64_t, const char *);
static inline void dns_report(DNSScanCallback fn, uint64_t id, const char *json) {
    fn(id, json);
}
static inline void dns_notify(FlowStateCallback fn, uint64_t id, int32_t state) {
    fn(id, state, 0, 0);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/NullLatency/flow-driver/internal/dnstunnel"
	"github.com/NullLatency/flow-driver/internal/localsocks"
)

//export dnstt_validate
func dnstt_validate(raw *C.char) C.bool {
	_, err := dnstunnel.ParseProfile(C.GoString(raw))
	return C.bool(err == nil)
}

//export dnstt_validate_resolvers
func dnstt_validate_resolvers(raw *C.char) C.bool {
	_, err := dnstunnel.Resolvers(C.GoString(raw))
	return C.bool(err == nil)
}

//export dnstt_normalize_resolvers
func dnstt_normalize_resolvers(raw *C.char) *C.char {
	resolvers, err := dnstunnel.SavedResolvers(C.GoString(raw))
	return canonicalResolvers(resolvers, err)
}

//export dnstt_reference_resolvers
func dnstt_reference_resolvers(raw *C.char) *C.char {
	resolvers, err := dnstunnel.ReferenceResolvers(C.GoString(raw))
	return canonicalResolvers(resolvers, err)
}

func canonicalResolvers(resolvers []netip.AddrPort, err error) *C.char {
	if err != nil {
		return nil
	}
	addresses := make([]string, len(resolvers))
	for index, resolver := range resolvers {
		addresses[index] = resolver.String()
	}
	return C.CString(strings.Join(addresses, "\n"))
}

//export dnstt_start
func dnstt_start(raw, addresses *C.char, timeout, port C.uint16_t, fallback C.bool, callback C.FlowStateCallback) C.uint64_t {
	profile, err := dnstunnel.ParseProfile(C.GoString(raw))
	resolvers, listErr := dnstunnel.Resolvers(C.GoString(addresses))
	if err != nil || listErr != nil || len(resolvers) == 0 || timeout < 5 || timeout > 45 || port == 0 || callback == nil {
		return 0
	}
	profile.Timeout = time.Duration(timeout) * time.Second
	cb := callback
	return start(cb, func(ctx context.Context, id C.uint64_t) (C.int32_t, C.int32_t) {
		C.dns_notify(callback, id, 15)
		for index, address := range resolvers {
			session, err := profile.Connect(ctx, address)
			if ctx.Err() != nil {
				if session != nil {
					session.Close()
				}
				return 0, 0
			}
			if errors.Is(err, dnstunnel.ErrHostKey) {
				return -9, 0
			}
			if errors.Is(err, dnstunnel.ErrSSH) {
				return -10, 0
			}
			if err != nil {
				continue
			}
			defer session.Close()
			C.dns_notify(callback, id, C.int32_t(20+index))
			serveCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() { _ = session.Wait(); cancel() }()
			return listen(serveCtx, uint16(port), bool(fallback), id, cb, func(ctx context.Context, listener net.Listener) error {
				return localsocks.Serve(ctx, listener, session.DialContext)
			})
		}
		return -8, 0
	})
}

type dnsUpdate struct {
	Resolver string `json:"resolver,omitempty"`
	dnstunnel.Diagnostic
}

var dnsScan struct {
	sync.Mutex
	id     C.uint64_t
	cancel context.CancelFunc
}

//export dnstt_scan_start
func dnstt_scan_start(raw, addresses *C.char, timeout C.uint16_t, deep C.bool, callback C.DNSScanCallback) C.uint64_t {
	profile, err := dnstunnel.ParseProfile(C.GoString(raw))
	resolvers, listErr := dnstunnel.Resolvers(C.GoString(addresses))
	if err != nil || listErr != nil || len(resolvers) == 0 || timeout < 5 || timeout > 45 || callback == nil {
		return 0
	}
	profile.Timeout = time.Duration(timeout) * time.Second
	dnsScan.Lock()
	defer dnsScan.Unlock()
	if dnsScan.cancel != nil {
		return 0
	}
	dnsScan.id++
	id := dnsScan.id
	ctx, cancel := context.WithCancel(context.Background())
	dnsScan.cancel = cancel

	go func() {
		report := func(update dnsUpdate) {
			body, _ := json.Marshal(update)
			ptr := C.CString(string(body))
			defer C.free(unsafe.Pointer(ptr))
			C.dns_report(callback, id, ptr)
		}
		var workers sync.WaitGroup
		queue := make(chan netip.AddrPort, len(resolvers))
		for _, address := range resolvers {
			queue <- address
		}
		close(queue)
		for range min(2, len(resolvers)) {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for address := range queue {
					if ctx.Err() != nil {
						return
					}
					profile.Diagnose(ctx, address, bool(deep), func(event dnstunnel.Diagnostic) {
						if ctx.Err() == nil {
							report(dnsUpdate{Resolver: address.String(), Diagnostic: event})
						}
					})
				}
			}()
		}
		workers.Wait()
		status := "finished"
		if ctx.Err() != nil {
			status = "cancelled"
		}
		cancel()
		dnsScan.Lock()
		dnsScan.cancel = nil
		dnsScan.Unlock()
		report(dnsUpdate{Diagnostic: dnstunnel.Diagnostic{Status: status}})
	}()
	return id
}

//export dnstt_scan_stop
func dnstt_scan_stop(id C.uint64_t) {
	dnsScan.Lock()
	defer dnsScan.Unlock()
	if dnsScan.id == id && dnsScan.cancel != nil {
		dnsScan.cancel()
	}
}
