package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NullLatency/flow-driver/internal/storage"
)

// Engine manages the local sessions, periodically flushes Tx buffers to files,
// and polls for new Rx files.

var StatBlocked uint64
var StatRejected uint64
var StatUploadRetry uint64
var StatUploadFail uint64

type Engine struct {
	backend storage.Backend
	myDir   Direction // DirReq for client, DirRes for server
	peerDir Direction // DirRes for client, DirReq for server
	id      string    // ClientID for client, empty for server

	sessions     map[string]*Session
	sessionMu    sync.RWMutex
	sessionReady chan struct{}

	// Tombstones for recently closed sessions to prevent re-triggering on delayed packets
	closedSessions   map[string]time.Time
	closedSessionsMu sync.Mutex

	pollTicker  time.Duration
	flushTicker time.Duration

	// Server mode handler: called when a new session is discovered
	OnNewSession func(sessionID, targetAddr string, s *Session)

	// Concurrency control for storage operations (Upload/Download)
	sem chan struct{}

	// Track processed files to avoid duplicates
	processed   map[string]bool
	processedMu sync.Mutex
}

func NewEngine(backend storage.Backend, isClient bool, clientID string) *Engine {
	e := &Engine{
		backend:        backend,
		id:             clientID,
		sessions:       make(map[string]*Session),
		sessionReady:   make(chan struct{}),
		closedSessions: make(map[string]time.Time),
		processed:      make(map[string]bool),
		// Default intervals: Poll (RX) fast for responsiveness, Flush (TX) slower for gathering
		pollTicker:  500 * time.Millisecond,
		flushTicker: 300 * time.Millisecond,
	}
	if isClient {
		e.myDir = DirReq
		e.peerDir = DirRes
	} else {
		e.myDir = DirRes
		e.peerDir = DirReq
	}
	// Limit to 8 concurrent upload/download operations to avoid OOM and FD exhaustion
	e.sem = make(chan struct{}, 4)
	return e
}

func (e *Engine) SetRefreshRate(ms int) {
	if ms > 0 {
		e.pollTicker = time.Duration(ms) * time.Millisecond
		// Legacy behavior: sets both if FlushTicker was still at default
		if e.flushTicker == 300*time.Millisecond {
			e.flushTicker = time.Duration(ms) * time.Millisecond
		}
	}
}

func (e *Engine) SetPollRate(ms int) {
	if ms > 0 {
		e.pollTicker = time.Duration(ms) * time.Millisecond
	}
}

func (e *Engine) SetFlushRate(ms int) {
	if ms > 0 {
		e.flushTicker = time.Duration(ms) * time.Millisecond
	}
}

func (e *Engine) Start(ctx context.Context) {
	go e.flushLoop(ctx)
	go e.pollLoop(ctx)
	go e.cleanupLoop(ctx)
	context.AfterFunc(ctx, func() {
		e.sessionMu.Lock()
		defer e.sessionMu.Unlock()
		for _, session := range e.sessions {
			session.mu.Lock()
			session.closed = true
			session.txCond.Broadcast()
			session.mu.Unlock()
		}
	})
}

func (e *Engine) GetSession(id string) *Session {
	e.sessionMu.RLock()
	defer e.sessionMu.RUnlock()
	return e.sessions[id]
}

func (e *Engine) SessionCount() int {
	e.sessionMu.RLock()
	defer e.sessionMu.RUnlock()
	return len(e.sessions)
}

func (e *Engine) AddSession(s *Session) bool {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()

	if len(e.sessions) >= 30 {
		atomic.AddUint64(&StatRejected, 1)
		log.Printf("Engine.AddSession: Rejecting session %s; too many active sessions (%d)", s.ID, len(e.sessions))
		return false
	}

	if len(e.sessions) == 0 {
		close(e.sessionReady)
	}
	e.sessions[s.ID] = s
	log.Printf("Engine.AddSession: Added session %s (Total now: %d)", s.ID, len(e.sessions))
	return true
}

func (e *Engine) waitForClientSession(ctx context.Context) bool {
	if e.myDir == DirRes {
		return ctx.Err() == nil
	}
	e.sessionMu.RLock()
	ready := e.sessionReady
	e.sessionMu.RUnlock()
	select {
	case <-ready:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func (e *Engine) flushLoop(ctx context.Context) {
	timer := time.NewTimer(e.flushTicker)
	defer timer.Stop()
	for e.waitForClientSession(ctx) {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.flushAll(ctx)
			timer.Reset(e.flushTicker)
		}
	}
}

func (e *Engine) flushAll(ctx context.Context) {
	e.sessionMu.Lock()
	sessions := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		sessions = append(sessions, s)
	}
	e.sessionMu.Unlock()

	muxes := make(map[string][]Envelope)
	var closedSessionIDs []string

	for _, s := range sessions {
		s.mu.Lock()

		// Idle Timeout check
		if time.Since(s.lastActivity) > 60*time.Second {
			s.closed = true
		}

		shouldSend := len(s.txBuf) > 0 || (s.txSeq == 0 && e.myDir == DirReq) || s.closed

		if !shouldSend {
			s.mu.Unlock()
			continue
		}

		payload := s.txBuf
		s.txBuf = nil
		s.txCond.Broadcast() // Release any blocked writers

		env := Envelope{
			SessionID:  s.ID,
			Seq:        s.txSeq,
			Payload:    payload,
			Close:      s.closed,
			TargetAddr: s.TargetAddr,
		}

		s.txSeq++
		if s.closed {
			closedSessionIDs = append(closedSessionIDs, s.ID)
		}

		cid := s.ClientID
		if cid == "" && e.myDir == DirReq {
			cid = e.id // For client requests, use our own ID
		}

		muxes[cid] = append(muxes[cid], env)
		s.mu.Unlock()
	}

	if len(muxes) > 0 {
		// log.Printf("Engine.flushAll: Prepared muxes for %d clients", len(muxes))
	}

	for cid, mux := range muxes {
		if cid == "" {
			cid = "unknown"
		}
		for _, env := range mux {
			filename := fmt.Sprintf("%s-%s-mux-%d.bin", e.myDir, cid, time.Now().UnixNano())
			select {
			case e.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			go func(env Envelope) {
				defer func() { <-e.sem }()
				data, err := env.MarshalBinary()
				if err == nil {
					err = e.backend.Upload(ctx, filename, bytes.NewReader(data))
				}
				if err != nil {
					log.Printf("FlowDriver upload failed")
				}
			}(env)
		}
	}

	for _, id := range closedSessionIDs {
		e.RemoveSession(id)
	}
}

func (e *Engine) uploadWithRetry(ctx context.Context, fname string, data []byte) error {
	var lastErr error

	for attempt := 1; attempt <= 4; attempt++ {
		if err := e.backend.Upload(ctx, fname, bytes.NewReader(data)); err != nil {
			lastErr = err
			backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
			atomic.AddUint64(&StatUploadRetry, 1)
			log.Printf("upload retry %d/4 failed for %s: %v; sleeping %s", attempt, fname, err, backoff)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}

		if attempt > 1 {
			log.Printf("upload succeeded after retry %d for %s", attempt, fname)
		}
		return nil
	}

	atomic.AddUint64(&StatUploadFail, 1)
	return lastErr
}

func (e *Engine) pollLoop(ctx context.Context) {
	currentPollInterval := e.pollTicker
	maxPollInterval := 5 * time.Second
	timer := time.NewTimer(currentPollInterval)
	defer timer.Stop()

	for e.waitForClientSession(ctx) {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Fetch multiplexed files
			prefix := string(e.peerDir) + "-"
			if e.myDir == DirReq {
				// Client only polls for its own responses
				prefix += e.id + "-mux-"
			} else {
				// Server polls for ALL client requests
				prefix += ""
			}
			files, err := e.backend.ListQuery(ctx, prefix)
			if err != nil {
				log.Printf("poll list error: %v", err)
				timer.Reset(currentPollInterval)
				continue
			}

			if len(files) == 0 {
				if e.myDir == DirRes { // SERVER OPTIMIZATION
					e.sessionMu.RLock()
					activeSessions := len(e.sessions)
					e.sessionMu.RUnlock()

					if activeSessions == 0 {
						// Increase polling delay step-by-step to save API calls
						currentPollInterval += 500 * time.Millisecond
						if currentPollInterval > maxPollInterval {
							currentPollInterval = maxPollInterval
						}
					} else {
						// A session is currently active, so loop fast!
						currentPollInterval = e.pollTicker
					}
				}
				// Client optimization doesn't change intervals, but needs its timer reset
				timer.Reset(currentPollInterval)
				continue
			}

			// We found data! Reset polling back to maximum speed
			currentPollInterval = e.pollTicker

			// We found files! Let's download them in parallel to boost speed massively
			var wg sync.WaitGroup
			for _, f := range files {
				// STARTUP OPTIMIZATION: Ignore files older than 5 minutes to avoid memory spikes on restart
				parts := strings.Split(f, "-")
				if len(parts) >= 3 {
					tsStr := parts[len(parts)-1]
					tsStr = strings.TrimSuffix(tsStr, ".bin")
					ts, _ := strconv.ParseInt(tsStr, 10, 64)
					if ts > 0 && time.Since(time.Unix(0, ts)) > 5*time.Minute {
						e.backend.Delete(ctx, f) // Silent cleanup
						continue
					}
				}

				e.processedMu.Lock()
				already := e.processed[f]
				if !already {
					e.processed[f] = true
				}
				e.processedMu.Unlock()

				if already {
					continue
				}

				wg.Add(1)
				go func(fname string) {
					defer wg.Done()

					e.sem <- struct{}{}        // Acquire
					defer func() { <-e.sem }() // Release

					// log.Printf("Engine.pollLoop: Downloading %s", fname)
					rc, err := e.backend.Download(ctx, fname)
					if err != nil {
						if errors.Is(err, storage.ErrInvalidObject) {
							_ = e.backend.Delete(ctx, fname)
							return
						}
						log.Printf("FlowDriver download failed")
						e.processedMu.Lock()
						delete(e.processed, fname) // failed to download, retry next poll
						e.processedMu.Unlock()
						return
					}
					defer rc.Close()

					// Extract ClientID from filename for server-side session initialization
					var fileClientID string
					parts := strings.Split(fname, "-")
					if len(parts) >= 4 && parts[2] == "mux" {
						fileClientID = parts[1]
					}

					// STREAMING DECODE
					retryLater := false
					for {
						var env Envelope
						if err := env.Decode(rc); err != nil {
							if err != io.EOF && err != io.ErrUnexpectedEOF {
								log.Printf("mux decode error %s: %v", fname, err)
							}
							break
						}

						// Process envelope immediately
						e.closedSessionsMu.Lock()
						if _, exists := e.closedSessions[env.SessionID]; exists {
							e.closedSessionsMu.Unlock()
							continue
						}
						e.closedSessionsMu.Unlock()

						e.sessionMu.Lock()
						s, exists := e.sessions[env.SessionID]
						if !exists && e.myDir == DirRes && env.Seq > 0 {
							retryLater = true
						}
						if !exists && len(e.sessions) < 30 && env.Seq == 0 && !env.Close && e.myDir == DirRes && e.OnNewSession != nil {
							s = NewSession(env.SessionID)
							s.ClientID = fileClientID
							e.sessions[env.SessionID] = s
							e.sessionMu.Unlock()
							log.Printf("Engine: Triggering new session %s for Client %s", env.SessionID, fileClientID)
							e.OnNewSession(env.SessionID, env.TargetAddr, s)
						} else {
							e.sessionMu.Unlock()
						}

						if s != nil {
							s.ProcessRx(&env)
						}
					}

					if retryLater {
						e.processedMu.Lock()
						delete(e.processed, fname)
						e.processedMu.Unlock()
					} else {
						e.backend.Delete(ctx, fname)
					}
				}(f)
			}

			// Wait for parallel batch to finish
			wg.Wait()

			// Adaptive Polling: Because we just received data, the connection is active.
			// Instead of jumping back to the select, immediately poll again after a tiny 100ms break to drain queues.
			timer.Reset(250 * time.Millisecond)
		}
	}
}

func (e *Engine) RemoveSession(id string) {
	e.sessionMu.Lock()
	if _, exists := e.sessions[id]; exists {
		delete(e.sessions, id)
		if len(e.sessions) == 0 && e.myDir == DirReq {
			e.sessionReady = make(chan struct{})
		}
	}
	e.sessionMu.Unlock()

	// Add to tombstone list
	e.closedSessionsMu.Lock()
	e.closedSessions[id] = time.Now()
	e.closedSessionsMu.Unlock()
}

func (e *Engine) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Cleanup old tombstones (older than 30s)
			e.closedSessionsMu.Lock()
			for id, t := range e.closedSessions {
				if time.Since(t) > 30*time.Second {
					delete(e.closedSessions, id)
				}
			}
			e.closedSessionsMu.Unlock()

			// Periodically clear processed map to prevent infinite growth
			e.processedMu.Lock()
			if len(e.processed) > 5000 {
				e.processed = make(map[string]bool)
			}
			e.processedMu.Unlock()

			// ZERO-TRAFFIC CLIENT OPTIMIZATION:
			if e.myDir == DirReq {
				e.sessionMu.RLock()
				count := len(e.sessions)
				e.sessionMu.RUnlock()
				if count == 0 {
					continue
				}
			}

			prefix := string(e.myDir) + "-"
			if e.myDir == DirReq {
				prefix += e.id + "-mux-"
			}
			files, _ := e.backend.ListQuery(ctx, prefix)
			for _, f := range files {
				parts := strings.Split(f, "-")
				// Formats:
				// OLD: "req", "UUID...", "Seq", "Timestamp.json" (len >= 4)
				// MUX: "req", "mux", "Timestamp.json" (len >= 3)
				if len(parts) >= 3 {
					tsStr := parts[len(parts)-1]
					tsStr = strings.TrimSuffix(tsStr, ".json")
					tsStr = strings.TrimSuffix(tsStr, ".bin")
					ts, err := strconv.ParseInt(tsStr, 10, 64)
					if err == nil {
						t := time.Unix(0, ts)
						if time.Since(t) > 2*time.Minute {
							e.backend.Delete(ctx, f)
						}
					}
				}
			}
		}
	}
}

func StartStatsLogger(e *Engine) {
	log.Printf("[stats] logger started")
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			log.Printf("[stats] active=%d blocked=%d rejected=%d upload_retry=%d upload_fail=%d",
				e.SessionCount(),
				atomic.LoadUint64(&StatBlocked),
				atomic.LoadUint64(&StatRejected),
				atomic.LoadUint64(&StatUploadRetry),
				atomic.LoadUint64(&StatUploadFail),
			)
		}
	}()
}
