package flow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/NullLatency/flow-driver/internal/localsocks"
	"github.com/NullLatency/flow-driver/internal/transport"
)

func StartClient(ctx context.Context, engine *transport.Engine, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	engine.Start(ctx)
	return localsocks.Serve(ctx, listener, func(ctx context.Context, network, target string) (net.Conn, error) {
		if ctx.Err() != nil || network != "tcp" || len(target) > 255 {
			return nil, fmt.Errorf("unsupported request")
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		session := transport.NewSession(hex.EncodeToString(id))
		session.TargetAddr = target
		if !engine.AddSession(session) {
			return nil, fmt.Errorf("session limit reached")
		}
		return transport.NewVirtualConn(ctx, session), nil
	})
}
