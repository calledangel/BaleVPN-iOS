package flow

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/NullLatency/flow-driver/internal/transport"
)

type Dial func(context.Context, string) (net.Conn, error)

func StartRelay(ctx context.Context, engine *transport.Engine, dial Dial) {
	engine.OnNewSession = func(_ string, target string, session *transport.Session) {
		go func() {
			virtual := transport.NewVirtualConn(ctx, session)
			defer virtual.Close()
			socket, err := dial(ctx, target)
			if err != nil {
				return
			}
			defer socket.Close()
			stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
			defer stop()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				defer virtual.Close()
				_, _ = io.Copy(virtual, socket)
			}()
			_, _ = io.Copy(socket, virtual)
			_ = socket.Close()
			<-finished
		}()
	}
	engine.Start(ctx)
}

var blockedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
}

func DialPublic(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{}
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() {
			continue
		}
		blocked := false
		for _, prefix := range blockedNetworks {
			blocked = blocked || prefix.Contains(address)
		}
		if !blocked {
			if connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port)); err == nil {
				return connection, nil
			}
		}
	}
	return nil, errors.New("destination unavailable")
}
