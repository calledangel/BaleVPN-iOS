package localsocks

import (
	"context"
	"io"
	"log"
	"net"
	"sync"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type noLocalDNS struct{}

func (noLocalDNS) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func Serve(ctx context.Context, listener net.Listener, dial func(context.Context, string, string) (net.Conn, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", 0))),
		socks5.WithResolver(noLocalDNS{}),
		socks5.WithDial(func(_ context.Context, network, target string) (net.Conn, error) {
			return dial(ctx, network, target)
		}),
		socks5.WithAssociateHandle(func(_ context.Context, w io.Writer, _ *socks5.Request) error {
			return socks5.SendReply(w, statute.RepCommandNotSupported, nil)
		}),
	)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var clients sync.WaitGroup
	defer func() { cancel(); clients.Wait() }()
	slots := make(chan struct{}, 32)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { <-slots }()
			defer connection.Close()
			stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
			defer stop()
			_ = server.ServeConn(connection)
		}()
	}
}
