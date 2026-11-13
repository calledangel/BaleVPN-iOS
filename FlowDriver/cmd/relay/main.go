package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NullLatency/flow-driver/internal/flow"
)

func main() {
	path := flag.String("profile", "", "path to the private FlowDriver profile")
	flag.Parse()
	file, err := os.Open(*path)
	if err != nil {
		log.Fatal("cannot open FlowDriver profile")
	}
	data, err := io.ReadAll(io.LimitReader(file, flow.MaxProfileSize+1))
	file.Close()
	if err != nil {
		log.Fatal("cannot read FlowDriver profile")
	}
	profile, err := flow.ParseProfile(data)
	clear(data)
	if err != nil {
		log.Fatal("invalid FlowDriver profile")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	backend, err := profile.Backend()
	if err != nil {
		log.Fatal("cannot initialize encrypted storage")
	}
	login, cancel := context.WithTimeout(ctx, 25*time.Second)
	err = backend.Login(login)
	cancel()
	if err != nil {
		log.Fatal("could not open the configured Drive folder")
	}
	log.Println("FlowDriver relay ready")
	log.SetOutput(io.Discard)
	flow.StartRelay(ctx, profile.Engine(backend, false, ""), flow.DialPublic)
	<-ctx.Done()
}
