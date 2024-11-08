package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/keihaya-com/connet"
)

var debug = flag.Bool("debug", false, "turn on debug logging")
var server = flag.String("server", "127.0.0.1:8443", "target server")
var auth = flag.String("auth", "", "authentication token")
var listenName = flag.String("listen-name", "", "name to listen on")
var listenTarget = flag.String("listen-target", "", "forward incoming conns to")
var connectName = flag.String("connect-name", "", "name to connect to")
var connectSource = flag.String("connect-source", "", "listen for incoming conns")
var caCert = flag.String("ca-cert", "", "ca cert file to use")
var caKey = flag.String("ca-key", "", "ca key file to use")

func main() {
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse flags: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	var opts = []connet.ClientOption{
		connet.ClientServer(*server),
		connet.ClientAuthentication(*auth),
	}

	if *caCert != "" {
		opts = append(opts, connet.ClientCA(*caCert, *caKey))
	}

	if *listenName != "" {
		opts = append(opts, connet.ClientDestination(*listenName, *listenTarget))
	}

	if *connectName != "" {
		opts = append(opts, connet.ClientSource(*connectSource, *connectName))
	}

	if *debug {
		opts = append(opts,
			connet.ClientLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))),
		)
	}

	c, err := connet.NewClient(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could create client: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := c.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "could create client: %v", err)
	}
}
