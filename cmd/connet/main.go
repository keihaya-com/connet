package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/keihaya-com/connet"
)

type Config struct {
	LogLevel  string       `toml:"log_level"`
	LogFormat string       `toml:"log_format"`
	Server    ServerConfig `toml:"server"`
	Client    ClientConfig `toml:"client"`
}

type ServerConfig struct {
	Tokens   []string       `toml:"tokens"`
	Hostname string         `toml:"hostname"`
	Cert     string         `toml:"cert_file"`
	Key      string         `toml:"key_file"`
	Control  ListenerConfig `toml:"control"`
	Relay    ListenerConfig `toml:"relay"`
}

type ListenerConfig struct {
	Addr string `toml:"bind_addr"`
	Cert string `toml:"cert_file"`
	Key  string `toml:"key_file"`
}

type ClientConfig struct {
	Token      string `toml:"token"`
	ServerAddr string `toml:"server_addr"`
	ServerCAs  string `toml:"server_cas"`
	DirectAddr string `toml:"direct_addr"`

	Destinations map[string]ForwardConfig `toml:"destinations"`
	Sources      map[string]ForwardConfig `toml:"sources"`
}

type ForwardConfig struct {
	Addr  string `toml:"addr"`
	Route string `toml:"route"`
}

func main() {
	args := os.Args
	if len(args) == 2 {
		// if we are given 'connet file-name.toml', pretend we start a client (if config file exists)
		if _, err := os.Stat(args[1]); err == nil {
			args = []string{args[0], "client", args[1]}
		}
	}
	if len(args) != 3 {
		fmt.Println("Usage: connet [server|client|check] <config-file>")
		os.Exit(1)
	}

	var cfg Config
	md, err := toml.DecodeFile(args[2], &cfg)
	if err != nil {
		fmt.Printf("Could not parse '%s' config file: %v\n", args[2], err)
		os.Exit(2)
	}

	logger := logger(cfg)

	switch args[1] {
	case "server":
		if err := server(cfg.Server, logger); err != nil {
			fmt.Printf("Error while running server: %v\n", err)
			os.Exit(4)
		}
		os.Exit(0)
	case "client":
		if err := client(cfg.Client, logger); err != nil {
			fmt.Printf("Error while running client: %v\n", err)
			os.Exit(5)
		}
		os.Exit(0)
	case "check":
		if len(md.Undecoded()) > 0 {
			fmt.Println("Invalid configuration file (unknown keys):", md.Undecoded())
			os.Exit(6)
		}
		fmt.Println("Valid configuration file")
		os.Exit(0)
	default:
		fmt.Println("Unknown command, try one of [server|client|check]")
		os.Exit(3)
	}
}

func logger(cfg Config) *slog.Logger {
	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	case "info":
		logLevel = slog.LevelInfo
	}

	switch cfg.LogFormat {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	case "text":
		fallthrough
	default:
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}
}

func server(cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	opts = append(opts, connet.ServerTokens(cfg.Tokens...))

	if cfg.Hostname != "" {
		opts = append(opts, connet.ServerHostname(cfg.Hostname))
	}
	if cfg.Cert != "" {
		opts = append(opts, connet.ServerDefaultCertificate(cfg.Cert, cfg.Key))
	}

	if cfg.Control.Addr != "" {
		opts = append(opts, connet.ServerControlAddress(cfg.Control.Addr))
	}
	if cfg.Control.Cert != "" {
		opts = append(opts, connet.ServerControlCertificate(cfg.Control.Cert, cfg.Control.Key))
	}

	if cfg.Relay.Addr != "" {
		opts = append(opts, connet.ServerRelayAddress(cfg.Relay.Addr))
	}
	if cfg.Relay.Cert != "" {
		opts = append(opts, connet.ServerRelayCertificate(cfg.Relay.Cert, cfg.Relay.Key))
	}

	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return err
	}
	return srv.Run(context.Background())
}

func client(cfg ClientConfig, logger *slog.Logger) error {
	var opts []connet.ClientOption

	opts = append(opts, connet.ClientToken(cfg.Token))
	opts = append(opts, connet.ClientLogger(logger))

	if cfg.ServerAddr != "" {
		opts = append(opts, connet.ClientControlAddress(cfg.ServerAddr))
	}
	if cfg.ServerCAs != "" {
		opts = append(opts, connet.ClientControlCAs(cfg.ServerCAs))
	}

	if cfg.DirectAddr != "" {
		opts = append(opts, connet.ClientDirectAddress(cfg.DirectAddr))
	}

	for name, fc := range cfg.Destinations {
		opts = append(opts, connet.ClientDestination(name, fc.Addr))
	}
	for name, fc := range cfg.Sources {
		opts = append(opts, connet.ClientSource(name, fc.Addr))
	}

	cl, err := connet.NewClient(opts...)
	if err != nil {
		return err
	}
	return cl.Run(context.Background())
}
