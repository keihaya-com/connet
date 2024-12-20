package control

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/keihaya-com/connet/logc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr       *net.UDPAddr
	Cert       tls.Certificate
	ClientAuth ClientAuthenticator
	RelayAuth  RelayAuthenticator
	Logger     *slog.Logger
	Dir        string
}

func NewServer(cfg Config) (*Server, error) {
	config, err := logc.NewKV[configKey, configValue](filepath.Join(cfg.Dir, "config"))
	if err != nil {
		return nil, err
	}

	s := &Server{
		addr: cfg.Addr,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.Cert},
			NextProtos:   []string{"connet", "connet-relays"},
		},
		logger: cfg.Logger.With("control", cfg.Addr),
	}

	relays, err := newRelayServer(cfg.RelayAuth, config, cfg.Dir, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s.relays = relays

	clSrv, err := newClientServer(cfg.ClientAuth, s.relays, config, cfg.Dir, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s.clients = clSrv

	return s, nil
}

type Server struct {
	addr    *net.UDPAddr
	tlsConf *tls.Config
	logger  *slog.Logger

	clients *clientServer
	relays  *relayServer
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.relays.run(ctx) })
	g.Go(func() error { return s.clients.run(ctx) })
	g.Go(func() error { return s.runListener(ctx) })

	return g.Wait()
}

func (s *Server) runListener(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	s.logger.Debug("start quic listener")
	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	defer tr.Close()

	l, err := tr.Listen(s.tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		s.logger.Info("connection accepted", "remote", conn.RemoteAddr(), "proto", conn.ConnectionState().TLS.NegotiatedProtocol)

		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case "connet":
			if err := s.clients.handle(ctx, conn); err != nil {
				return err
			}
		case "connet-relays":
			if err := s.relays.handle(ctx, conn); err != nil {
				return err
			}
		default:
			conn.CloseWithError(1, "unknown protocol")
		}
	}
}

type configKey string

var (
	configServerID           configKey = "server-id"
	configServerClientSecret configKey = "server-client-secret"
)

type configValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}
