package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keihaya-com/connet/authc"
	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
)

type Server struct {
	serverConfig

	realms map[string]*realmClients
}

func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &serverConfig{
		address: "0.0.0.0:8443",
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if len(cfg.auth.Realms()) == 0 {
		return nil, kleverr.New("no realms defined")
	}
	realms := map[string]*realmClients{}
	for _, r := range cfg.auth.Realms() {
		realms[r] = &realmClients{name: r, targets: map[string]*ServerClient{}}
	}

	return &Server{
		serverConfig: *cfg,
		realms:       realms,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("resolving udp address", "addr", s.address)
	addr, err := net.ResolveUDPAddr("udp", s.address)
	if err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Debug("start udp listener", "addr", addr)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	s.logger.Debug("start quic listener", "addr", addr)
	l, err := tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{*s.certificate},
		NextProtos:   []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Info("waiting for incoming connections", "addr", addr)
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				s.logger.Info("stopped quic listener", "addr", addr)
				return nil
			}
		}

		scID := ksuid.New()
		sc := &ServerClient{
			server: s,
			id:     scID,
			conn:   conn,
			logger: s.logger.With("client-id", scID),
		}
		go sc.Run(ctx)
	}
}

func (s *Server) register(auth authc.Authentication, name string, c *ServerClient) error {
	localName, realmName, found := strings.Cut(name, "@")
	if found {
		if !slices.Contains(auth.Realms, realmName) {
			return kleverr.Newf("realm not accessible: %s", realmName)
		}
	} else {
		realmName = auth.SelfRealm
	}

	realm, ok := s.realms[realmName]
	if !ok {
		return kleverr.Newf("realm not found: %s", realmName)
	}
	realm.register(localName, c)
	return nil
}

func (s *Server) find(auth authc.Authentication, name string) (*ServerClient, error) {
	localName, realmName, found := strings.Cut(name, "@")
	if found {
		if !slices.Contains(auth.Realms, realmName) {
			return nil, kleverr.Newf("realm not accessible: %s", realmName)
		}
	} else {
		realmName = auth.SelfRealm
	}

	realm, ok := s.realms[realmName]
	if !ok {
		return nil, kleverr.Newf("realm not found: %s", realmName)
	}
	return realm.find(localName)
}

func (s *Server) deregister(c *ServerClient) {
	for _, realm := range s.realms {
		realm.deregister(c)
	}
}

type realmClients struct {
	name    string
	targets map[string]*ServerClient
	mu      sync.RWMutex
}

func (r *realmClients) register(name string, c *ServerClient) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.targets[name] = c
	// TODO last register wins?
	// TODO multiple targets
}

func (r *realmClients) find(name string) (*ServerClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.targets[name]
	if !ok {
		return nil, kleverr.Newf("target %s not found in %s realm", name, r.name)
	}
	return c, nil
}

func (r *realmClients) deregister(c *ServerClient) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, v := range r.targets {
		if v.id == c.id {
			delete(r.targets, k)
		}
	}
}

type ServerClient struct {
	server *Server
	id     ksuid.KSUID
	conn   quic.Connection
	logger *slog.Logger
	auth   authc.Authentication
}

func (c *ServerClient) Run(ctx context.Context) {
	auth, err := c.authenticate(ctx)
	if err != nil {
		c.logger.Error("authentication failed", "err", err)
		c.conn.CloseWithError(1, "no auth")
		return
	}
	c.auth = auth

	defer c.server.deregister(c)

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			c.logger.Error("disconnected", "err", err)
			c.conn.CloseWithError(2, "disconnect")
			return
		}

		ssID := ksuid.New()
		ss := &ServerStream{
			client: c,
			id:     ssID,
			stream: stream,
			logger: c.logger.With("stream-id", ssID),
		}
		go ss.Run(ctx)
	}
}

var retAuth = kleverr.Ret1[authc.Authentication]

func (c *ServerClient) authenticate(ctx context.Context) (authc.Authentication, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return authc.Authentication{}, err
	}
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return retAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	if err := pb.Write(authStream, &pbs.AuthenticateResp{}); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "realms", auth.Realms)
	return auth, nil
}

type ServerStream struct {
	client *ServerClient
	id     ksuid.KSUID
	stream quic.Stream
	logger *slog.Logger
}

func (s *ServerStream) Run(ctx context.Context) {
	defer s.stream.Close()

	req, err := pbs.ReadRequest(s.stream)
	if err != nil {
		// TODO error
		return
	}
	s.logger.Debug("incomming request", "req", req)

	switch {
	case req.Register != nil:
		s.register(ctx, req.Register.Name)
	case req.Connect != nil:
		s.connect(ctx, req.Connect.Name)
	default:
		s.unknown(ctx, req)
	}
}

func (s *ServerStream) register(ctx context.Context, name string) {
	if err := s.client.server.register(s.client.auth, name, s.client); err != nil {
		// TODO better errors, codes from below
		err := pb.NewError(pb.Error_RegistrationFailed, "registration failed: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("cannot write register response", "err", err)
		}
		return
	}
	s.logger.Info("registered listener", "name", name)

	if err := pb.Write(s.stream, &pbs.Response{}); err != nil {
		s.logger.Warn("cannot write register response", "err", err)
	}
}

func (s *ServerStream) connect(ctx context.Context, name string) {
	s.logger.Debug("lookup listener", "name", name)
	otherConn, err := s.client.server.find(s.client.auth, name)
	if err != nil {
		s.logger.Debug("listener lookup failed", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerNotFound, "failed to lookup registration: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	otherStream, err := otherConn.conn.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Debug("listener not connected", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerNotConnected, "failed to connect listener: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	if err := pb.Write(otherStream, &pbc.Request{
		Connect: &pbc.Request_Connect{
			Name: name,
		},
	}); err != nil {
		s.logger.Warn("error while writing request", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerRequestFailed, "failed to write client request: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	if _, err := pbc.ReadResponse(otherStream); err != nil {
		s.logger.Warn("error while reading response", "name", name, "err", err)
		var respErr *pb.Error
		if !errors.As(err, &respErr) {
			respErr = pb.NewError(pb.Error_ListenerResponseFailed, "failed to read client response: %v", err)
		}
		if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	if err := pb.Write(s.stream, &pbs.Response{}); err != nil {
		s.logger.Warn("failed to write response", "err", err)
		return
	}

	s.logger.Info("joining conns", "name", name)
	err = netc.Join(ctx, s.stream, otherStream)
	s.logger.Info("disconnected conns", "name", name, "err", err)
}

func (s *ServerStream) unknown(ctx context.Context, req *pbs.Request) {
	s.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	if err := pb.Write(s.stream, &pbc.Response{Error: err}); err != nil {
		s.logger.Warn("could not write response", "err", err)
	}
}

type serverConfig struct {
	address     string
	certificate *tls.Certificate
	logger      *slog.Logger
	auth        authc.Authenticator
}

type ServerOption func(*serverConfig) error

func ServerAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.address = address
		return nil
	}
}

func ServerSelfSigned() ServerOption {
	return func(cfg *serverConfig) error {
		if cert, err := certc.SelfSigned(); err != nil {
			return err
		} else {
			cfg.certificate = &cert
			return nil
		}
	}
}

func ServerCertificate(cert, key string) ServerOption {
	return func(cfg *serverConfig) error {
		if cert, err := certc.Load(cert, key); err != nil {
			return err
		} else {
			cfg.certificate = &cert
			return nil
		}
	}
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

func ServerAuthenticator(auth authc.Authenticator) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.auth = auth
		return nil
	}
}
