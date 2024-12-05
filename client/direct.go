package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	servers   map[string]*vServer
	serversMu sync.RWMutex
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) (*DirectServer, error) {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		servers: map[string]*vServer{},
	}, nil
}

type vServer struct {
	serverName string
	serverCert tls.Certificate
	clients    map[certc.Key]*vClient
	clientCA   atomic.Pointer[x509.CertPool]
	mu         sync.RWMutex
}

type vClient struct {
	cert *x509.Certificate
	ch   chan quic.Connection
}

func (s *vServer) dequeue(key certc.Key) *vClient {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.clients[key]; ok {
		delete(s.clients, key)
		return exp
	}

	return nil
}

func (s *vServer) updateClientCA() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientCA := x509.NewCertPool()
	for _, exp := range s.clients {
		clientCA.AddCert(exp.cert)
	}
	s.clientCA.Store(clientCA)
}

func (s *DirectServer) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runServer(ctx) })

	return g.Wait()
}

func (s *DirectServer) addServerCert(cert tls.Certificate) {
	serverName := cert.Leaf.DNSNames[0]

	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	s.logger.Debug("add server cert", "server", serverName, "cert", certc.NewKey(cert.Leaf))
	s.servers[serverName] = &vServer{
		serverName: serverName,
		serverCert: cert,
		clients:    map[certc.Key]*vClient{},
	}
}

func (s *DirectServer) getServer(serverName string) *vServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.servers[serverName]
}

func (s *DirectServer) expectConn(serverCert tls.Certificate, cert *x509.Certificate) chan quic.Connection {
	key := certc.NewKey(cert)
	srv := s.getServer(serverCert.Leaf.DNSNames[0])

	defer srv.updateClientCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if exp, ok := srv.clients[key]; ok {
		s.logger.Debug("cancel client", "server", srv.serverName, "cert", key)
		close(exp.ch)
	}

	s.logger.Debug("expect client", "server", srv.serverName, "cert", key)
	ch := make(chan quic.Connection)
	srv.clients[key] = &vClient{cert: cert, ch: ch}
	return ch
}

func (s *DirectServer) runServer(ctx context.Context) error {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"connet-direct"},
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		sni := s.getServer(chi.ServerName)
		if sni == nil {
			return nil, kleverr.Newf("server not found: %s", chi.ServerName)
		}
		conf := tlsConf.Clone()
		conf.Certificates = []tls.Certificate{sni.serverCert}
		conf.ClientCAs = sni.clientCA.Load()
		return conf, nil
	}

	l, err := s.transport.Listen(tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}

	s.logger.Debug("listening for conns")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		go s.runConn(conn)
	}
}

func (s *DirectServer) runConn(conn quic.Connection) {
	srv := s.getServer(conn.ConnectionState().TLS.ServerName)
	if srv == nil {
		conn.CloseWithError(1, "server not found")
		return
	}

	key := certc.NewKey(conn.ConnectionState().TLS.PeerCertificates[0])
	s.logger.Debug("accepted conn", "server", srv.serverName, "cert", key, "remote", conn.RemoteAddr())

	exp := srv.dequeue(key)
	if exp == nil {
		conn.CloseWithError(2, "client not found")
		return
	}

	s.logger.Debug("accept client", "server", srv.serverName, "cert", key)
	exp.ch <- conn
	close(exp.ch)

	srv.updateClientCA()
}
