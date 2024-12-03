package selfhosted

import (
	"context"
	"crypto/x509"
	"sync"
	"sync/atomic"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/relay"
)

func NewRelaySync(relayAddr model.HostPort, cert *x509.Certificate) (*RelaySync, error) {
	s := &RelaySync{
		relays: notify.NewV[map[model.HostPort]*x509.Certificate](),
		certs:  map[certc.Key]*relay.Authentication{},
	}
	s.relays.Set(map[model.HostPort]*x509.Certificate{relayAddr: cert})
	return s, nil
}

type RelaySync struct {
	relays  *notify.V[map[model.HostPort]*x509.Certificate]
	certs   map[certc.Key]*relay.Authentication
	certsMu sync.RWMutex
	pool    atomic.Pointer[x509.CertPool]
}

func (s *RelaySync) Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	auth := &relay.Authentication{
		Certificate:  cert,
		Destinations: map[model.Forward]struct{}{},
		Sources:      map[model.Forward]struct{}{},
	}
	for _, dst := range destinations {
		auth.Destinations[dst] = struct{}{}
	}
	for _, src := range sources {
		auth.Sources[src] = struct{}{}
	}

	s.certs[certc.NewKey(cert)] = auth

	pool := x509.NewCertPool()
	for _, cfg := range s.certs {
		pool.AddCert(cfg.Certificate)
	}
	s.pool.Store(pool)
}

func (s *RelaySync) Remove(cert *x509.Certificate) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	delete(s.certs, certc.NewKey(cert))

	pool := x509.NewCertPool()
	for _, cfg := range s.certs {
		pool.AddCert(cfg.Certificate)
	}
	s.pool.Store(pool)
}

func (s *RelaySync) Active(ctx context.Context, f func(map[model.HostPort]*x509.Certificate) error) error {
	return s.relays.Listen(ctx, f)
}

func (s *RelaySync) Authenticate(certs []*x509.Certificate) *relay.Authentication {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()

	for _, cert := range certs {
		if auth := s.certs[certc.NewKey(cert)]; auth != nil && auth.Certificate.Equal(cert) {
			return auth
		}
	}

	return nil
}

func (s *RelaySync) CertificateAuthority() *x509.CertPool {
	return s.pool.Load()
}
