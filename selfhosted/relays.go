package selfhosted

import (
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/klev-dev/kleverr"
)

func NewRelayAuthenticator(tokens ...string) control.RelayAuthenticator {
	s := &relayAuthenticator{map[string]struct{}{}}
	for _, t := range tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

type relayAuthenticator struct {
	tokens map[string]struct{}
}

func (s *relayAuthenticator) Authenticate(token string) (control.RelayAuthentication, error) {
	if _, ok := s.tokens[token]; ok {
		return &relayAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type relayAuthentication struct {
	token string
}

func (r *relayAuthentication) Allow(fwd model.Forward) bool {
	return true
}

func (r *relayAuthentication) MarshalBinary() (data []byte, err error) {
	return []byte(r.token), nil
}
