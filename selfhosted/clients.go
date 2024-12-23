package selfhosted

import (
	"encoding/json"

	"github.com/keihaya-com/connet/control"
	"github.com/keihaya-com/connet/model"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(tokens ...string) control.ClientAuthenticator {
	s := &clientsAuthenticator{map[string]struct{}{}}
	for _, t := range tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

type clientsAuthenticator struct {
	tokens map[string]struct{}
}

func (s *clientsAuthenticator) Authenticate(token string) (control.ClientAuthentication, error) {
	if _, ok := s.tokens[token]; ok {
		return &clientAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type clientAuthentication struct {
	token string
}

func (a *clientAuthentication) Validate(fwd model.Forward, role model.Role) (model.Forward, error) {
	return fwd, nil
}

func (a *clientAuthentication) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.token)
}

func (a *clientAuthentication) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*a = clientAuthentication{s}
	return nil
}
