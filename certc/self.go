package certc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/klev-dev/kleverr"
)

var SharedSubject = pkix.Name{
	Country:      []string{"US"},
	Organization: []string{"Connet"},
}

type Cert struct {
	der []byte
	pk  ed25519.PrivateKey
}

type CertOpts struct {
	Domains []string
	IPs     []net.IP
}

type certType struct{ string }

var (
	intermediateCert = certType{"intermediate"}
	serverCert       = certType{"server"}
	clientCert       = certType{"client"}
)

func NewRoot() (*Cert, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),

		Subject: SharedSubject,

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}
	return &Cert{der, priv}, nil
}

func (c *Cert) new(opts CertOpts, typ certType) (*Cert, error) {
	parent, err := x509.ParseCertificate(c.der)
	if err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: SharedSubject,

		DNSNames:    opts.Domains,
		IPAddresses: opts.IPs,
	}

	csrData, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrData)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),

		Issuer:  parent.Subject,
		Subject: csr.Subject,

		DNSNames:    opts.Domains,
		IPAddresses: opts.IPs,

		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	switch typ {
	case intermediateCert:
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = true

		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{}
	case serverCert:
		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case clientCert:
		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{}
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, csr.PublicKey, c.pk)
	if err != nil {
		return nil, err
	}

	return &Cert{der, priv}, nil
}

func (c *Cert) NewIntermediate(opts CertOpts) (*Cert, error) {
	return c.new(opts, intermediateCert)
}

func (c *Cert) NewServer(opts CertOpts) (*Cert, error) {
	return c.new(opts, serverCert)
}

func (c *Cert) NewClient(opts CertOpts) (*Cert, error) {
	return c.new(opts, clientCert)
}

func (c *Cert) Cert() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.der)
}

func (c *Cert) CertPool() (*x509.CertPool, error) {
	cert, err := c.Cert()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

func (c *Cert) TLSCert() (tls.Certificate, error) {
	cert, err := c.Cert()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{c.der},
		PrivateKey:  c.pk,
		Leaf:        cert,
	}, nil
}

func (c *Cert) Encode(certOut io.Writer, keyOut io.Writer) error {
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.der,
	}); err != nil {
		return kleverr.Ret(err)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(c.pk)
	if err != nil {
		return kleverr.Ret(err)
	}
	return pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	})
}

func (c *Cert) EncodeToMemory() ([]byte, []byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.der,
	})

	keyData, err := x509.MarshalPKCS8PrivateKey(c.pk)
	if err != nil {
		return nil, nil, kleverr.Ret(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	})
	return certPEM, keyPEM, nil
}

func SelfSigned(domain string) (tls.Certificate, error) {
	root, err := NewRoot()
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := root.NewServer(CertOpts{
		Domains: []string{domain},
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert.TLSCert()
}
