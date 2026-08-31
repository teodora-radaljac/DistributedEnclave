package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/danko-miladinovic/fort/atls/attestation"
	"github.com/danko-miladinovic/fort/atls/ea"
	sevguestclient "github.com/google/go-sev-guest/client"
	"google.golang.org/protobuf/proto"
)

type AcceptEvidenceVerifier struct{}

func (AcceptEvidenceVerifier) VerifyEvidence(_ []byte, _ [64]byte) error { return nil }

const (
	dummyAttestationEvidence           = "dummy-attestation-report"
	dummyAttestationEvidenceMediaType  = "application/octet-stream"
	sevSNPAttestationEvidenceMediaType = "application/vnd.google.go-sev-guest.attestation+protobuf"
)

type AttestationEvidence struct {
	MediaType string
	Bytes     []byte
}

type AttestationEvidenceFetcher func(reportData [64]byte) (AttestationEvidence, error)

// GenerateCertificate generates a fresh self-signed ATLS identity certificate
// using crypto/rand, so each caller gets a distinct key pair.
func GenerateCertificate() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "atls-identity"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// GenerateExampleCertificate returns a deterministic certificate for tests and
// examples. Do not use in production — all callers get the identical key pair.
func GenerateExampleCertificate() (tls.Certificate, error) {
	entropy := newDeterministicReader(1)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), entropy)
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "atls-test"},
		NotBefore:             notBefore,
		NotAfter:              time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(entropy, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func ExampleServerLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	return ExampleAttesterLeafExtensions(st, req, leaf)
}

func SEVSNPServerLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	return SEVSNPAttesterLeafExtensions(st, req, leaf)
}

func ExampleAttesterLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	return buildAttesterLeafExtensions(st, req, leaf, fetchDummyAttestationEvidence)
}

func SEVSNPAttesterLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	return buildAttesterLeafExtensions(st, req, leaf, fetchSEVSNPAttestationEvidence)
}

func AttesterLeafExtensions(useSEVSNP bool) func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) ([]ea.Extension, error) {
	if useSEVSNP {
		return SEVSNPAttesterLeafExtensions
	}
	return ExampleAttesterLeafExtensions
}

func ServerLeafExtensions(useSEVSNP bool) func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) ([]ea.Extension, error) {
	return AttesterLeafExtensions(useSEVSNP)
}

func buildAttesterLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate, fetcher AttestationEvidenceFetcher) ([]ea.Extension, error) {
	if req == nil {
		return nil, fmt.Errorf("atls: missing authenticator request")
	}
	if fetcher == nil {
		fetcher = fetchDummyAttestationEvidence
	}

	_, aikPubHash, binding, err := attestation.ComputeBinding(st, attestation.ExporterLabelAttestation, req.Context, leaf)
	if err != nil {
		return nil, err
	}
	reportData, err := buildSEVSNPReportData(req.Context, leaf)
	if err != nil {
		return nil, err
	}
	evidence, err := fetcher(reportData)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:   1,
		MediaType: evidence.MediaType,
		Evidence:  evidence.Bytes,
		Binder: attestation.AttestationBinder{
			AIKPubHash: aikPubHash,
			Binding:    binding,
		},
	})
	if err != nil {
		return nil, err
	}
	ext, err := ea.CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		return nil, err
	}
	return []ea.Extension{ext}, nil
}

func buildSEVSNPReportData(context []byte, leaf *x509.Certificate) ([64]byte, error) {
	var reportData [64]byte

	pubKey, err := attestation.PublicKeyBytes(leaf)
	if err != nil {
		return reportData, err
	}
	digest := sha512.New()
	if _, err := digest.Write(pubKey); err != nil {
		return reportData, err
	}
	if _, err := digest.Write(context); err != nil {
		return reportData, err
	}
	copy(reportData[:], digest.Sum(nil))
	return reportData, nil
}

func fetchDummyAttestationEvidence(_ [64]byte) (AttestationEvidence, error) {
	return AttestationEvidence{
		MediaType: dummyAttestationEvidenceMediaType,
		Bytes:     []byte(dummyAttestationEvidence),
	}, nil
}

func fetchSEVSNPAttestationEvidence(reportData [64]byte) (AttestationEvidence, error) {
	device, err := sevguestclient.OpenDevice()
	if err != nil {
		return AttestationEvidence{}, fmt.Errorf("open SEV guest device: %w", err)
	}
	defer device.Close()

	report, err := sevguestclient.GetExtendedReport(device, reportData)
	if err != nil {
		return AttestationEvidence{}, fmt.Errorf("get SEV-SNP extended report: %w", err)
	}
	evidence, err := proto.Marshal(report)
	if err != nil {
		return AttestationEvidence{}, fmt.Errorf("marshal SEV-SNP attestation: %w", err)
	}
	return AttestationEvidence{
		MediaType: sevSNPAttestationEvidenceMediaType,
		Bytes:     evidence,
	}, nil
}

func ExampleRequest(context []byte) (*ea.AuthenticatorRequest, error) {
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		return nil, err
	}
	return &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeCertificateRequest,
		Context: context,
		Extensions: []ea.Extension{
			sigExt,
			ea.CMWAttestationOfferExtension(),
		},
	}, nil
}

func ExampleVerifyOptions(cert tls.Certificate) (*x509.VerifyOptions, error) {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, nil
}

type deterministicReader struct {
	r *mathrand.Rand
}

func newDeterministicReader(seed int64) io.Reader {
	return &deterministicReader{r: mathrand.New(mathrand.NewSource(seed))}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.r.Intn(256))
	}
	return len(p), nil
}
