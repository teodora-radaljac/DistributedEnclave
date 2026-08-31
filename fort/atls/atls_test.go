package atls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"

	"github.com/danko-miladinovic/fort/atls/attestation"
	"github.com/danko-miladinovic/fort/atls/ea"
)

func TestClientServerBootstrapOverCryptoTLS(t *testing.T) {
	cert, err := GenerateExampleCertificate()
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	serverCfg := &ServerConfig{
		TLSConfig:     serverTLS,
		VerifyOptions: verifyOptsOrFatal(t, cert),
		AttestationPolicy: attestation.VerificationPolicy{
			EvidenceVerifier: AcceptEvidenceVerifier{},
		},
	}

	a, b := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		tlsConn := tls.Server(a, serverTLS.Clone())
		conn, err := Server(tlsConn, serverCfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if conn.ValidationResult == nil || conn.ValidationResult.Attestation == nil {
			serverErr <- fmt.Errorf("expected client attestation validation result")
			return
		}
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(buf, []byte("ping")) {
			serverErr <- fmt.Errorf("unexpected client payload %q", buf)
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	clientConn, err := Client(tls.Client(b, clientTLS.Clone()), &ClientConfig{
		TLSConfig:           clientTLS,
		Identity:            cert,
		BuildLeafExtensions: ExampleAttesterLeafExtensions,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	if clientConn.ValidationResult != nil {
		t.Fatalf("expected client side validation result to be empty")
	}
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := clientConn.Read(reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("unexpected reply %q", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDefaultServerRequestUsesCertificateRequest(t *testing.T) {
	req, err := buildRequest(&ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Type != ea.HandshakeTypeCertificateRequest {
		t.Fatalf("request type = %d, want %d", req.Type, ea.HandshakeTypeCertificateRequest)
	}

	exampleReq, err := ExampleRequest([]byte("request-context"))
	if err != nil {
		t.Fatal(err)
	}
	if exampleReq.Type != ea.HandshakeTypeCertificateRequest {
		t.Fatalf("example request type = %d, want %d", exampleReq.Type, ea.HandshakeTypeCertificateRequest)
	}
}

func verifyOptsOrFatal(t *testing.T, cert tls.Certificate) *x509.VerifyOptions {
	t.Helper()
	verifyOpts, err := ExampleVerifyOptions(cert)
	if err != nil {
		t.Fatal(err)
	}
	return verifyOpts
}
