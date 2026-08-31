package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/danko-miladinovic/fort/atls"
	"github.com/danko-miladinovic/fort/atls/attestation"
)

// issuingCA holds a self-signed CA and issues short-lived leaf certs.
type issuingCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	counter atomic.Int64
}

func newIssuingCA() (*issuingCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fort Ray CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca := &issuingCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
	ca.counter.Store(1)
	return ca, nil
}

func (ca *issuingCA) issue(pub interface{}, cn string, ips []net.IP) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.counter.Add(1)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (ca *issuingCA) signCSR(csrPEM []byte, workerIP string) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	var ips []net.IP
	if ip := net.ParseIP(workerIP); ip != nil {
		ips = append(ips, ip)
	}
	return ca.issue(csr.PublicKey, csr.Subject.CommonName, ips)
}

func (ca *issuingCA) issueHeadCert(headIP string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(headIP); ip != nil {
		ips = append(ips, ip)
	}
	// Workers dial the head via the bridge IP (verifier_ip=192.168.100.1 on the
	// kernel cmdline), so the cert must cover that address even when headIP is the
	// host's LAN IP.
	const bridgeIP = "192.168.100.1"
	if headIP != bridgeIP {
		ips = append(ips, net.ParseIP(bridgeIP))
	}
	certPEM, err = ca.issue(&key.PublicKey, "fort-ray-head", ips)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// loadOrGenerateATLSCert loads the server's ATLS identity certificate from disk.
// If the files don't exist it generates a fresh key pair, saves it, and logs a
// reminder to copy the cert into the buildroot overlay before the next image
// build — the cert must be embedded in the measured worker image so workers can
// pin it.
func loadOrGenerateATLSCert(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load ATLS cert: %w", err)
		}
		log.Printf("ATLS identity loaded from %s", certPath)
		return cert, nil
	}

	cert, err := atls.GenerateCertificate()
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if err := os.WriteFile(certPath, newCertPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write ATLS cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return tls.Certificate{}, err
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, newKeyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write ATLS key: %w", err)
	}
	log.Printf("ATLS identity generated and saved to %s", certPath)
	log.Printf("ACTION REQUIRED: copy %s into the buildroot overlay "+
		"(fort/buildroot/board/fort/rootfs-overlay/root/atls-server.crt) "+
		"and rebuild the worker image before starting workers", certPath)
	return cert, nil
}

func main() {
	addr := envOrDefault("ATLS_ADDR", "0.0.0.0:9443")
	headIP := envOrDefault("RAY_HEAD_IP", "127.0.0.1")
	caCertPath := envOrDefault("RAY_CA_CERT_PATH", "ca.crt")
	headCertPath := envOrDefault("RAY_HEAD_CERT_PATH", "head.crt")
	headKeyPath := envOrDefault("RAY_HEAD_KEY_PATH", "head.key")
	atlasCertPath := envOrDefault("FORT_ATLS_CERT_PATH", "atls-server.crt")
	atlasKeyPath := envOrDefault("FORT_ATLS_KEY_PATH", "atls-server.key")

	// SNP verification config (env-driven so it survives binary deploys).
	//
	//   FORT_SKIP_SNP_VERIFY=true   — skip AMD VCEK signature check; accept any
	//                                 valid SEV-SNP proto (for QEMU test setups).
	//   FORT_EXPECTED_MEASUREMENT=<96 hex chars>
	//                               — require this exact 48-byte measurement.
	//
	// Non-SEV (dummy evidence) clients are always rejected once SNP verification
	// is in use; the bypass only affects the AMD signature chain check.
	skipSNPVerify := strings.EqualFold(os.Getenv("FORT_SKIP_SNP_VERIFY"), "true")
	allowDummy := strings.EqualFold(os.Getenv("FORT_ALLOW_DUMMY"), "true")
	var expectedMeasurement []byte
	if m := strings.TrimSpace(os.Getenv("FORT_EXPECTED_MEASUREMENT")); m != "" {
		var err error
		expectedMeasurement, err = hex.DecodeString(m)
		if err != nil || len(expectedMeasurement) != 48 {
			log.Fatalf("FORT_EXPECTED_MEASUREMENT must be 96 hex chars (48 bytes), got %q", m)
		}
	}

	snpVerifier := &SNPEvidenceVerifier{
		SkipVerification:    skipSNPVerify,
		AllowDummy:          allowDummy,
		ExpectedMeasurement: expectedMeasurement,
	}
	if skipSNPVerify {
		log.Printf("WARNING: SNP AMD signature verification DISABLED (FORT_SKIP_SNP_VERIFY=true)")
	}
	if allowDummy {
		log.Printf("WARNING: dummy (non-SEV) evidence ACCEPTED (FORT_ALLOW_DUMMY=true)")
	}
	if expectedMeasurement != nil {
		log.Printf("SNP measurement enforcement enabled: %s", hex.EncodeToString(expectedMeasurement))
	}

	ca, err := newIssuingCA()
	if err != nil {
		log.Fatalf("create CA: %v", err)
	}
	if err := os.WriteFile(caCertPath, ca.certPEM, 0644); err != nil {
		log.Fatalf("write CA cert: %v", err)
	}
	headCert, headKey, err := ca.issueHeadCert(headIP)
	if err != nil {
		log.Fatalf("issue head cert: %v", err)
	}
	if err := os.WriteFile(headCertPath, headCert, 0644); err != nil {
		log.Fatalf("write head cert: %v", err)
	}
	if err := os.WriteFile(headKeyPath, headKey, 0600); err != nil {
		log.Fatalf("write head key: %v", err)
	}
	log.Printf("CA cert → %s  head cert → %s  head key → %s", caCertPath, headCertPath, headKeyPath)

	atlasCert, err := loadOrGenerateATLSCert(atlasCertPath, atlasKeyPath)
	if err != nil {
		log.Fatalf("ATLS identity: %v", err)
	}
	ln, err := atls.Listen("tcp", addr, &atls.ServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{atlasCert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		},
		VerifyOptions: nil, // EA signature + attestation evidence provide the security guarantee
		AttestationPolicy: attestation.VerificationPolicy{
			EvidenceVerifier: snpVerifier,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Printf("ATLS server listening on %s", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, ca)
	}
}

func handleConn(conn net.Conn, ca *issuingCA) {
	defer conn.Close()

	atlsConn, ok := conn.(*atls.Conn)
	if !ok {
		log.Printf("reject %s: not an ATLS connection", conn.RemoteAddr())
		return
	}
	attested := atlsConn.ValidationResult != nil
	log.Printf("connection from %s attested=%v", conn.RemoteAddr(), attested)
	if !attested {
		log.Printf("reject %s: attestation required", conn.RemoteAddr())
		return
	}

	// Read CSR PEM line by line until the end marker.
	scanner := bufio.NewScanner(conn)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if line == "-----END CERTIFICATE REQUEST-----" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("read CSR from %s: %v", conn.RemoteAddr(), err)
		return
	}
	csrPEM := []byte(strings.Join(lines, "\n") + "\n")

	workerIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	workerCert, err := ca.signCSR(csrPEM, workerIP)
	if err != nil {
		log.Printf("sign CSR for %s: %v", workerIP, err)
		return
	}

	// Send worker cert then CA cert; EOF on close signals the client to stop reading.
	if _, err := conn.Write(workerCert); err != nil {
		log.Printf("send cert to %s: %v", workerIP, err)
		return
	}
	if _, err := conn.Write(ca.certPEM); err != nil {
		log.Printf("send CA cert to %s: %v", workerIP, err)
		return
	}
	log.Printf("issued Ray TLS cert for worker %s", workerIP)
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
