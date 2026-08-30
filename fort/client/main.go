package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danko-miladinovic/fort/atls"
)

const (
	defaultATLSAddr            = "127.0.0.1:9443"
	kernelCmdlinePath          = "/proc/cmdline"
	verifierIPKernelParam      = "verifier_ip"
	verifierPortKernelParam    = "verifier_port"
	atls_snp_attestation_param = "atls_snp_attestation"
	connectRetryInterval       = 5 * time.Second
	useSEVSNPAttestationEnv    = "ATLS_USE_SEV_SNP_ATTESTATION"
	rayCertDir                 = "/root"
	// pinnedServerCertPath is the path to the server's ATLS certificate embedded
	// in the worker image at build time. Workers pin this cert to authenticate the
	// central node before sending evidence or a CSR.
	pinnedServerCertPath = "/root/atls-server.crt"
)

func main() {
	addr := resolveDialAddress(os.Getenv, os.ReadFile)
	for {
		if err := run(addr); err != nil {
			log.Printf("client connection to %s failed: %v", addr, err)
			time.Sleep(connectRetryInterval)
			continue
		}
		return
	}
}

func run(addr string) error {
	useSEVSNPAttestation, err := resolveSEVSNPAttestation(os.Getenv, os.ReadFile)
	if err != nil {
		return err
	}

	key, csrPEM, err := generateCSR()
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	atlasCert, err := atls.GenerateCertificate()
	if err != nil {
		return err
	}
	pinnedDER, err := loadPinnedServerCert(pinnedServerCertPath)
	if err != nil {
		return err
	}
	conn, err := atls.Dial("tcp", addr, &atls.ClientConfig{
		TLSConfig: &tls.Config{
			// InsecureSkipVerify skips Go's built-in chain check (the server cert
			// is self-signed, so chain verification would always fail). The actual
			// authentication is done by VerifyPeerCertificate, which checks the
			// server's presented cert against the value pinned in the worker image.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 || !bytes.Equal(rawCerts[0], pinnedDER) {
					return fmt.Errorf("atls: server certificate does not match pinned cert")
				}
				return nil
			},
		},
		Identity:            atlasCert,
		BuildLeafExtensions: atls.AttesterLeafExtensions(useSEVSNPAttestation),
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("EA bootstrap complete; sending CSR")

	if _, err := conn.Write(csrPEM); err != nil {
		return fmt.Errorf("send CSR: %w", err)
	}

	// Server closes the connection after sending certs; read until EOF.
	certData, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read certs: %w", err)
	}

	workerCertPEM, caCertPEM, err := splitCerts(certData)
	if err != nil {
		return fmt.Errorf("parse cert response: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(rayCertDir+"/ray-worker.crt", workerCertPEM, 0644); err != nil {
		return fmt.Errorf("write worker cert: %w", err)
	}
	if err := os.WriteFile(rayCertDir+"/ray-worker.key", keyPEM, 0600); err != nil {
		return fmt.Errorf("write worker key: %w", err)
	}
	if err := os.WriteFile(rayCertDir+"/ca.crt", caCertPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	log.Printf("Ray TLS certs written to %s", rayCertDir)
	return nil
}

func generateCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "fort-ray-worker"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// splitCerts decodes the first two PEM blocks from data (worker cert, CA cert).
func splitCerts(data []byte) (workerCertPEM, caCertPEM []byte, err error) {
	b1, rest := pem.Decode(data)
	if b1 == nil {
		return nil, nil, fmt.Errorf("no worker cert block")
	}
	b2, _ := pem.Decode(rest)
	if b2 == nil {
		return nil, nil, fmt.Errorf("no CA cert block")
	}
	return pem.EncodeToMemory(b1), pem.EncodeToMemory(b2), nil
}

func resolveDialAddress(getenv func(string) string, readFile func(string) ([]byte, error)) string {
	if addr := strings.TrimSpace(getenv("ATLS_ADDR")); addr != "" {
		return addr
	}
	if addr, ok := verifierAddressFromSource(getenv("VERIFIER_IP"), getenv("VERIFIER_PORT")); ok {
		return addr
	}
	cmdline, err := readFile(kernelCmdlinePath)
	if err != nil {
		log.Printf("unable to read %s: %v", kernelCmdlinePath, err)
		return defaultATLSAddr
	}
	params := parseKernelCmdline(string(cmdline))
	if addr, ok := verifierAddressFromSource(
		params[verifierIPKernelParam],
		params[verifierPortKernelParam],
	); ok {
		return addr
	}
	return defaultATLSAddr
}

func verifierAddressFromSource(ip, port string) (string, bool) {
	ip = strings.TrimSpace(ip)
	port = strings.TrimSpace(port)
	if ip == "" || port == "" {
		return "", false
	}
	return net.JoinHostPort(ip, port), true
}

func parseKernelCmdline(cmdline string) map[string]string {
	params := make(map[string]string)
	for _, field := range strings.Fields(cmdline) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		params[key] = value
	}
	return params
}

// resolveSEVSNPAttestation returns true if real SEV-SNP attestation should be
// used. The kernel cmdline parameter atls_snp_attestation takes precedence over
// the ATLS_USE_SEV_SNP_ATTESTATION env var, so a plain VM can be launched with
// atls_snp_attestation=false on the cmdline without a separate image.
func resolveSEVSNPAttestation(getenv func(string) string, readFile func(string) ([]byte, error)) (bool, error) {
	cmdline, err := readFile(kernelCmdlinePath)
	if err == nil {
		params := parseKernelCmdline(string(cmdline))
		if v, ok := params[atls_snp_attestation_param]; ok {
			enabled, err := strconv.ParseBool(v)
			if err != nil {
				return false, fmt.Errorf("invalid %s value %q in kernel cmdline", atls_snp_attestation_param, v)
			}
			return enabled, nil
		}
	}
	return boolEnv(useSEVSNPAttestationEnv)
}

func boolEnv(key string) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q", key, value)
	}
	return enabled, nil
}

// loadPinnedServerCert reads a PEM-encoded certificate from path and returns
// its raw DER bytes for use in VerifyPeerCertificate.
func loadPinnedServerCert(path string) ([]byte, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("atls: read pinned server cert %s: %w", path, err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("atls: no PEM block in pinned server cert %s", path)
	}
	return block.Bytes, nil
}
