package atls

import (
	"bytes"
	"crypto/x509"
	"testing"
)

func TestBuildSEVSNPReportDataDeterministic(t *testing.T) {
	cert, err := GenerateExampleCertificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	context := []byte("request-context")
	first, err := buildSEVSNPReportData(context, leaf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildSEVSNPReportData(context, leaf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first[:], second[:]) {
		t.Fatalf("expected deterministic report data")
	}
	if len(first) != 64 {
		t.Fatalf("unexpected report data length: %d", len(first))
	}
}

func TestFetchDummyAttestationEvidence(t *testing.T) {
	evidence, err := fetchDummyAttestationEvidence([64]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.MediaType != dummyAttestationEvidenceMediaType {
		t.Fatalf("unexpected media type: %q", evidence.MediaType)
	}
	if string(evidence.Bytes) != dummyAttestationEvidence {
		t.Fatalf("unexpected dummy evidence: %q", evidence.Bytes)
	}
}
