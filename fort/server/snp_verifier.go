package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"
)

// SNPEvidenceVerifier verifies SEV-SNP attestation evidence produced by
// go-sev-guest's GetExtendedReport and marshalled as proto.
//
// Environment variables (all consumed by main.go):
//
//	FORT_SKIP_SNP_VERIFY=true       bypass AMD VCEK signature check (QEMU testing)
//	FORT_ALLOW_DUMMY=true           accept non-proto (dummy) evidence from non-SEV VMs
//	FORT_EXPECTED_MEASUREMENT=<hex> require this exact 48-byte firmware measurement
type SNPEvidenceVerifier struct {
	// SkipVerification bypasses the AMD VCEK signature check.
	// Must NOT be used in production — only for testing without real AMD hardware.
	SkipVerification bool

	// AllowDummy accepts evidence that cannot be parsed as a pb.Attestation proto
	// (e.g. the dummy "application/octet-stream" evidence sent by non-SEV VMs).
	// Must NOT be used in production.
	AllowDummy bool

	// ExpectedMeasurement, if non-nil, is the required 48-byte SHA-384
	// measurement of the CVM image (firmware + kernel). Nil means any
	// measurement is accepted.
	ExpectedMeasurement []byte
}

// VerifyEvidence implements attestation.EvidenceVerifier.
func (v *SNPEvidenceVerifier) VerifyEvidence(evidence []byte, expectedReportData [64]byte) error {
	var att spb.Attestation
	if err := proto.Unmarshal(evidence, &att); err != nil {
		if v.AllowDummy {
			log.Printf("snp: accepting dummy (non-SEV) evidence")
			return nil
		}
		return fmt.Errorf("snp: evidence is not a valid SEV-SNP attestation proto: %w", err)
	}

	report := att.GetReport()
	if report == nil {
		return fmt.Errorf("snp: attestation proto contains no report")
	}

	if !v.SkipVerification {
		// verify.SnpAttestation checks the full AMD certificate chain:
		//   ARK (AMD Root Key) → ASK (AMD SEV Key) → VCEK → Report signature.
		// VCEK certificates are embedded in the ExtendedReport or fetched from
		// AMD's Key Distribution Service (KDS) over HTTPS.
		if err := verify.SnpAttestation(&att, verify.DefaultOptions()); err != nil {
			return fmt.Errorf("snp: AMD signature chain verification failed: %w", err)
		}
	}

	// Validate report fields. ReportData is always checked — it ties the
	// AMD-signed evidence to this specific TLS connection and EA leaf key,
	// preventing replay of a genuine evidence blob from another session.
	vopts := &validate.Options{
		ReportData: expectedReportData[:],
		// Allow the SMT-allowed bit in the guest policy (bit 16).
		// QEMU sets this by default; leaving it false would reject any VM
		// whose SNP guest policy permits SMT.
		GuestPolicy: abi.SnpPolicy{SMT: true},
	}
	if v.ExpectedMeasurement != nil {
		vopts.Measurement = v.ExpectedMeasurement
	}
	if err := validate.SnpAttestation(&att, vopts); err != nil {
		return fmt.Errorf("snp: report validation failed: %w", err)
	}

	log.Printf("snp: attestation accepted  measurement=%s", hex.EncodeToString(report.GetMeasurement()))
	return nil
}
