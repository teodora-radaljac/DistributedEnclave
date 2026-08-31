package attestation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

type EvidenceVerifier interface {
	// VerifyEvidence verifies the attestation evidence. expectedReportData is
	// the SHA-512(AIK pub || context) value the attester embedded in REPORT_DATA;
	// the implementation MUST check the signed report contains this exact value.
	VerifyEvidence(evidence []byte, expectedReportData [64]byte) error
}

type ResultsVerifier interface {
	VerifyAttestationResults(results []byte) error
}

type VerificationPolicy struct {
	EvidenceVerifier EvidenceVerifier
	ResultsVerifier  ResultsVerifier
}

func VerifyPayload(st *tls.ConnectionState, defaultLabel string, certificateRequestContext []byte, leaf *x509.Certificate, payload *Payload, policy VerificationPolicy) (*VerifiedPayload, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}

	verified := &VerifiedPayload{
		Payload:           payload,
		UsedExporterLabel: defaultLabel,
	}

	if len(payload.Evidence) > 0 && policy.EvidenceVerifier != nil {
		expectedRD, err := ComputeReportData(certificateRequestContext, leaf)
		if err != nil {
			return nil, fmt.Errorf("attestation: compute report data: %w", err)
		}
		if err := policy.EvidenceVerifier.VerifyEvidence(payload.Evidence, expectedRD); err != nil {
			return nil, err
		}
		verified.EvidenceVerified = true
	} else if len(payload.Evidence) > 0 {
		return nil, ErrEvidenceVerificationMissing
	}
	if len(payload.AttestationResults) > 0 && policy.ResultsVerifier != nil {
		if err := policy.ResultsVerifier.VerifyAttestationResults(payload.AttestationResults); err != nil {
			return nil, err
		}
		verified.ResultsVerified = true
	} else if len(payload.AttestationResults) > 0 {
		return nil, ErrResultsVerificationMissing
	}
	if err := VerifyBinder(st, defaultLabel, certificateRequestContext, leaf, payload.Binder); err != nil {
		return nil, err
	}
	verified.BindingVerified = true
	return verified, nil
}

func VerifyBinder(st *tls.ConnectionState, label string, certificateRequestContext []byte, leaf *x509.Certificate, binder AttestationBinder) error {
	exportedValue, aikPubHash, binding, err := ComputeBinding(st, label, certificateRequestContext, leaf)
	if err != nil {
		return err
	}
	_ = exportedValue
	if !equalBytes(aikPubHash, binder.AIKPubHash) {
		return ErrAIKPubHashMismatch
	}
	if !equalBytes(binding, binder.Binding) {
		return ErrBindingMismatch
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
