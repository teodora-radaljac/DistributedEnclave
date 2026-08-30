package main

import (
	"errors"
	"testing"
)

func TestParseKernelCmdline(t *testing.T) {
	params := parseKernelCmdline("console=ttyS0 verifier_ip=192.0.2.10 verifier_port=8443 root=/dev/ram0")

	if got := params[verifierIPKernelParam]; got != "192.0.2.10" {
		t.Fatalf("expected verifier_ip to be parsed, got %q", got)
	}
	if got := params[verifierPortKernelParam]; got != "8443" {
		t.Fatalf("expected verifier_port to be parsed, got %q", got)
	}
}

func TestResolveDialAddressPrefersATLSAddr(t *testing.T) {
	addr := resolveDialAddress(func(key string) string {
		if key == "ATLS_ADDR" {
			return "198.51.100.7:9443"
		}
		return ""
	}, func(string) ([]byte, error) {
		return nil, errors.New("should not read kernel cmdline when ATLS_ADDR is set")
	})

	if addr != "198.51.100.7:9443" {
		t.Fatalf("expected ATLS_ADDR to win, got %q", addr)
	}
}

func TestResolveDialAddressFallsBackToKernelCmdline(t *testing.T) {
	addr := resolveDialAddress(func(string) string {
		return ""
	}, func(string) ([]byte, error) {
		return []byte("quiet verifier_ip=203.0.113.9 verifier_port=10443"), nil
	})

	if addr != "203.0.113.9:10443" {
		t.Fatalf("expected kernel cmdline verifier address, got %q", addr)
	}
}

func TestBoolEnvDefaultsFalse(t *testing.T) {
	t.Setenv(useSEVSNPAttestationEnv, "")

	enabled, err := boolEnv(useSEVSNPAttestationEnv)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("expected env to default to false")
	}
}

func TestBoolEnvParsesTrue(t *testing.T) {
	t.Setenv(useSEVSNPAttestationEnv, "true")

	enabled, err := boolEnv(useSEVSNPAttestationEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("expected env to parse as true")
	}
}

func TestBoolEnvRejectsInvalidValue(t *testing.T) {
	t.Setenv(useSEVSNPAttestationEnv, "not-a-bool")

	if _, err := boolEnv(useSEVSNPAttestationEnv); err == nil {
		t.Fatal("expected invalid env value to fail")
	}
}
