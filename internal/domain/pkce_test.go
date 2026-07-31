package domain

import "testing"

func TestVerifyPKCES256(t *testing.T) {
	// Example from RFC 7636 appendix B
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if err := VerifyPKCES256(challenge, verifier); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
	if err := VerifyPKCES256(challenge, "wrong-verifier-wrong-verifier-wrong-verif"); err == nil {
		t.Fatal("expected mismatch")
	}
}
