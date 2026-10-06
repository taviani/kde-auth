package usecase

import "testing"

func TestOIDCMetadataOmitsIDTokenSigningAlgs(t *testing.T) {
	uc := NewOIDCMetadata(stubIssuer{url: "https://auth.example"})
	doc := uc.Execute()
	if _, ok := doc["id_token_signing_alg_values_supported"]; ok {
		t.Fatalf("discovery must not advertise id_token support: %#v", doc["id_token_signing_alg_values_supported"])
	}
	if doc["issuer"] != "https://auth.example" {
		t.Fatalf("issuer: %v", doc["issuer"])
	}
	if doc["userinfo_endpoint"] != "https://auth.example/userinfo" {
		t.Fatalf("userinfo: %v", doc["userinfo_endpoint"])
	}
}
