package detect

import "testing"

func TestDetectsAwsKey(t *testing.T) {
	f := Inspect("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	if f == nil || f.CredentialType != "aws_access_key_id" {
		t.Fatalf("expected aws key, got %#v", f)
	}
	if f.Redacted == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("redacted value must not equal the raw value")
	}
}

func TestDetectsHighEntropySecret(t *testing.T) {
	if Inspect("API_KEY", "aB3xZ9qL7wR2tP5mN8kQ1vC4") == nil {
		t.Fatal("expected high-entropy secret to be detected")
	}
}

func TestIgnoresPlaceholders(t *testing.T) {
	if Inspect("API_KEY", "your-api-key-here") != nil {
		t.Fatal("placeholder should not be flagged")
	}
	if Inspect("DB_PASSWORD", "${DB_PASSWORD}") != nil {
		t.Fatal("template reference should not be flagged")
	}
}

func TestIgnoresOrdinaryValues(t *testing.T) {
	if Inspect("LOG_LEVEL", "info") != nil {
		t.Fatal("ordinary value should not be flagged")
	}
	if Inspect("REPLICAS", "3") != nil {
		t.Fatal("number should not be flagged")
	}
}
