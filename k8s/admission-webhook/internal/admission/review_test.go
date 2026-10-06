package admission

import (
	"encoding/json"
	"strings"
	"testing"
)

func review(t *testing.T, object string) *AdmissionResponse {
	t.Helper()
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",` +
		`"request":{"uid":"test-uid","kind":{"kind":"Pod"},"object":` + object + `}}`
	r, err := Review([]byte(body))
	if err != nil {
		t.Fatalf("review error: %v", err)
	}
	return r.Response
}

func TestAllowsSecretKeyRef(t *testing.T) {
	obj := `{"spec":{"containers":[{"name":"app","env":[
		{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}]}]}}`
	resp := review(t, obj)
	if !resp.Allowed {
		t.Fatalf("secretKeyRef should be allowed, got %#v", resp.Status)
	}
}

func TestRejectsPlaintextAwsKey(t *testing.T) {
	obj := `{"spec":{"containers":[{"name":"app","env":[
		{"name":"AWS_ACCESS_KEY_ID","value":"AKIAIOSFODNN7EXAMPLE"}]}]}}`
	resp := review(t, obj)
	if resp.Allowed {
		t.Fatal("plaintext AWS key should be rejected")
	}
	if strings.Contains(resp.Status.Message, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("response message must not contain the raw secret")
	}
	if resp.UID != "test-uid" {
		t.Fatalf("response UID should echo request UID, got %q", resp.UID)
	}
}

func TestRejectsPlaintextInDeploymentTemplate(t *testing.T) {
	obj := `{"spec":{"template":{"spec":{"containers":[{"name":"api","env":[
		{"name":"API_KEY","value":"aB3xZ9qL7wR2tP5mN8kQ1vC4"}]}]}}}}`
	resp := review(t, obj)
	if resp.Allowed {
		t.Fatal("plaintext secret in a deployment template should be rejected")
	}
}

func TestAllowsOrdinaryEnv(t *testing.T) {
	obj := `{"spec":{"containers":[{"name":"app","env":[
		{"name":"LOG_LEVEL","value":"info"},{"name":"REPLICAS","value":"3"}]}]}}`
	resp := review(t, obj)
	if !resp.Allowed {
		t.Fatalf("ordinary env should be allowed, got %#v", resp.Status)
	}
}

func TestResponseIsSerializable(t *testing.T) {
	obj := `{"spec":{"containers":[{"name":"app","env":[
		{"name":"AWS_ACCESS_KEY_ID","value":"AKIAIOSFODNN7EXAMPLE"}]}]}}`
	r, _ := Review([]byte(`{"request":{"uid":"u","object":` + obj + `}}`))
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("review response should serialize: %v", err)
	}
}
