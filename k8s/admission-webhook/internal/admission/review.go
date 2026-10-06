// Package admission implements the validating webhook logic using only the Go
// standard library. It defines the small subset of the admission.k8s.io/v1 and
// core/v1 schemas that the webhook needs, so it does not depend on the large
// Kubernetes client modules. Responses never contain a secret value; they name
// the container and variable and the credential type only.
package admission

import (
	"encoding/json"
	"fmt"

	"github.com/example/secretscope/k8s/admission-webhook/internal/detect"
)

// The minimal AdmissionReview types.

type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID    string          `json:"uid"`
	Kind   GroupVersionK   `json:"kind"`
	Object json.RawMessage `json:"object"`
}

type GroupVersionK struct {
	Kind string `json:"kind"`
}

type AdmissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Status  *Status `json:"status,omitempty"`
}

type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// The minimal object schema: enough to reach container env values in both a
// bare Pod and a workload that carries a pod template (Deployment, StatefulSet,
// DaemonSet, Job).

type object struct {
	Spec objectSpec `json:"spec"`
}

type objectSpec struct {
	Containers     []container `json:"containers"`
	InitContainers []container `json:"initContainers"`
	Template       *struct {
		Spec objectSpec `json:"spec"`
	} `json:"template"`
}

type container struct {
	Name string   `json:"name"`
	Env  []envVar `json:"env"`
}

type envVar struct {
	Name      string     `json:"name"`
	Value     string     `json:"value"`
	ValueFrom *valueFrom `json:"valueFrom,omitempty"`
}

type valueFrom struct {
	SecretKeyRef *struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"secretKeyRef,omitempty"`
}

func collectContainers(spec objectSpec) []container {
	var all []container
	all = append(all, spec.Containers...)
	all = append(all, spec.InitContainers...)
	if spec.Template != nil {
		all = append(all, collectContainers(spec.Template.Spec)...)
	}
	return all
}

// violation records one flagged variable. It never holds the secret value.
type violation struct {
	container      string
	envName        string
	credentialType string
	redacted       string
}

func (v violation) String() string {
	return fmt.Sprintf("container %q variable %q looks like a %s (%s)",
		v.container, v.envName, v.credentialType, v.redacted)
}

// Evaluate parses an object and returns any plaintext-credential violations.
// A variable sourced via valueFrom.secretKeyRef is never a violation, because
// that is exactly the pattern the webhook wants to encourage.
func Evaluate(raw json.RawMessage) ([]violation, error) {
	var obj object
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	var out []violation
	for _, c := range collectContainers(obj.Spec) {
		for _, e := range c.Env {
			if e.ValueFrom != nil {
				continue // sourced from a Secret or other reference; allowed
			}
			if f := detect.Inspect(e.Name, e.Value); f != nil {
				out = append(out, violation{
					container:      c.Name,
					envName:        e.Name,
					credentialType: f.CredentialType,
					redacted:       f.Redacted,
				})
			}
		}
	}
	return out, nil
}

// Review builds a response for an incoming AdmissionReview body.
func Review(body []byte) (*AdmissionReview, error) {
	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		return nil, err
	}
	resp := &AdmissionResponse{Allowed: true}
	if review.Request != nil {
		resp.UID = review.Request.UID
		violations, err := Evaluate(review.Request.Object)
		if err != nil {
			resp.Allowed = false
			resp.Status = &Status{Code: 400, Message: "could not parse object for credential inspection"}
		} else if len(violations) > 0 {
			resp.Allowed = false
			msg := "SecretScope blocked this object: plaintext credentials found. "
			for i, v := range violations {
				if i > 0 {
					msg += "; "
				}
				msg += v.String()
			}
			msg += ". Move these values into a Secret and reference them with valueFrom.secretKeyRef."
			resp.Status = &Status{Code: 403, Message: msg}
		}
	}
	return &AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response:   resp,
	}, nil
}

// Marshal encodes an AdmissionReview response as JSON.
func Marshal(review *AdmissionReview) ([]byte, error) {
	return json.Marshal(review)
}
