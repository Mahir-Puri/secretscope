// Command webhook runs the SecretScope validating admission webhook.
//
// It serves HTTPS (Kubernetes requires TLS for webhooks) and validates incoming
// AdmissionReview requests, rejecting objects that carry plaintext credentials
// in environment variables. It uses only the Go standard library.
package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/example/secretscope/k8s/admission-webhook/internal/admission"
)

func main() {
	var (
		addr     = flag.String("addr", ":8443", "address to listen on")
		certFile = flag.String("tls-cert", "/etc/webhook/certs/tls.crt", "path to TLS certificate")
		keyFile  = flag.String("tls-key", "/etc/webhook/certs/tls.key", "path to TLS private key")
		insecure = flag.Bool("insecure", false, "serve plain HTTP instead of HTTPS (local testing only)")
	)
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/validate", handleValidate)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("secretscope webhook listening on %s", *addr)
	var err error
	if *insecure {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 3<<20)) // cap at 3 MiB
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}
	review, err := admission.Review(body)
	if err != nil {
		http.Error(w, "could not parse admission review", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data, err := admission.Marshal(review)
	if err != nil {
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}
