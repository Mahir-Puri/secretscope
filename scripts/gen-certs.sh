#!/usr/bin/env bash
# Generate a self-signed TLS certificate for the webhook service and wire it
# into the cluster: create the TLS Secret and set the webhook caBundle.
#
# The generated key and certificate are local artifacts and are gitignored.
# This script needs openssl, kubectl, and a running cluster.
set -euo pipefail

NAMESPACE="secretscope"
SERVICE="secretscope-webhook"
CERT_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERT_DIR"

CN="${SERVICE}.${NAMESPACE}.svc"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${CERT_DIR}/tls.key" \
  -out "${CERT_DIR}/tls.crt" \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:${CN},DNS:${SERVICE}.${NAMESPACE}.svc.cluster.local"

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "${NAMESPACE}" create secret tls "${SERVICE}-certs" \
  --cert="${CERT_DIR}/tls.crt" \
  --key="${CERT_DIR}/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

CA_BUNDLE="$(base64 -w0 < "${CERT_DIR}/tls.crt")"
kubectl patch validatingwebhookconfiguration secretscope \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_BUNDLE}\"}]"

echo "certificates generated and caBundle injected"
