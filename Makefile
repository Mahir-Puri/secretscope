# SecretScope developer tasks.
#
# Rust tasks use cargo. The webhook tasks use Go. The k8s-* tasks need Docker,
# kind, and kubectl and are not exercised in CI; they are here to make the local
# cluster demo reproducible.

CARGO ?= cargo
CLI := ./target/release/secretscope
IMAGE ?= secretscope/webhook:latest
KIND_CLUSTER ?= secretscope

.PHONY: all build release test lint fmt fmt-check demo benchmark clean \
        webhook-build webhook-test webhook-vet \
        k8s-up k8s-demo-safe k8s-demo-unsafe k8s-down

all: build test

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

demo: release
	@echo "== scanning the vulnerable fixture with blast-radius analysis =="
	$(CLI) scan fixtures/repositories/vulnerable --iam-dir fixtures/aws/demo-account

benchmark:
	$(CARGO) run --release -p benchmarks

clean:
	$(CARGO) clean
	rm -rf certs

webhook-build:
	cd k8s/admission-webhook && go build -o webhook ./cmd/webhook

webhook-test:
	cd k8s/admission-webhook && go test ./...

webhook-vet:
	cd k8s/admission-webhook && go vet ./...

k8s-up:
	kind create cluster --name $(KIND_CLUSTER)
	docker build -t $(IMAGE) k8s/admission-webhook
	kind load docker-image $(IMAGE) --name $(KIND_CLUSTER)
	kubectl apply -f k8s/manifests/namespace.yaml
	./scripts/gen-certs.sh
	kubectl apply -f k8s/manifests/deployment.yaml -f k8s/manifests/service.yaml
	kubectl apply -f k8s/manifests/validatingwebhookconfiguration.yaml

k8s-demo-safe:
	kubectl apply -f k8s/examples/safe-deployment.yaml

k8s-demo-unsafe:
	@echo "this apply is expected to be rejected by the webhook:"
	-kubectl apply -f k8s/examples/unsafe-aws-key.yaml

k8s-down:
	kind delete cluster --name $(KIND_CLUSTER)
