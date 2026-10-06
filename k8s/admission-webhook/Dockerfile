# Build a static webhook binary and ship it on a minimal base.
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook /webhook
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/webhook"]
