FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN /usr/local/go/bin/go mod download
COPY main.go guard.go ./
RUN CGO_ENABLED=0 GOOS=linux /usr/local/go/bin/go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/slipnet-relay .

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS certs
RUN apk add --no-cache ca-certificates

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/slipnet-relay /slipnet-relay

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV PORT=8080
EXPOSE 8080

USER 10001:10001
ENTRYPOINT ["/slipnet-relay"]
