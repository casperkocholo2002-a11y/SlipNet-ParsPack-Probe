FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/slipnet-relay ./cmd/relay

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/slipnet-relay /usr/local/bin/slipnet-relay
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/slipnet-relay"]
