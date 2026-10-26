FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN /usr/local/go/bin/go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -trimpath -ldflags="-s -w" -o /out/slipnet-relay ./main.go

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/slipnet-relay /usr/local/bin/slipnet-relay
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/slipnet-relay"]
