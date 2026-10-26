FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/slipnet-relay ./main.go

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/slipnet-relay /usr/local/bin/slipnet-relay
ENV PORT=8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/slipnet-relay"]
