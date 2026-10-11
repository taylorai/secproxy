# Minimal image: the static binary and CA roots, nothing else.
#   docker build -t ghcr.io/taylorai/secproxy:dev .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /secproxy ./cmd/secproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /secproxy /usr/local/bin/secproxy
# ca.pem is written here at startup; /run is writable in distroless.
ENTRYPOINT ["/usr/local/bin/secproxy"]
CMD ["serve", "--config", "/etc/secproxy/secproxy.yaml"]
