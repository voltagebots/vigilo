FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /vigilo ./cmd/vigilo/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /vigilo /usr/local/bin/vigilo

# Default config path — mount your own at /etc/vigilo/config.yaml
RUN mkdir -p /etc/vigilo /var/lib/vigilo

EXPOSE 7070

ENTRYPOINT ["/usr/local/bin/vigilo"]
CMD ["-config", "/etc/vigilo/config.yaml", "-db", "/var/lib/vigilo/events.db"]
