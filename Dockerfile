FROM golang:alpine3.16 as builder

RUN apk update && \
    apk add --no-cache ca-certificates && \
    update-ca-certificates

RUN adduser -D -g '' appuser

WORKDIR /app

ENV CGO_ENABLED=0

COPY go.mod .
COPY go.sum .
RUN go mod download
RUN go mod verify

COPY . .
RUN go build -o /go/bin/eth2-monitor -ldflags '-extldflags "-static"'

# second step to build minimal image
FROM alpine:3.16

# add common trusted certificates from the build stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

USER appuser

COPY --from=builder /go/bin/eth2-monitor /go/bin/eth2-monitor

ENTRYPOINT ["/go/bin/eth2-monitor"]
