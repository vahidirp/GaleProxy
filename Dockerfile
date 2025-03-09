# Dockerfile
FROM golang:1.23 as builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY proxy.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o galeproxy proxy.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates bash

WORKDIR /root/
COPY --from=builder /app/galeproxy .
COPY config.yaml .
COPY entrypoint.sh .

RUN chmod +x /root/entrypoint.sh
RUN mkdir -p /var/run /var/log

ENV CONFIG_PATH=/root/config.yaml
ENV GALEPROXY_PID_FILE=/var/run/galeproxy.pid
ENV GALEPROXY_LOG_FILE=/var/log/galeproxy.log
ENV GALEPROXY_BINARY=/root/galeproxy

EXPOSE 8080

ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["start"]