# Dockerfile для Go-приложения
FROM golang:1.24.4-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./

RUN go mod download
RUN go get github.com/ClickHouse/clickhouse-go/v2

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o alertsystem .

FROM alpine:latest
WORKDIR /app


COPY --from=builder /app/alertsystem .

RUN chmod +x /app/alertsystem

CMD ["/app/alertsystem"]