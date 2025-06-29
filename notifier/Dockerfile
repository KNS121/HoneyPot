FROM golang:1.24.4-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /notifier .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /notifier .

RUN chmod +x /app/notifier

CMD ["/app/notifier"]