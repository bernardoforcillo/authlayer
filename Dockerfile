FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /authlayer-server ./cmd/authlayer-server

FROM alpine:3.19

RUN apk --no-cache add ca-certificates
COPY --from=builder /authlayer-server /authlayer-server

EXPOSE 50051

ENTRYPOINT ["/authlayer-server"]
