.PHONY: build run test proto clean docker-up docker-down seed lint

BINARY_NAME=authlayer-server
BUILD_DIR=bin

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/authlayer-server

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

test:
	go test ./... -v -race -cover

proto:
	buf generate

proto-lint:
	buf lint

clean:
	rm -rf $(BUILD_DIR)
	go clean

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down -v

seed:
	go run ./migrations/seed.go

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

fmt:
	gofmt -w .
