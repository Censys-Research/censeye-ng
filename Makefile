BINARY_NAME := censeye-ng

.PHONY: all build clean fmt vet test

all: build

build:
	go build -o $(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

