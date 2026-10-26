BINARY  := bin/releasedrift
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build install test vet fmt demo clean

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/releasedrift

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/releasedrift

test:
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w .

# Offline scan of the sample folder (no network). Exit 1 is expected.
demo: build
	./$(BINARY) --offline examples/sample || test $$? -eq 1

clean:
	rm -rf bin dist
