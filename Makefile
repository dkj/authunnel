DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build
build:
	@mkdir -p $(DIST)
	go build $(LDFLAGS) -o $(DIST)/authunnel-server ./server
	go build $(LDFLAGS) -o $(DIST)/authunnel-client ./client

.PHONY: release-build
release-build:
	@mkdir -p $(DIST)
	@for OS in darwin linux; do \
	  for ARCH in amd64 arm64; do \
	    echo "Building $$OS/$$ARCH..."; \
	    GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST)/authunnel-server-$$OS-$$ARCH ./server; \
	    GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST)/authunnel-client-$$OS-$$ARCH ./client; \
	  done; \
	done

.PHONY: clean
clean:
	rm -rf $(DIST)

.PHONY: test
test:
	go test ./...
