DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build
# CGO_ENABLED=0 is required — see release-build comment below.
build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/authunnel-server ./server
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/authunnel-client ./client

.PHONY: release-build
# CGO_ENABLED=0 is required for syscall.AllThreadsSyscall6 to work correctly.
# When cgo is enabled, AllThreadsSyscall6 returns ENOTSUP because it cannot
# safely stop cgo-managed threads. This would silently prevent PR_SET_NO_NEW_PRIVS
# and capability-dropping from being applied across all OS threads at startup.
release-build:
	@mkdir -p $(DIST)
	@for OS in darwin linux; do \
	  for ARCH in amd64 arm64; do \
	    echo "Building $$OS/$$ARCH..."; \
	    CGO_ENABLED=0 GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST)/authunnel-server-$$OS-$$ARCH ./server; \
	    CGO_ENABLED=0 GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST)/authunnel-client-$$OS-$$ARCH ./client; \
	  done; \
	done

.PHONY: clean
clean:
	rm -rf $(DIST)

.PHONY: test
test:
	go test ./...
