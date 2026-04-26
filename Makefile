DIST               := dist
VERSION            := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CYCLONEDX_VERSION  := v1.10.0
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
	@for ARCH in amd64 arm64; do \
	  echo "Building windows/$$ARCH..."; \
	  CGO_ENABLED=0 GOOS=windows GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST)/authunnel-client-windows-$$ARCH.exe ./client; \
	done

.PHONY: clean
clean:
	rm -rf $(DIST)

.PHONY: test
test:
	go test ./...

.PHONY: race
race:
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: staticcheck
staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

.PHONY: govulncheck
govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: gosec
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

.PHONY: sbom
sbom:
	@mkdir -p $(DIST)
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_VERSION)
	@_gobin=$$(go env GOBIN); CDXGOMOD=$${_gobin:-$$(go env GOPATH)/bin}/cyclonedx-gomod; \
	OUTDIR=$$(pwd)/$(DIST); \
	MODDIR=$$(dirname $$(git rev-parse --git-common-dir)); \
	for OS in darwin linux; do \
	  for ARCH in amd64 arm64; do \
	    (cd $$MODDIR && GOOS=$$OS GOARCH=$$ARCH $$CDXGOMOD app -licenses -json -output $$OUTDIR/sbom-server-$$OS-$$ARCH.cdx.json -main ./server); \
	    (cd $$MODDIR && GOOS=$$OS GOARCH=$$ARCH $$CDXGOMOD app -licenses -json -output $$OUTDIR/sbom-client-$$OS-$$ARCH.cdx.json -main ./client); \
	  done; \
	done; \
	for ARCH in amd64 arm64; do \
	  (cd $$MODDIR && GOOS=windows GOARCH=$$ARCH $$CDXGOMOD app -licenses -json -output $$OUTDIR/sbom-client-windows-$$ARCH.cdx.json -main ./client); \
	done

.PHONY: lint
lint: vet staticcheck govulncheck gosec
