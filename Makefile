BIN     := mehfil-bridge
VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
OUTDIR  := bin

.PHONY: all clean darwin linux windows checksums

all: darwin linux windows

darwin:
	mkdir -p $(OUTDIR)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o $(OUTDIR)/$(BIN)-darwin-amd64   .
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(OUTDIR)/$(BIN)-darwin-arm64   .

linux:
	mkdir -p $(OUTDIR)
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(OUTDIR)/$(BIN)-linux-amd64    .
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o $(OUTDIR)/$(BIN)-linux-arm64    .

windows:
	mkdir -p $(OUTDIR)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(OUTDIR)/$(BIN)-windows-amd64.exe .

checksums:
	cd $(OUTDIR) && sha256sum * > SHA256SUMS

clean:
	rm -rf $(OUTDIR)

# Quick local run
run:
	go run .

# Install to /usr/local/bin (macOS/Linux)
install:
	go build $(LDFLAGS) -o /usr/local/bin/$(BIN) .
	@echo "Installed to /usr/local/bin/$(BIN)"
