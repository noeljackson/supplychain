BIN      ?= supplychain
PREFIX   ?= $(HOME)/.local
BIN_DIR  ?= $(PREFIX)/bin
LDFLAGS  ?= -s -w
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build install uninstall test clean dist

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./

install: build
	mkdir -p $(BIN_DIR)
	install -m 0755 $(BIN) $(BIN_DIR)/$(BIN)
	@echo "installed -> $(BIN_DIR)/$(BIN)"

uninstall:
	rm -f $(BIN_DIR)/$(BIN)

test:
	go test ./...

clean:
	rm -f $(BIN)
	rm -rf dist

# Cross-compile release artifacts for darwin/linux × amd64/arm64.
dist: clean
	@mkdir -p dist
	@for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    out="dist/$(BIN)-$$os-$$arch"; \
	    echo "==> $$out"; \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	      go build -ldflags "$(LDFLAGS)" -o "$$out" ./; \
	  done; \
	done
