BIN      ?= supplychain
PREFIX   ?= $(HOME)/.local
BIN_DIR  ?= $(PREFIX)/bin
GOFLAGS  ?= -trimpath
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  ?= -s -w -X 'github.com/noeljackson/supplychain/cmd.Version=$(VERSION)'

.PHONY: help all build install install-full uninstall test vet lint dist clean

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: build ## default — build the binary in the repo

build: ## compile ./supplychain
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) ./

install: build ## install supplychain to $(BIN_DIR)
	@mkdir -p $(BIN_DIR)
	install -m 0755 $(BIN) $(BIN_DIR)/$(BIN)
	@echo "installed -> $(BIN_DIR)/$(BIN)"
	@case ":$$PATH:" in \
	  *":$(BIN_DIR):"*) ;; \
	  *) echo "note: $(BIN_DIR) is not in PATH. Add: export PATH=\"$(BIN_DIR):\$$PATH\"" ;; \
	esac
	@echo "next: run '$(BIN) update' to also install osv-scanner, then '$(BIN) doctor'"

install-full: install ## install supplychain AND bootstrap osv-scanner
	$(BIN_DIR)/$(BIN) update

uninstall: ## remove the installed binary (does NOT touch DataDir)
	rm -f $(BIN_DIR)/$(BIN)
	@echo "uninstalled $(BIN_DIR)/$(BIN)"
	@echo "(state under \$$XDG_DATA_HOME/supplychain is preserved; rm -rf it if you also want a clean slate)"

vet: ## run `go vet`
	go vet ./...

test: ## run unit tests under -race
	go test ./... -race -count=1

lint: vet test ## vet + test

clean: ## delete build artifacts
	rm -f $(BIN)
	rm -rf dist

# Cross-compile release artifacts for darwin/linux x amd64/arm64.
dist: clean ## build release binaries for linux/darwin x amd64/arm64
	@mkdir -p dist
	@for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    out="dist/$(BIN)-$$os-$$arch"; \
	    echo "==> $$out"; \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	      go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o "$$out" ./; \
	  done; \
	done
