# Matchlock Makefile
# This Makefile delegates to mise for task execution.
# Install mise: https://mise.jdx.dev/getting-started.html
# Then run: mise install

# Configuration for macOS targets
OUTPUT_DIR ?= $(HOME)/.cache/matchlock
KERNEL_VERSION ?= 6.1.137
GO ?= go
MATCHLOCK_BIN = bin/matchlock
ENTITLEMENTS_FILE = matchlock.entitlements

.PHONY: help
help:
	@echo "Matchlock uses mise for task management."
	@echo ""
	@echo "Setup:"
	@echo "  1. Install mise: https://mise.jdx.dev/getting-started.html"
	@echo "  2. Run: mise install"
	@echo "  3. Run: mise tasks"
	@echo ""
	@echo "Common tasks:"
	@echo "  mise run build           Build the matchlock CLI"
	@echo "  mise run test            Run all tests"
	@echo "  mise run lint            Run golangci-lint"
	@echo "  mise run kernel:build    Build kernels for all architectures"
	@echo "  mise run kernel:publish  Publish kernels to GHCR"
	@echo ""
	@echo "macOS targets (Apple Silicon):"
	@echo "  make build-darwin         Build and codesign CLI for macOS"
	@echo "  make guest-binaries-darwin Build ARM64 guest binaries"
	@echo "  make setup-darwin         Full macOS setup"
	@echo ""
	@echo "For backwards compatibility, make targets delegate to mise:"
	@mise tasks 2>/dev/null || echo "mise not installed - see https://mise.jdx.dev"

# =============================================================================
# Delegate common targets to mise
# =============================================================================

.PHONY: build build-all clean test lint fmt vet tidy check
.PHONY: kernel kernel-x86_64 kernel-arm64 kernel-publish kernel-clean
.PHONY: install setup images

build:
	@mise run build

build-all:
	@mise run build:all

clean:
	@mise run clean

test:
	@mise run test

lint:
	@mise run lint

fmt:
	@mise run fmt

vet:
	@mise run vet

tidy:
	@mise run tidy

check:
	@mise run check

kernel:
	@mise run kernel:build

kernel-x86_64:
	@mise run kernel:x86_64

kernel-arm64:
	@mise run kernel:arm64

kernel-publish:
	@mise run kernel:publish

kernel-clean:
	@mise run kernel:clean

install:
	@mise run install

setup:
	@mise run setup

images:
	@mise run images

# =============================================================================
# macOS build targets (Apple Silicon)
# =============================================================================

$(ENTITLEMENTS_FILE):
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $@
	@echo '<plist version="1.0">' >> $@
	@echo '<dict>' >> $@
	@echo '    <key>com.apple.security.virtualization</key>' >> $@
	@echo '    <true/>' >> $@
	@echo '</dict>' >> $@
	@echo '</plist>' >> $@

.PHONY: build-darwin
build-darwin: $(ENTITLEMENTS_FILE)
	@mkdir -p bin
	$(GO) build -o $(MATCHLOCK_BIN) ./cmd/matchlock
	codesign --entitlements $(ENTITLEMENTS_FILE) -f -s - $(MATCHLOCK_BIN)
	@echo "Built and signed $(MATCHLOCK_BIN) for macOS"

.PHONY: guest-binaries-darwin
guest-binaries-darwin:
	@mkdir -p bin $(OUTPUT_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(OUTPUT_DIR)/guest-agent ./cmd/guest-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(OUTPUT_DIR)/guest-fused ./cmd/guest-fused
	@echo "Built ARM64 guest binaries in $(OUTPUT_DIR)"

.PHONY: setup-darwin
setup-darwin: build-darwin guest-binaries-darwin
	@echo ""
	@echo "============================================"
	@echo "Matchlock macOS setup complete!"
	@echo "============================================"
	@echo ""
	@echo "Guest binaries installed to $(OUTPUT_DIR)"
	@echo ""
	@echo "Test with container images:"
	@echo "  ./bin/matchlock run --image alpine:latest echo 'Hello from macOS VM!'"

.PHONY: quick-test-darwin
quick-test-darwin: build-darwin guest-binaries-darwin
	@echo "Running quick macOS test..."
	./$(MATCHLOCK_BIN) run --image alpine:latest echo "Matchlock works on macOS!"
