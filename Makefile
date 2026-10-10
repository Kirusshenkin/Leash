# Сборка без npm и бандлеров. Тулчейн закреплён в rust-toolchain.toml.
# Без Homebrew (CI на Linux) передайте RUSTUP_BIN=$HOME/.cargo/bin.
RUSTUP_BIN ?= $(shell brew --prefix rustup 2>/dev/null)/bin
export PATH := $(RUSTUP_BIN):$(HOME)/.cargo/bin:$(PATH)
# make 3.81 на macOS ищет команды по старому PATH, поэтому пути явные.
CARGO        := $(RUSTUP_BIN)/cargo
WASM_BINDGEN := $(HOME)/.cargo/bin/wasm-bindgen

TARGET  := wasm32-unknown-unknown
WASM    := target/$(TARGET)/release/leash.wasm
PKG     := extension/pkg
VERSION := $(shell sed -n 's/.*"version": "\([0-9.]*\)".*/\1/p' extension/manifest.json)
# wasm-bindgen-cli обязан совпадать с версией крейта из Cargo.lock.
BINDGEN_VERSION := $(shell grep -A1 '^name = "wasm-bindgen"$$' Cargo.lock | sed -n 's/version = "\(.*\)"/\1/p')

.PHONY: all build host install test lint static deny audit check zip source hooks clean e2e

all: check

build:
	@$(WASM_BINDGEN) --version | grep -qx "wasm-bindgen $(BINDGEN_VERSION)" || \
		{ echo "нужен wasm-bindgen-cli $(BINDGEN_VERSION): cargo install wasm-bindgen-cli --version '=$(BINDGEN_VERSION)' --locked"; exit 1; }
	$(CARGO) build --locked --offline --release --target $(TARGET) -p leash
	$(WASM_BINDGEN) --target web --no-typescript --out-dir $(PKG) $(WASM)

host:
	$(CARGO) build --locked --offline --release -p leash-host

# Мост для текущего пользователя: бинарник в ~/.local/bin и манифест для Firefox.
install: host
	sh scripts/install.sh

test:
	$(CARGO) test --locked --offline

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --locked --offline --all-targets -- -D warnings
	$(CARGO) clippy --locked --offline --target $(TARGET) -p leash -- -D warnings

static: build
	sh scripts/check-static.sh

deny:
	$(CARGO) deny --locked check

audit:
	$(CARGO) audit --deny warnings

check: lint test static deny audit

zip: check
	mkdir -p dist
	rm -f dist/leash-$(VERSION).zip
	cd extension && zip -r -X ../dist/leash-$(VERSION).zip manifest.json ui.css background sidebar options confirm content icons pkg
	@for f in manifest.json background/background.js content/content.js sidebar/sidebar.html options/options.html confirm/confirm.html confirm/confirm.js pkg/leash_bg.wasm; do \
		unzip -l dist/leash-$(VERSION).zip | grep -q " $$f$$" || { echo "в архиве нет $$f"; exit 1; }; \
	done

# Исходники для ревьюеров AMO: только то, что в git (без e2e/private, target, dist).
source:
	mkdir -p dist
	git archive --format=zip -o dist/leash-src-$(VERSION).zip HEAD

hooks:
	git config core.hooksPath .githooks

clean:
	$(CARGO) clean
	rm -rf $(PKG) dist

e2e: build host
	cd e2e && go run .
