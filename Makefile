.PHONY: build release run test lint fmt setup-rpc clean

APP_NAME := xmr-ancap-gateway

build:
	cargo build

release:
	cargo build --release

run:
	./start.sh

test:
	cargo test --all-targets

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

setup-rpc:
	./start.sh --setup-rpc

clean:
	cargo clean
