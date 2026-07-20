.PHONY: check test fmt lint doctor

check:
	./scripts/check.sh

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

doctor:
	cargo run -p polyctl -- doctor
