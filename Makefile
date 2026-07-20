.PHONY: check test fmt lint doctor image boot-test repro-check

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

image:
	cargo xtask repro-check --scenario normal

boot-test:
	cargo xtask boot-test

repro-check:
	cargo xtask repro-check
