SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help install-node build-frontend build-macos build-zkvm-browser \
	test test-frontend test-backend test-extra test-swift test-attestation \
	test-prover test-zkvm test-grammar test-witness test-compact \
	test-compact-browser test-onchain typecheck

help:
	@printf '%s\n' \
		'Install' \
		'  make install-node       Install every pinned Node package independently' \
		'' \
		'Build' \
		'  make build-frontend     Build the web, writer, verifier, share, and deck assets' \
		'  make build-macos        Build the macOS app bundle' \
		'  make build-zkvm-browser Build the browser zkVM verifier' \
		'' \
		'Check' \
		'  make typecheck          Type-check the frontend deck' \
		'  make test               Run the maintained frontend, backend, and extra suites' \
		'  make test-frontend      Run the Node frontend suite' \
		'  make test-backend       Run attestation, prover, zkVM, and on-chain suites' \
		'  make test-extra         Run Swift and compact-native suites'

install-node:
	npm --prefix frontend ci
	npm --prefix backend/hosting ci
	npm --prefix backend/integrations/attestation ci
	npm --prefix extra/experiments/noir-compact/browser ci
	npm --prefix extra/experiments/noir-replay/runtime ci

build-frontend:
	npm --prefix frontend run build
	npm --prefix frontend run build:faces
	cd frontend && node ../extra/experiments/noir-compact/browser/build.mjs --web
	cd frontend && node write/build.mjs

build-macos:
	backend/scripts/build.sh

build-zkvm-browser:
	backend/zkvm/scripts/build-browser.sh

typecheck:
	npm --prefix frontend run typecheck

test: test-frontend test-backend test-extra

test-frontend:
	npm --prefix frontend test

test-backend: test-attestation test-prover test-zkvm test-grammar test-witness test-onchain

test-extra: test-swift test-compact test-compact-browser

test-swift:
	swift test --package-path extra --scratch-path .build --jobs 2

test-attestation:
	npm --prefix backend/integrations/attestation test

test-prover:
	cargo test --manifest-path backend/prover/Cargo.toml --locked

test-zkvm:
	cargo test --manifest-path backend/zkvm/Cargo.toml -p huma-replay-core -p huma-replay-verifier --locked

test-grammar:
	cargo test --manifest-path backend/integrations/grammar/Cargo.toml --locked

test-witness:
	cargo test --manifest-path backend/integrations/noir/witness/Cargo.toml --locked

test-compact:
	cargo test --manifest-path extra/experiments/noir-compact/native/Cargo.toml --all-targets --locked

test-compact-browser:
	npm --prefix extra/experiments/noir-compact/browser test

test-onchain:
	forge test --root backend/onchain
