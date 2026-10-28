# Run all CI checks in the same order as ci.yml.
# Usage: just        (runs `ci`)
#        just fmt    (fix formatting)
#        just test   (unit + ignored)

default: ci

# Run every CI check — mirrors what the pipeline does.
ci: fmt-check clippy build test doc typos

# Check formatting (read-only, same as CI).
fmt-check:
    cargo fmt --check

# Fix formatting in place.
fmt:
    cargo fmt

# Lint with all warnings promoted to errors.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Build the release binary.
build:
    cargo build --locked

# Run all unit tests.
test:
    cargo test --all-features --locked

# Run ignored (root-required) tests — needs sudo.
test-root:
    cargo test --all-features --locked -- --ignored

# Build docs with warnings as errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Spell-check the source tree.
typos:
    typos
