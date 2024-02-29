
# Makefile for building the cryptothingy Rust project

# Set the desired Rust flags
RUSTFLAGS := -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt -Z threads=12

# Target for building the release version
release:
	cargo +nightly build --release

# Target for running the project
run: release
	./target/release/cryptothingy

# Target for cleaning build artifacts
clean:
	cargo clean

# Default target when just running `make` without any specific target
.PHONY: default
default: release
