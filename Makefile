CARGO ?= cargo

all:
	$(CARGO) build --release
	@mkdir -p bin/$(shell uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/')
	@cp target/release/libantigravity_proxy.so bin/$(shell uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/')/
	@echo "Built libantigravity_proxy.so for $(shell uname -m)"

x64:
	$(CARGO) build --release --target x86_64-unknown-linux-gnu
	@mkdir -p bin/x64
	@cp target/x86_64-unknown-linux-gnu/release/libantigravity_proxy.so bin/x64/
	@echo "Built bin/x64/libantigravity_proxy.so"

arm64:
	$(CARGO) build --release --target aarch64-unknown-linux-gnu
	@mkdir -p bin/arm64
	@cp target/aarch64-unknown-linux-gnu/release/libantigravity_proxy.so bin/arm64/
	@echo "Built bin/arm64/libantigravity_proxy.so"

clean:
	$(CARGO) clean
	rm -rf bin/x64/*.so bin/arm64/*.so

.PHONY: all x64 arm64 clean
