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

macos:
	@uname -s | grep -q Darwin || (echo "Build the macOS dylib on a Mac or in GitHub Actions macos-latest. This host has no Apple SDK." && exit 1)
	$(CARGO) build --release -p macos-proxy
	@if [ "$$(uname -m)" = "arm64" ]; then dest=bin/macos-arm64; else dest=bin/macos-x64; fi; \
	  mkdir -p $$dest && cp target/release/libantigravity_proxy.dylib $$dest/ && \
	  echo "Built $$dest/libantigravity_proxy.dylib"

windows:
	$(CARGO) build --release --target x86_64-pc-windows-gnu -p windows-proxy -p windows-injector
	@mkdir -p bin/windows-x64
	@cp target/x86_64-pc-windows-gnu/release/version.dll bin/windows-x64/
	@cp target/x86_64-pc-windows-gnu/release/antigravity-proxy.exe bin/windows-x64/
	@echo "Built bin/windows-x64/version.dll and antigravity-proxy.exe"

clean:
	$(CARGO) clean
	rm -rf bin/x64/*.so bin/arm64/*.so bin/windows-x64/*.dll bin/windows-x64/*.exe

.PHONY: all x64 arm64 windows macos clean
