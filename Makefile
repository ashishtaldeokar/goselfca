.PHONY: all build clean linux windows darwin

# Binary name
BINARY_NAME=goselfca
# Entrypoint for the CLI
MAIN_PACKAGE=./cmd/goselfca

# Default target
all: build

# Standard build for the current system
build:
	go build -o $(BINARY_NAME) $(MAIN_PACKAGE)

# Cross-compilation targets
linux:
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	GOOS=linux GOARCH=arm64 go build -o bin/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)

windows:
	GOOS=windows GOARCH=amd64 go build -o bin/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	GOOS=windows GOARCH=arm64 go build -o bin/$(BINARY_NAME)-windows-arm64.exe $(MAIN_PACKAGE)

darwin:
	GOOS=darwin GOARCH=amd64 go build -o bin/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=arm64 go build -o bin/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

# Build for all major platforms
release: linux windows darwin
	@echo "All binaries generated in bin/ directory"

clean:
	go clean
	rm -rf bin/
	rm -f $(BINARY_NAME)
