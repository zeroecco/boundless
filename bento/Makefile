# Compiler settings
NVCC_APPEND_FLAGS = --gpu-architecture=compute_75 --gpu-code=compute_75,sm_75 --generate-code arch=compute_75,code=sm_75
CARGO = cargo
BUILD_DIR = build
TARGET_DIR = target/release

# Package settings
FPM = fpm
VERSION ?= 1.0.0
ITERATION ?= 1
PACKAGE_NAME = bento
INSTALL_DIR = /usr/local/bin
DEB_BUILD_DIR = $(BUILD_DIR)/deb

export NVCC_APPEND_FLAGS

# Setup build environment
.PHONY: setup
setup:
	@echo "Installing build dependencies..."
	@command -v apt-get >/dev/null 2>&1 || { echo "Error: This setup script requires apt-get (Debian/Ubuntu)"; exit 1; }
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		libssl-dev \
		postgresql \
		postgresql-contrib \
		redis \
		ruby \
		ruby-dev
	@command -v cargo >/dev/null 2>&1 || { echo "Installing Rust toolchain..."; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; }
	@command -v fpm >/dev/null 2>&1 || { echo "Installing FPM..."; sudo gem install fpm; }
	@echo "Starting required services..."
	sudo systemctl start postgresql
	sudo systemctl start redis-server

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@command -v $(CARGO) >/dev/null 2>&1 || { echo "Error: cargo is not installed. Please run: make setup"; exit 1; }
	@command -v $(FPM) >/dev/null 2>&1 || { echo "Error: fpm is not installed. Please run: make setup"; exit 1; }
	@command -v gcc >/dev/null 2>&1 || { echo "Error: gcc is not installed. Please run: make setup"; exit 1; }
	@command -v nvcc >/dev/null 2>&1 || { echo "Error: nvcc is not installed. Please install CUDA toolkit."; exit 1; }
	@ldconfig -p | grep -q libssl.so || { echo "Error: libssl-dev is not installed. Please run: make setup"; exit 1; }
	@command -v psql >/dev/null 2>&1 || { echo "Error: PostgreSQL is not installed. Please run: make setup"; exit 1; }
	@command -v redis-cli >/dev/null 2>&1 || { echo "Error: Redis is not installed. Please run: make setup"; exit 1; }
	@command -v mc >/dev/null 2>&1 || { echo "Error: MinIO client is not installed. Please run: make setup"; exit 1; }
	@echo "Checking service configurations..."
	@pg_isready >/dev/null 2>&1 || { echo "Error: PostgreSQL is not running. Please run: make setup"; exit 1; }
	@redis-cli ping >/dev/null 2>&1 || { echo "Error: Redis is not running. Please run: make setup"; exit 1; }
	@mc alias ls myminio >/dev/null 2>&1 || { echo "Error: MinIO is not configured. Please run: make setup"; exit 1; }
	@echo "All dependencies found and services configured."

# Default target
.PHONY: all
all: check-deps $(BUILD_DIR)/bento-agent $(BUILD_DIR)/bento-api

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/bento-agent: | $(BUILD_DIR)
	$(CARGO) build --release -p workflow --bin agent
	cp $(TARGET_DIR)/agent $@

$(BUILD_DIR)/bento-api: | $(BUILD_DIR)
	$(CARGO) build --release -p api --bin rest_api
	cp $(TARGET_DIR)/rest_api $@

.PHONY: agent
agent: check-deps $(BUILD_DIR)/bento-agent

.PHONY: api
api: check-deps $(BUILD_DIR)/bento-api

.PHONY: deb
deb: check-deps all prepare-deb
	$(FPM) -s dir -t deb \
		-n $(PACKAGE_NAME) \
		-v $(VERSION) \
		--iteration $(ITERATION) \
		--description "Bento Cluster Services" \
		--depends libssl-dev \
		--depends nvidia-cuda-toolkit \
		--depends postgresql \
		--depends redis \
		--depends minio \
		$(DEB_BUILD_DIR)/usr/local/bin/bento-agent=/usr/local/bin/bento-agent \
		$(DEB_BUILD_DIR)/usr/local/bin/bento-api=/usr/local/bin/bento-api

.PHONY: prepare-deb
prepare-deb: all
	mkdir -p $(DEB_BUILD_DIR)/usr/local/bin
	cp $(BUILD_DIR)/bento-agent $(DEB_BUILD_DIR)/usr/local/bin/
	cp $(BUILD_DIR)/bento-api $(DEB_BUILD_DIR)/usr/local/bin/

.PHONY: clean clean-deb
clean:
	rm -rf $(BUILD_DIR)
	$(CARGO) clean

clean-deb:
	rm -rf $(DEB_BUILD_DIR)
	rm -f *.deb

# Clean and rebuild everything
.PHONY: rebuild
rebuild: clean all

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  setup    - Install all required dependencies and configure services"
	@echo "  all      - Build both Agent and API (default)"
	@echo "  agent    - Build just the Agent"
	@echo "  api      - Build just the API"
	@echo "  clean    - Remove built binaries"
	@echo "  rebuild  - Clean and rebuild everything"
	@echo "  deb      - Create Debian package"
	@echo "  clean-deb- Clean Debian package files"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION  - Package version (default: $(VERSION))"
	@echo "  ITERATION- Package iteration (default: $(ITERATION))"
	@echo ""
	@echo "Required dependencies:"
	@echo "  - Rust toolchain (cargo)"
	@echo "  - Ruby's fpm (gem install fpm)"
	@echo "  - Build essentials (gcc)"
	@echo "  - libssl-dev"
	@echo "  - NVIDIA CUDA toolkit"
	@echo "  - PostgreSQL (postgresql and postgresql-contrib)"
	@echo "  - Redis (redis-server)"
	@echo "  - MinIO (minio-client)"
	@echo ""
	@echo "Quick start:"
	@echo "  1. Run 'make setup' to install dependencies and configure services"
	@echo "  2. Run 'make' to build the project"
	@echo "  3. Run 'make deb' to create a Debian package"
