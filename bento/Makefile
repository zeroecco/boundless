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
SYSTEMD_DIR = /etc/systemd/system
TEMPLATES_DIR = systemd
DEB_BUILD_DIR = $(BUILD_DIR)/deb

export NVCC_APPEND_FLAGS

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@command -v $(CARGO) >/dev/null 2>&1 || { echo "Error: cargo is not installed. Please install Rust toolchain."; exit 1; }
	@command -v $(FPM) >/dev/null 2>&1 || { echo "Error: fpm is not installed. Please install with: gem install fpm"; exit 1; }
	@command -v gcc >/dev/null 2>&1 || { echo "Error: gcc is not installed. Please install build-essential."; exit 1; }
	@command -v nvcc >/dev/null 2>&1 || { echo "Error: nvcc is not installed. Please install CUDA toolkit."; exit 1; }
	@ldconfig -p | grep -q libssl.so || { echo "Error: libssl-dev is not installed."; exit 1; }
	@echo "All dependencies found."

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
		--depends systemd \
		--depends libssl-dev \
		--depends nvidia-cuda-toolkit \
		--deb-systemd $(DEB_BUILD_DIR)/bento-agent.service \
		--deb-systemd $(DEB_BUILD_DIR)/bento-api.service \
		$(DEB_BUILD_DIR)/usr/local/bin/bento-agent=/usr/local/bin/bento-agent \
		$(DEB_BUILD_DIR)/usr/local/bin/bento-api=/usr/local/bin/bento-api

.PHONY: prepare-deb
prepare-deb: all
	mkdir -p $(DEB_BUILD_DIR)/usr/local/bin
	cp $(BUILD_DIR)/bento-agent $(DEB_BUILD_DIR)/usr/local/bin/
	cp $(BUILD_DIR)/bento-api $(DEB_BUILD_DIR)/usr/local/bin/

	# Create systemd service files if they don't exist
	if [ ! -d "$(TEMPLATES_DIR)" ]; then \
		mkdir -p $(TEMPLATES_DIR); \
		echo "[Unit]" > $(TEMPLATES_DIR)/bento-agent.service; \
		echo "Description=Bento Agent Service" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "After=network.target" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "[Service]" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "Type=simple" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "ExecStart=/usr/local/bin/bento-agent" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "Restart=on-failure" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "[Install]" >> $(TEMPLATES_DIR)/bento-agent.service; \
		echo "WantedBy=multi-user.target" >> $(TEMPLATES_DIR)/bento-agent.service; \
		\
		echo "[Unit]" > $(TEMPLATES_DIR)/bento-api.service; \
		echo "Description=Bento API Service" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "After=network.target" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "[Service]" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "Type=simple" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "ExecStart=/usr/local/bin/bento-api" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "Restart=on-failure" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "[Install]" >> $(TEMPLATES_DIR)/bento-api.service; \
		echo "WantedBy=multi-user.target" >> $(TEMPLATES_DIR)/bento-api.service; \
	fi

	# Copy systemd service files to the deb build directory
	cp $(TEMPLATES_DIR)/*.service $(DEB_BUILD_DIR)/ 2>/dev/null || true

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
