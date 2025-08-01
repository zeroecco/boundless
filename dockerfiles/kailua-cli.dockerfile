# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.88.0
ARG KAILUA_VERSION=main
ARG SCCACHE_VERSION=0.8.2
ARG BUILD_TYPE=release

FROM rust:${RUST_VERSION}-bookworm AS builder

# Add labels for better maintainability
LABEL maintainer="Boundless Team"
LABEL version="1.0"

# Pass SCCACHE_VERSION to this stage
ARG SCCACHE_VERSION

# Install system dependencies
RUN apt-get -qq update && \
    apt-get install -y -q clang git curl wget && \
    wget https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux && \
    chmod +x solc-static-linux && \
    mv solc-static-linux /usr/local/bin/solc && \
    rm -rf /var/lib/apt/lists/*

# Install sccache for faster compilation
RUN cargo install sccache --version ${SCCACHE_VERSION}

# Configure sccache
ENV SCCACHE_DIR=/tmp/sccache
ENV SCCACHE_CACHE_SIZE=2G

# Install RISC Zero toolchain (skip if architecture not supported)
SHELL ["/bin/bash", "-c"]
ARG CACHE_DATE=2025-07-17  # update this date to force rebuild
# Github token can be provided as a secret with the name githubTokenSecret. Useful
# for shared build environments where Github rate limiting is an issue.
RUN --mount=type=secret,id=githubTokenSecret,target=/run/secrets/githubTokenSecret \
    if [ "$(uname -m)" = "x86_64" ]; then \
        if [ -f /run/secrets/githubTokenSecret ]; then \
            GITHUB_TOKEN=$(cat /run/secrets/githubTokenSecret) curl -L https://risczero.com/install | bash && \
            GITHUB_TOKEN=$(cat /run/secrets/githubTokenSecret) PATH="$PATH:/root/.risc0/bin" rzup install cargo-risczero 2.2.0; \
        else \
            curl -L https://risczero.com/install | bash && \
            PATH="$PATH:/root/.risc0/bin" rzup install cargo-risczero 2.2.0; \
        fi; \
    else \
        echo "Skipping RISC Zero installation on $(uname -m) architecture"; \
    fi

# Install cargo-chef for better dependency caching
RUN cargo install cargo-chef

FROM builder AS deps

# Clone the kailua repository
WORKDIR /src
RUN git clone https://github.com/risc0/kailua.git && \
    cd kailua && \
    git checkout ${KAILUA_VERSION}

# Fetch dependencies
RUN cargo fetch --manifest-path kailua/Cargo.toml

FROM deps AS planner

WORKDIR /src/kailua

# Prepare recipe for cargo-chef
RUN cargo chef prepare --recipe-path recipe.json

FROM deps AS rust-builder

WORKDIR /src/kailua

# Copy source code
COPY --from=deps /src/kailua/ ./

# Build kailua-cli
SHELL ["/bin/bash", "-c"]
RUN cargo install svm-rs && \
    svm install 0.8.24

# Create sccache directory and set permissions
RUN mkdir -p /tmp/sccache && chmod 777 /tmp/sccache

# Build with sccache enabled
RUN RUSTC_WRAPPER=sccache cargo build --release --bin kailua-cli

# Runtime stage
FROM rust:${RUST_VERSION}-bookworm AS runtime

# Pass SCCACHE_VERSION to runtime stage
ARG SCCACHE_VERSION

# Install runtime dependencies
RUN apt-get -qq update && \
    apt-get install -y -q ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/*

# Install sccache in runtime stage for consistency
RUN cargo install sccache --version ${SCCACHE_VERSION}

# Configure sccache for runtime
ENV SCCACHE_DIR=/tmp/sccache
ENV SCCACHE_CACHE_SIZE=2G

# Install RISC Zero toolchain in runtime stage
SHELL ["/bin/bash", "-c"]
RUN curl -L https://risczero.com/install | bash && \
    PATH="$PATH:/root/.risc0/bin" rzup install r0vm 2.3.1;

# Create proper directory structure and sccache directory
RUN mkdir -p /app /tmp/sccache
WORKDIR /app

# Create volume for sccache cache persistence
VOLUME ["/tmp/sccache"]

# Copy binary from builder stage
COPY --from=rust-builder /src/kailua/target/release/kailua-cli /app/kailua-cli

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/kailua-cli --help || exit 1

# Set environment variables for RISC Zero
ENV PATH="/root/.risc0/bin:$PATH"

# Set proper entrypoint
ENTRYPOINT ["/app/kailua-cli"]
