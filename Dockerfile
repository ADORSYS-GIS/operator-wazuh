# Build stage
FROM rust:1.92-slim-bookworm as builder

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY . .

# Build the operator-cli which contains the run command
RUN --mount=type=cache,target=/root/.cargo \
      cargo build --release -p operator-cli

# Runtime stage
FROM debian:bookworm-slim

LABEL maintainer="stephane-segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="Wazuh Operator"

COPY --from=builder /usr/src/app/target/release/wazuh-operator /usr/local/bin/wazuh-operator

ENTRYPOINT ["/usr/local/bin/wazuh-operator"]
