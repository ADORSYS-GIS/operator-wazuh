# Build stage
FROM rust:1.92-slim-bookworm as builder

WORKDIR /usr/src/app
COPY . .

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Build the operator-cli which contains the run command
RUN cargo build --release -p operator-cli

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/wazuh-operator /usr/local/bin/wazuh-operator

ENTRYPOINT ["/usr/local/bin/wazuh-operator"]
