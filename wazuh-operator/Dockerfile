FROM rust as base

WORKDIR /app

FROM base as builder

# Copy the Cargo.toml and Cargo.lock files to cache dependencies
COPY ./ ./

# Build the dependencies
RUN cargo build --release

FROM base

WORKDIR /app

COPY --from=builder /app/target/release/wazuh-operator /app/wazuh-operator

CMD ["/app/wazuh-operator"]