# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml ./backend/
COPY frontend/Cargo.toml ./frontend/
COPY unit_tests/Cargo.toml ./unit_tests/
COPY API_tests/Cargo.toml ./API_tests/

# Create stub lib/main files so cargo can resolve the workspace without full source
RUN mkdir -p backend/src frontend/src unit_tests/src API_tests/src \
    && echo 'fn main() {}' > backend/src/main.rs \
    && echo '' > backend/src/lib.rs \
    && echo 'fn main() {}' > frontend/src/main.rs \
    && echo '' > unit_tests/src/lib.rs \
    && echo '' > API_tests/src/lib.rs

# Pre-fetch dependencies
RUN cargo fetch

# Now copy real source
COPY backend/ ./backend/

# Build release binary
RUN cargo build --release -p backend

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/backend /app/backend
COPY backend/Rocket.toml /app/Rocket.toml

EXPOSE 8000

CMD ["./backend"]
