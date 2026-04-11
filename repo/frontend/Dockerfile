# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.87-bookworm AS builder

# Install wasm target
RUN rustup target add wasm32-unknown-unknown

# Install trunk from pre-built binary (avoids OOM from compiling trunk from source)
RUN curl -L https://github.com/trunk-rs/trunk/releases/download/v0.21.7/trunk-x86_64-unknown-linux-gnu.tar.gz \
    | tar -xz -C /usr/local/bin

WORKDIR /build

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml ./backend/
COPY frontend/Cargo.toml ./frontend/
COPY unit_tests/Cargo.toml ./unit_tests/
COPY API_tests/Cargo.toml ./API_tests/
COPY frontend_tests/Cargo.toml ./frontend_tests/

# Stub files for dependency pre-fetch
RUN mkdir -p backend/src frontend/src unit_tests/src API_tests/src frontend_tests/src \
    && echo 'fn main() {}' > backend/src/main.rs \
    && echo '' > backend/src/lib.rs \
    && echo 'fn main() {}' > frontend/src/main.rs \
    && echo '' > unit_tests/src/lib.rs \
    && echo '' > API_tests/src/lib.rs \
    && echo '' > frontend_tests/src/lib.rs

RUN cargo fetch

# Copy real frontend source
COPY frontend/ ./frontend/

# Build WASM bundle
WORKDIR /build/frontend
RUN trunk build --release

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM nginx:alpine

COPY --from=builder /build/frontend/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
