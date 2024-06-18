FROM rust:1.69 AS builder

RUN set -x \
    && DEBIAN_FRONTEND=noninteractive apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y \
        --no-install-recommends musl-tools

WORKDIR /workspace

ADD .cargo/ .cargo/
ADD Cargo.toml Cargo.toml
ADD Cargo.lock Cargo.lock

RUN cargo fetch

ADD src/ src/

RUN set -x \
    && cargo build --release \
    && strip target/release/policy-server \
    && mv target/release/policy-server policy-server

# ---------- 8< ----------

FROM debian:bookworm-slim

RUN set -x \
    && echo "policy-server:x:65533:policy-server" >> /etc/group \
    && echo "policy-server:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd

COPY --from=builder /workspace/policy-server /policy-server

USER 65533:65533
EXPOSE 3000
ENTRYPOINT ["/policy-server"]
