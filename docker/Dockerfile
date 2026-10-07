FROM rust:bookworm AS builder

# The operator image runs native ETH API, indexer and challenge services.
# The browser SDK and host application build separately.
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY protocol ./protocol

RUN cargo build --locked --release -p zkapi-cli -p zkapi-indexerd -p zkapi-serverd --bins

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zkapi

WORKDIR /srv/zkapi

COPY --from=builder /app/target/release/zkapi /usr/local/bin/zkapi
COPY --from=builder /app/target/release/zkapi-indexerd /usr/local/bin/zkapi-indexerd
COPY --from=builder /app/target/release/zkapi-challenged /usr/local/bin/zkapi-challenged
# The ceremony setup of circuit zkapi-v2-concession-v1. A release build loads
# only its pinned mpc-1 keys, which G-SETUP commits: until then the daemons
# refuse to start.
COPY --from=builder /app/protocol/setup/v2-concession /srv/zkapi/protocol/setup/v2-concession

COPY --chmod=755 docker/aws/run-daemon.sh /usr/local/bin/zkapi-run

USER zkapi

ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["zkapi-run"]
CMD ["server"]
