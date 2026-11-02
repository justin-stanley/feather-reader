# synthfeeds, for the capacity measurement (#263). Built on the host that runs
# it (apps), like the invite bot: `docker build -t synthfeeds:local bench/`.
# Same pinned bases as the app's Dockerfile.
FROM rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
COPY --from=build /src/target/release/synthfeeds /usr/local/bin/synthfeeds
USER 65534:65534
ENV SYNTH_BIND=0.0.0.0:8263
EXPOSE 8263
ENTRYPOINT ["/usr/local/bin/synthfeeds"]
