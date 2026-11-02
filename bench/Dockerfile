# synthfeeds, for the capacity measurement (#263). Built on the host that runs
# it (apps), like the invite bot: `docker build -t synthfeeds:local bench/`.
# Same pinned bases as the app's Dockerfile.
FROM rust:1.99-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /src/target/release/synthfeeds /usr/local/bin/synthfeeds
USER 65534:65534
ENV SYNTH_BIND=0.0.0.0:8263
EXPOSE 8263
ENTRYPOINT ["/usr/local/bin/synthfeeds"]
