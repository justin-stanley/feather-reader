# synthfeeds, for the capacity measurement (#263). Built on the host that runs
# it (apps), like the invite bot: `docker build -t synthfeeds:local bench/`.
# Same pinned bases as the app's Dockerfile.
FROM rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS build
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
