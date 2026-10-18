# synthfeeds, for the capacity measurement (#263). Built on the host that runs
# it (apps), like the invite bot: `docker build -t synthfeeds:local bench/`.
# Same pinned bases as the app's Dockerfile.
FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --from=build /src/target/release/synthfeeds /usr/local/bin/synthfeeds
USER 65534:65534
ENV SYNTH_BIND=0.0.0.0:8263
EXPOSE 8263
ENTRYPOINT ["/usr/local/bin/synthfeeds"]
