# synthfeeds, for the capacity measurement (#263). Built on the host that runs
# it (apps), like the invite bot: `docker build -t synthfeeds:local bench/`.
# Same pinned bases as the app's Dockerfile.
FROM rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
COPY --from=build /src/target/release/synthfeeds /usr/local/bin/synthfeeds
USER 65534:65534
ENV SYNTH_BIND=0.0.0.0:8263
EXPOSE 8263
ENTRYPOINT ["/usr/local/bin/synthfeeds"]
