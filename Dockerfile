# Build the SecretScope CLI as a small container image. This is handy for
# running the scanner inside CI without installing a Rust toolchain there.
FROM rust:1.75 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p secretscope-cli

FROM debian:bookworm-slim
# git is used for history scanning.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/secretscope /usr/local/bin/secretscope
ENTRYPOINT ["secretscope"]
CMD ["--help"]
