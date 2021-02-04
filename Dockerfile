FROM rust as planner
WORKDIR /unblock
RUN cargo install cargo-chef 
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM rust as cacher
WORKDIR /unblock
RUN cargo install cargo-chef
COPY --from=planner /unblock/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust as builder
WORKDIR /unblock
COPY . .
COPY --from=cacher /unblock/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
RUN cargo build --release --bin unblock

FROM debian:buster-slim
RUN apt-get update && apt-get install -y libssl1.1 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /unblock
COPY --from=builder /unblock/target/release/unblock /usr/local/bin
ENTRYPOINT ["/usr/local/bin/unblock", "/etc/unblock/config.yml"]