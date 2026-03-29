FROM rust as builder
WORKDIR /usr/src/reroute
COPY . .
RUN cargo install --path .

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/reroute /usr/local/bin/reroute
ENTRYPOINT ["reroute", "/etc/reroute/config.yml"]
