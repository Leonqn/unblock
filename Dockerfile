FROM rust as builder
WORKDIR /usr/src/unblock
COPY . .
RUN cargo install --path .

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/unblock /usr/local/bin/unblock
ENTRYPOINT ["unblock", "/etc/unblock/config.yml"]
