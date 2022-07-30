FROM rust as builder
WORKDIR /usr/src/unblock
COPY . .
RUN cargo install --path .

FROM debian:buster-slim
RUN apt-get update && apt-get install -y libssl1.1 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/unblock /usr/local/bin/unblock
ENTRYPOINT ["unblock", "/etc/unblock/config.yml"]
