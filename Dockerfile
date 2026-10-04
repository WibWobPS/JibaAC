FROM rust:1.82-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p anticheat-cli -p anticheat-ffi

FROM debian:12-slim
RUN useradd -m anticheat
COPY --from=build /src/target/release/anticheat /usr/local/bin/anticheat
COPY --from=build /src/config/anticheat.example.json /etc/anticheat/config.json
USER anticheat
EXPOSE 12777
ENV ANTICHEAT_TOKEN=""
ENTRYPOINT ["/usr/local/bin/anticheat", "daemon", "--port", "12777"]
