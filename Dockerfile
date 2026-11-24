# Build stage: cargo on rust:1-bookworm. Runtime: Debian slim with ffmpeg (x264, libopus, aac) and VAAPI.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
ARG TARGETARCH
# VAAPI drivers are Intel-only, so they exist for amd64 only: i965-va-driver covers Sandy Bridge (i3-2120),
# intel-media-va-driver covers Gen8+, and vainfo helps diagnose VAAPI. arm64 images run with hwaccel = "none".
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
 && if [ "$TARGETARCH" = "amd64" ]; then \
      apt-get install -y --no-install-recommends vainfo i965-va-driver intel-media-va-driver; \
    fi \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/local-dvr /usr/local/bin/local-dvr

ENTRYPOINT ["local-dvr"]
CMD ["--config", "/etc/local-dvr/config.toml"]
