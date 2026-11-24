<div align="center">

# 📹 local-dvr

**A lightweight Rust bridge that publishes RTSP cameras to Apple HomeKit: live view, remote streaming, motion sensor and HomeKit Secure Video recordings in iCloud.**

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

</div>

---

## 📖 Overview

`local-dvr` is a small service written in Rust that runs in a homelab and makes cheap RTSP cameras show up in the Apple Home app as native HomeKit cameras. It was built for my own house: iCSee (Xiongmai) cameras on the LAN, a HomePod mini as the home hub, and no cloud service in between.

Each camera is published as its own HomeKit accessory with its own identity and pairing. The Home app can watch it live (at home and over cellular), take snapshots, show motion notifications and record clips with HomeKit Secure Video (HKSV), which the home hub analyzes and stores end-to-end encrypted in iCloud.

> **This project was built with [Claude Code](https://claude.com/claude-code).** The HomeKit protocol (HAP) layer, the HomeKit Data Stream, the media pipeline and the tests were written together with Claude Code, then validated against a real HomePod mini and iPhone. Treat it as hobby-grade software: it works on my setup, and it has not been audited.

## ✨ Features

- **Live view** — H.264 over the classic HomeKit camera service, with SRTP, audio and a prebuffered stream so the camera opens fast. Works on Wi-Fi and over cellular (remote access through the home hub).
- **Snapshots** — served through the HAP `/resource` endpoint.
- **Motion sensor** — optional; listens for the camera's own alarms over DVRIP and exposes them as a HomeKit motion sensor, with a configurable hold time.
- **HomeKit Secure Video** — H.264 + AAC fragmented MP4 sent over the HomeKit Data Stream. Transcoding only happens during events, from the main stream.
- **Always-open ingest** — one `main` and one `sub` RTSP connection per camera, with a GOP ring buffer used as prebuffer.
- **Single TOML file** — one config file describes the whole server and every camera.
- **No dependencies on other HomeKit stacks** — pairing (SRP-6a), pair-verify, encrypted HAP sessions and mDNS advertising are implemented in this repo.
- **Log redaction** — camera credentials in URLs are masked in logs.

Disabled by default: H.265 and the HSV3/WebRTC services (`hsv3 = false`). Apple published them with iOS 27 and they are left behind a flag until they stabilize.

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (edition 2024) |
| Async runtime | tokio |
| RTSP ingest | retina |
| Discovery | mdns-sd (`_hap._tcp`) |
| Transcoding | ffmpeg subprocesses (x264, libopus, AAC) |
| Motion events | DVRIP (Xiongmai / iCSee) |
| Packaging | Docker, systemd |

## 📋 Requirements

- **Home hub**: a HomePod or Apple TV running iOS/tvOS 27. Tested with a HomePod mini and an iPhone.
- **Network**: the host running `local-dvr` must be on the **same layer-2 network** as the hub, because HomeKit discovers accessories through mDNS/Bonjour. A different VLAN or a guest Wi-Fi will not work.
- **ffmpeg** at runtime, built with `libx264`, `libopus` and `aac`. The Docker image already includes it.
- **Cameras**: at least one with a main and a sub stream over RTSP.
- **To build**: Rust 1.85 or newer (edition 2024).

Target platform: `x86_64-unknown-linux-gnu`. Building and running the tests that do not need ffmpeg or cameras also works on macOS.

## 🚀 Getting Started

### 1. Clone and configure

```bash
git clone https://github.com/Im-Fran/hksv-rtsp-bridge.git
cd hksv-rtsp-bridge
cp config.example.toml config.toml   # git-ignored; never commit real credentials
```

Edit `config.toml` with your cameras, then run it.

### 2. Run with Docker (recommended)

```bash
mkdir -m 700 state                 # ./state is mounted as /var/lib/local-dvr
docker compose up -d --build
docker compose logs -f local-dvr
```

`compose.yaml` uses `network_mode: host` (required for mDNS) and mounts `./config.toml` (read-only), `./state` and `/dev/dri`. Remove the `/dev/dri` block if you use `hwaccel = "none"` or the host has no Intel GPU.

Prebuilt images are published to GitHub Container Registry on every release tag (`linux/amd64`):

```bash
docker pull ghcr.io/im-fran/hksv-rtsp-bridge:latest
```

To use it, replace `build: .` with `image: ghcr.io/im-fran/hksv-rtsp-bridge:<version>` in `compose.yaml`.

### 3. Or build and run from source

```bash
cargo build --release
RUST_LOG=info ./target/release/local-dvr --config config.toml
```

The default config path is `/etc/local-dvr/config.toml`.

### 4. Or install as a systemd service

`deploy/local-dvr.service` runs the binary as a dedicated system user, with `StateDirectory=local-dvr` and basic hardening.

```bash
sudo install -m 0755 target/release/local-dvr /usr/local/bin/local-dvr
sudo useradd --system --no-create-home --shell /usr/sbin/nologin local-dvr
sudo install -d -m 0750 -o root -g local-dvr /etc/local-dvr
sudo install -m 0640 -o root -g local-dvr config.toml /etc/local-dvr/config.toml
sudo install -m 0644 deploy/local-dvr.service /etc/systemd/system/local-dvr.service
sudo systemctl daemon-reload
sudo systemctl enable --now local-dvr
```

With `hwaccel = "vaapi"`, also add the user to the `render` and `video` groups.

## ⚙️ Configuration

Example (`config.example.toml` has more comments):

```toml
[server]
setup_code = "031-45-154"          # HomeKit pairing code, format DDD-DD-DDD
state_dir = "/var/lib/local-dvr"   # keys and pairings; permissions 0700
bind = "::"                        # dual-stack; "0.0.0.0" = IPv4 only
base_port = 51830
hwaccel = "none"                   # "none" | "vaapi"
prebuffer_secs = 8
motion_hold_secs = 10
# max_resolution = "360p"          # advertise only 640x360 (no 2K transcoding)

[[camera]]
name = "Exterior"
main = "rtsp://192.168.1.10:554/user=U&password=P&channel=1&stream=0.sdp?real_stream"
sub = "rtsp://192.168.1.10:554/user=U&password=P&channel=1&stream=1.sdp?real_stream"
motion = "dvrip://U:P@192.168.1.10:34567"   # optional
# snapshot = "..."                           # optional snapshot URL
```

| Section | Key | Default | Notes |
|---|---|---|---|
| `server` | `setup_code` | required | `DDD-DD-DDD`. Codes HAP does not allow (`111-11-111`, `12345678`, ...) are rejected. |
| `server` | `state_dir` | required | Created with 0700; state files with 0600. One camera = one `<slug>.json`. |
| `server` | `bind` | `::` | Listen address of the HAP servers. |
| `server` | `base_port` | `51830` | Camera `i` (from 0) listens on `base_port + i`. |
| `server` | `hwaccel` | `none` | `vaapi` uses `/dev/dri/renderD128` (`h264_vaapi`). |
| `server` | `prebuffer_secs` | `8` | Buffer kept before an event. |
| `server` | `motion_hold_secs` | `10` | How long `MotionDetected` stays `true` after the last alarm. |
| `server` | `max_resolution` | `"720p"` | `"360p"` or `"720p"`. |
| `server` | `hsv3` | `false` | Publishes the HSV3/H.265 services. Leave `false` unless you want to experiment. |
| `server` | `legacy` | `"same"` | Only with `hsv3 = true`: `same`, `separate` or `off`. |
| `camera` | `name` | required | Unique in the file; the name HomeKit shows. |
| `camera` | `main`, `sub` | required | RTSP URLs. `sub` feeds the live view and snapshots; `main` is used for recordings. |
| `camera` | `motion` | none | `dvrip://U:P@host:34567`. Without it there is no motion sensor. |
| `camera` | `snapshot` | none | Optional snapshot URL. |

Logs mask `user:pass@` and `user=`/`password=` in camera URLs. Still, review logs before sharing them.

## 🔗 Pairing

1. Start `local-dvr`. Each camera advertises an `_hap._tcp` accessory with its name and port (`base_port + i`).
2. In the Home app, tap **Add Accessory** and enter the `setup_code`. Do it once per camera: each one is a separate accessory.
3. Live view and HomeKit Secure Video recording options are then configured from the Home app, on the camera.

To re-pair a camera, stop the service, delete that camera's `<state_dir>/<slug>.json` (the slug is the lowercase name with spaces and underscores turned into `-`), start again, and remove the old accessory from the Home app. Deleting the whole `state_dir` loses every pairing.

## 🧪 Testing

```bash
cargo test            # unit tests; the ones that need ffmpeg or cameras are #[ignore]
cargo clippy
cargo fmt
```

Run the ignored tests with `cargo test -- --ignored` on a host with ffmpeg and, for some of them, a real camera.

## 🩺 Troubleshooting

**The camera does not show up in Home, or stays on "Searching".**
- The host and the hub must share the same L2 network. With Docker, check that the container uses `network_mode: host`.
- Allow mDNS (UDP 5353, multicast) and TCP ports `base_port` to `base_port + N - 1` in the host firewall.
- Unpaired accessories advertise `sf=1` in the mDNS TXT record. If it stays `1` after pairing, the state file was not saved: check the permissions of `state_dir` (0700, owned by the process user).

**Live view does not load or stutters.**
- Try `max_resolution = "360p"`: it comes from the sub stream, with no 2K transcoding.
- With `hwaccel = "none"`, 1280x720 is upscaled from the 640x360 sub stream because decoding 2K on the CPU is expensive. With `hwaccel = "vaapi"` it comes from main.
- Check that `sub` answers: `ffprobe -rtsp_transport tcp "<sub url>"`.

**VAAPI does not work.**
- Check that `/dev/dri/renderD128` exists on the host and in the container.
- Inside the container: `docker compose run --rm --entrypoint vainfo local-dvr`. It should list H.264 profiles with `VAEntrypointEncSlice`. On Sandy Bridge the driver is `i965-va-driver`.
- If there is no driver or `vainfo` fails, use `hwaccel = "none"`.

**"ffmpeg: not found" or missing encoders.**
- Outside Docker, install an ffmpeg with `libx264`, `libopus` and `aac`. Verify with `ffmpeg -encoders | grep -E "libx264|libopus|aac"`.

**HomeKit Secure Video recordings do not appear.**
- Recording transcodes the main stream during an event, which needs CPU; run with `RUST_LOG=debug` to follow each event.
- Without `motion` there are no events, so there are no motion recordings.
- Recordings need an iCloud+ plan and a home hub; clips can take a few minutes to show up in the Home app.

## ⚠️ Known limitations

- Live audio can sound slightly choppy on some connections.
- 720p live view did not play on a direct iPhone connection during testing; `max_resolution = "360p"` is the workaround and the one that has been verified.
- H.265, HSV3 and WebRTC are disabled by default.
- Tested only with iCSee cameras, a HomePod mini and an iPhone.

## 🤝 Contributing

Issues and pull requests are welcome. Fork the repository, create a branch, make sure `cargo test`, `cargo clippy` and `cargo fmt` pass, and open a pull request. Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

## 📄 License

Licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE).
