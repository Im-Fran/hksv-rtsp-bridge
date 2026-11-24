# Contributing to hksv-rtsp-bridge

Thanks for taking the time to help. This is a small Rust service, so the rules are few.

## Ground rules

- Be kind; see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit camera credentials, setup codes, SRTP keys, `config.toml` or anything from `state/`. Use placeholders such as `U` and `P` in examples.
- Keep the project small: no new dependency, abstraction or option unless it clearly pays for itself.
- Everything in the repository is written in English: code, comments, logs, docs and commit messages.

## Setup

Requirements: Rust 1.85 or newer (edition 2024) and, for the tests that touch media, ffmpeg with `libx264`, `libopus` and `aac`.

```bash
git clone https://github.com/Im-Fran/hksv-rtsp-bridge.git
cd hksv-rtsp-bridge
cargo build
cargo test
```

Tests marked `#[ignore]` need ffmpeg or a real camera; run them with `cargo test -- --ignored`.

## Structure

- `src/hap/`: HomeKit Accessory Protocol (pairing, encrypted HTTP, mDNS).
- `src/camera/`: camera services, RTP/SRTP sessions and HomeKit Secure Video recording.
- `src/hds/`: HomeKit Data Stream.
- `src/media/`: RTSP ingest, ring buffer, snapshots and ffmpeg subprocesses.
- `src/motion/`: DVRIP motion events.

## Branches and commits

- Branch from `dev` as `im-fran/<type>/<short-description>` (`feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `security`), or any clear `<type>/<description>` if you are an outside contributor.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org). Pull requests are merged with a merge commit, so every commit message matters, not only the PR title.
- Commits on `dev` must be signed.

## Opening a pull request

1. Make sure `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --locked` pass.
2. Open the PR against `dev` and fill in the template.
3. Resolve all review threads; CI must be green.
