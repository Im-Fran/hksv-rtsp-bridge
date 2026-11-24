## What this changes

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- The problem being solved. Link the issue: Closes #123 -->

## How

<!-- The approach, and anything a reviewer would otherwise have to reverse-engineer. -->

## Testing

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --locked` passes
- [ ] Tried it against a real hub/camera, if it touches pairing, streaming or recording

<!-- Say which hub, camera and iOS/tvOS version it was verified against. -->

## Checklist

- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org)
- [ ] No credentials, setup codes, SRTP keys or `state/` contents anywhere in the diff or logs
- [ ] No new dependencies unless clearly needed
- [ ] README or `config.example.toml` updated if behaviour or configuration changed
