# Security Policy

## Supported versions

Fixes land on `dev` and go out in the next release; older versions are not patched.

| Version | Supported |
| --- | --- |
| Latest release (or `dev` until the first tag) | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/Im-Fran/hksv-rtsp-bridge/security/advisories/new)
(repository → **Security** → **Advisories** → **Report a vulnerability**).

Helpful things to include:

- What the issue is and what an attacker gets out of it.
- Steps to reproduce, or a proof of concept.
- The `hksv-rtsp-bridge` version or commit, how it is deployed (Docker, systemd, source) and the host OS.

Please never paste camera credentials, setup codes or the contents of `state_dir` in a report; redact them first.

What to expect:

- An acknowledgement within a few days.
- An assessment and a plan once the report is confirmed.
- A fix in the next release, with credit in the advisory unless you would rather not be named.

Please give a reasonable window for a fix before disclosing publicly.

## Scope

`hksv-rtsp-bridge` runs on a home network and speaks HomeKit (HAP) to a home hub. In scope:

- The HAP server: pairing (SRP), pair-verify, encrypted sessions and permission checks.
- The HomeKit Data Stream and the recording pipeline.
- Leaking camera credentials, SRTP keys or pairing material through logs, errors or files.
- Unsafe handling of the files in `state_dir`.

Out of scope: vulnerabilities in cameras, ffmpeg, Apple devices or other third-party software, and attacks that already require control of the host or `config.toml`.
