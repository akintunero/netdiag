# Changelog

All notable changes are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No changes yet._

## [0.1.0] - 2025-06-04

### Initial release

**netdiag** is a new stdlib-only CLI for SRE and on-call network troubleshooting - one tool for incident triage instead of stitching together `dig`, `ping`, `curl`, and `traceroute` scripts.

**What ships in 0.1.0**

- Runbook workflow: `doctor` → `oncall` → `report`, with stable exit codes (`0` / `1` / `2`) for automation
- Layered probes: traceroute (ASN/BGP enrichment), ping, latency, DNS, TCP ports, HTTP/TLS, redirects, headers
- Presets for common roles: `web`, `api`, `vpn`, `oncall`
- VPN diagnostics: tunnel interfaces, routes, resolver drift, corp vs public reachability
- Throughput smoke test via `speed` (Cloudflare CDN)
- `--json` on every command; optional `~/.config/netdiag/config.toml`
- Shell completions (bash / zsh); `netdiag --info` for version and environment
- Documentation: [README](README.md), [CLI contract](docs/CLI_CONTRACT.md), [cookbook](docs/cookbook.md), CONTRIBUTING, SECURITY
- CI on Ubuntu and macOS (Python 3.11–3.13); 95+ tests with offline fixtures

Install from source or Git - see [README](README.md#install).

[Unreleased]: https://github.com/akintunero/netdiag/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/akintunero/netdiag/releases/tag/v0.1.0
