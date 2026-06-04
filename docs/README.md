# Documentation

Guides and reference for **netdiag** - a stdlib-only CLI for SRE and on-call network troubleshooting.

| Document | Purpose |
|----------|---------|
| [Cookbook](cookbook.md) | On-call recipes: DNS, API outage, VPN, TLS, automation |
| [CLI contract](CLI_CONTRACT.md) | Exit codes `0` / `1` / `2`, stable flags, JSON conventions |
| [Config example](config.example.toml) | Optional `~/.config/netdiag/config.toml` |

## Runbook essentials

```bash
netdiag doctor
netdiag oncall <HOST> --json
netdiag report <HOST> -o incident.md
```

Use a real hostname or IP (`1.1.1.1`, your service FQDN). Names like `api.example.com` are reserved ([RFC 6761](https://datatracker.ietf.org/doc/html/rfc6761)) and will not resolve on the public internet.

## Project docs (repo root)

| Document | Purpose |
|----------|---------|
| [README](../README.md) | Install, command overview, quick start |
| [CONTRIBUTING](../CONTRIBUTING.md) | Development setup and PR expectations |
| [SECURITY](../SECURITY.md) | Vulnerability reporting |
| [ROADMAP](../ROADMAP.md) | Planned work and non-goals |
| [CHANGELOG](../CHANGELOG.md) | Release history |
