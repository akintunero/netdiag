# Documentation

Guides and reference for **netdiag** - a stdlib-only CLI for SRE and on-call network troubleshooting.

Install: `python3 -m pip install netdiag-cli` ([PyPI](https://pypi.org/project/netdiag-cli/)) · command: **`netdiag`**

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

`doctor` checks required tools (`ping`) and lists recommended/optional binaries (`dig`, `traceroute`, `lsof`, `ss`, etc.). Exit **`2`** when a required tool is missing.

Use a real hostname or IP (`1.1.1.1`, your service FQDN). Names like `api.example.com` are reserved ([RFC 6761](https://datatracker.ietf.org/doc/html/rfc6761)) and will not resolve on the public internet.

## Command help

```bash
netdiag --help              # all subcommands and global flags
netdiag <command> --help    # flags for one command (e.g. oncall, trace, dns-compare)
netdiag --version           # installed version (e.g. 0.1.1)
netdiag --info              # version, platform, repo links
```

## Host diagnostics (local machine)

When investigating the laptop or server itself:

| Command | What it shows |
|---------|----------------|
| `netdiag connections` | Established TCP/UDP with **process name and PID** |
| `netdiag local-ports` | All listening TCP ports and owners |
| `netdiag listen PORT` | Processes bound to one port (`--json` supported) |
| `netdiag route` / `ifaces` | Routing table and interfaces |
| `netdiag dns-config` | Active resolver configuration |

Process names require **`lsof`** (macOS default) or **`ss -p`** (Linux). Without them, connections still list endpoints but process columns show `-`.

Example:

```bash
netdiag connections --limit 20 --json
netdiag listen 443 --json
```

## DNS drift

Compare answers across system and public resolvers. Exit **`1`** when resolvers disagree.

```bash
netdiag dns-compare SERVICE -t A --json
netdiag dns-compare SERVICE -t A --corp app.internal.corp --json
```

With `--corp`, JSON includes a second block under `"corp"` for the internal hostname. Pass `--corp` explicitly on `dns-compare` (config `corp_host` applies to `oncall`, `vpn`, and `report`, not this command).

## Project docs (repo root)

| Document | Purpose |
|----------|---------|
| [README](../README.md) | Install, command overview, quick start |
| [CHANGELOG](../CHANGELOG.md) | Release history (current: 0.1.1) |
| [CONTRIBUTING](../CONTRIBUTING.md) | Development setup and PR expectations |
| [SECURITY](../SECURITY.md) | Vulnerability reporting |
| [ROADMAP](../ROADMAP.md) | Planned work and non-goals |
