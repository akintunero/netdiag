# netdiag

**Production runbook CLI for network incidents** - traceroute with ASN/BGP, DNS drift, latency, VPN checks, and on-call presets in one binary.

[![CI](https://github.com/akintunero/netdiag/actions/workflows/ci.yml/badge.svg)](https://github.com/akintunero/netdiag/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![PyPI](https://img.shields.io/pypi/v/netdiag-cli?label=PyPI&color=blue)

![License](https://img.shields.io/badge/license-MIT-green)

**Latest:** [0.1.1](CHANGELOG.md) on [PyPI](https://pypi.org/project/netdiag-cli/) (`netdiag-cli`)

**Stdlib-only at runtime** · **`--json` on every command** · **Exit codes built for automation**

```bash
netdiag doctor
netdiag oncall <HOST> --json
```

---

## Install

| Method | Command |
|--------|---------|
| From source (dev) | `python3 -m pip install -e ".[dev]"` |
| PyPI | `python3 -m pip install netdiag-cli` |
| From Git | `python3 -m pip install "git+https://github.com/akintunero/netdiag.git"` |

Use `python3 -m pip` (not bare `pip`) on macOS if `pip` is missing. The PyPI package is **`netdiag-cli`**; the command is still **`netdiag`**.

**System tools:** `ping` (required). Recommended: `traceroute`, `dig`. Optional: **`lsof`** (macOS) or **`ss -p`** (Linux) for process names on `connections`, `listen`, and `local-ports`. Run `netdiag doctor` to see what is on your PATH.

---

## Runbook workflow

| Step | Command | Exit code |
|------|---------|-----------|
| 1. Pre-flight | `netdiag doctor` | `0` ready · `2` missing required tools |
| 2. Incident check | `netdiag oncall <HOST> --json` | `0` pass · `1` fail · `2` error |
| 3. Ticket artifact | `netdiag report <HOST> -o incident.md` | same |

Exit code semantics are stable in v0.x - see [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md).

```bash
netdiag oncall 1.1.1.1 --json
netdiag oncall YOUR-SERVICE.example.com --json | jq '.steps[] | select(.ok==false)'
```

> **Tip:** Run one command per line. Do not paste trailing `#` comments from docs into zsh/bash.

### VPN and corporate DNS

```bash
netdiag vpn --corp intranet.company.com
netdiag oncall app.internal --corp app.internal --vpn --json
```

### Optional config

Copy [docs/config.example.toml](docs/config.example.toml) to `~/.config/netdiag/config.toml`:

```toml
[defaults]
corp_host = "app.internal.corp"

[oncall]
preset = "oncall"
```

### Shell completions

```bash
eval "$(netdiag completion bash)"
eval "$(netdiag completion zsh)"
```

### About the CLI

```bash
netdiag --info    # version, platform, repo links, wordmark banner
```

Set `NETDIAG_NO_BANNER=1` to hide the banner.

---

## Why operators use it

| | |
|---|---|
| **One CLI** | Replaces ad-hoc `dig` + `ping` + `curl` + `traceroute` scripts |
| **`--json`** | PagerDuty, CI, Slack bots, `jq` filters |
| **Presets** | `web`, `api`, `vpn`, `oncall` - tuned check bundles |
| **Small runtime** | No required PyPI dependencies |

---

## Quick start (developers)

```bash
git clone https://github.com/akintunero/netdiag.git
cd netdiag
python3 -m pip install -e ".[dev]"
netdiag doctor
python3 -m pytest tests/ -q
```

Smoke test (live network, all subcommands):

```bash
bash scripts/cli_smoke.sh
```

Example probes:

```bash
netdiag oncall 1.1.1.1 --json
netdiag oncall 1.1.1.1 --preset api --json
netdiag trace 8.8.8.8 -m 12 --no-bgp-api
netdiag report 1.1.1.1 -o incident.md
```

---

## Command reference

| Command | Description |
|---------|-------------|
| **`doctor`** | Pre-flight: required tools for runbooks |
| **`oncall`** | Primary incident bundle (preset `oncall`) |
| `report` | Markdown report (`-o file.md`, `--vpn`) |
| `vpn` | VPN, split-tunnel, DNS drift |
| `check` | Health check; `--preset` for bundles |
| `trace` | Traceroute + ASN/BGP enrichment |
| `ping` / `latency` | RTT, jitter, percentiles |
| `dns` / `dns-trace` / `dns-all` | DNS lookups and delegation trace |
| **`dns-compare`** | Resolver drift; **`--corp HOST`** for internal DNS (exit `1` on mismatch) |
| `port` / `ports` | TCP probes and scans |
| `http` / `tls` / `redirects` / `headers` | Application layer |
| `speed` | CDN throughput (Cloudflare by default) |
| `compare` | Two-host DNS + ping diff |
| `connections` | Established TCP/UDP sockets with **process name and PID** (`lsof` / `ss`) |
| `local-ports` / `listen` | Listening ports and owning processes |
| `route` / `ifaces` / `dns-config` | Local routing, interfaces, resolvers |
| `presets` | List available presets |
| `completion` | bash / zsh completions |

Also: `whois`, `subnet`, `ip`, `ptr`, `mtr`, and more.

```bash
netdiag --help              # all subcommands
netdiag <command> --help    # flags for one command
netdiag connections --limit 10 --json
netdiag dns-compare HOST -t A --corp app.internal --json
```

All commands support `--json`.

---

## Documentation

| Doc | Link |
|-----|------|
| Docs index | [docs/README.md](docs/README.md) |
| Cookbook (on-call recipes) | [docs/cookbook.md](docs/cookbook.md) |
| CLI contract (exit codes, flags) | [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security | [SECURITY.md](SECURITY.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

## Author

**Olúmáyòwá Akinkuehinmi** - [@akintunero](https://github.com/akintunero) · [akintunero101@gmail.com](mailto:akintunero101@gmail.com)

## License

MIT - see [LICENSE](LICENSE).

## Responsible use

Use only on networks and hosts you are authorized to test.
