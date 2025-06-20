# Roadmap

netdiag aims to be a **trustworthy, stdlib-only CLI** that SREs and platform engineers use daily during incidents.

## Near term

| Item | Status |
|------|--------|
| GitHub repo public and CI green | In progress |
| PyPI publish under a **distinct** name (`netdiag` is taken) | Planned |
| Cookbook in `docs/` (VPN split-tunnel, DNS drift, API outage) | Done - [docs/cookbook.md](docs/cookbook.md) |
| README badges (CI, Python) | Done |
| Offline fixtures for ping / traceroute / `dig` parsers | Done |
| Shell completions (bash / zsh) | Done |
| `netdiag doctor` pre-flight | Done |
| Config file `~/.config/netdiag/config.toml` | Done |
| Stable CLI contract | Done |

## Medium term

- Homebrew formula or distro packaging
- Bounded UDP probes (DNS/NTP) with documented limits
- HTML export for `netdiag report` (ticket attachments)

## Principles (non-negotiable)

- No required runtime PyPI dependencies
- Every user-facing command supports `--json`
- Safe defaults for scanning (limits; no aggressive wide-area scanning)
- Clear authorized-use messaging in docs and CLI help

## Not planned

- Full port-scanner / nmap replacement
- Internet-wide or aggressive scanning modes
- Hosted SaaS or agents that phone home
- Bundled large geo-IP or threat-intel databases

Open an issue if your org needs something that fits these constraints.
