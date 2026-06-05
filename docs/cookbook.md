# Cookbook

Copy-paste recipes for common on-call scenarios. Replace placeholders with your real hostnames.

| Placeholder | Meaning |
|-------------|---------|
| `SERVICE` | Production hostname (e.g. `api.yourcompany.com`) |
| `CORP` | Internal hostname for VPN/DNS checks (e.g. `app.internal.corp`) |

**Exit codes:** `0` pass · `1` probe failed · `2` tool/config error - see [CLI_CONTRACT.md](CLI_CONTRACT.md).

**Targets:** Use real FQDNs or IPs. Reserved names like `api.example.com` do not resolve on the public internet ([RFC 6761](https://datatracker.ietf.org/doc/html/rfc6761)).

**Command reference:** `netdiag --help` lists every subcommand; `netdiag <command> --help` shows flags for that command.

---

## 0. Before every incident

Confirm the machine can run core probes:

```bash
netdiag doctor
```

Exit `2` means fix the environment (usually missing `ping`) before trusting other commands.

---

## 1. Standard incident triage

Fastest path - one command, JSON for the ticket:

```bash
netdiag oncall SERVICE --json
```

Save only failing steps:

```bash
netdiag oncall SERVICE --json | jq '.steps[] | select(.ok == false)'
```

Attach a markdown report:

```bash
netdiag report SERVICE -o incident.md
```

**Preset:** default is `oncall` (strict: DNS compare, trace, headers, redirects). For a lighter public API check:

```bash
netdiag oncall SERVICE --preset api --json
```

For a public website (redirects + security headers):

```bash
netdiag oncall SERVICE --preset web --json
```

---

## 2. “Is it DNS?”

### Quick answer on one host

```bash
netdiag dns SERVICE -t A
netdiag dns SERVICE -t AAAA
netdiag dns-compare SERVICE -t A --json
```

`dns-compare` uses system resolvers vs common public resolvers. A mismatch often means VPN DNS, split tunnel, or stale corp resolver. **Exit code `1`** when resolver answers differ (same as automation-friendly fail).

```bash
netdiag dns-compare SERVICE -t A --json
echo $?   # 0 = consistent, 1 = mismatch, 2 = error (e.g. dig missing)
```

### Full record sweep

```bash
netdiag dns-all SERVICE
```

### Trace delegation (where resolution breaks)

```bash
netdiag dns-trace SERVICE -t A
```

### With corporate context

When the app only exists on corp DNS, use `--corp` on `oncall` / `vpn` / `report`, or standalone compare:

```bash
netdiag oncall SERVICE --corp CORP --json
netdiag dns-compare SERVICE -t A --corp CORP --json
netdiag vpn --corp CORP --json
```

### Compare two names (VPN laptop vs baseline)

Useful when “works on VPN” / “broken off VPN”:

```bash
netdiag compare SERVICE CORP --json
```

---

## 3. API outage (5xx, timeouts, “can’t reach API”)

### Bundle check (API preset)

Skips redirect/header noise; includes short trace:

```bash
netdiag oncall SERVICE --preset api --json
```

### Layer breakdown

| Layer | Command |
|-------|---------|
| Reachability | `netdiag ping SERVICE -c 10` |
| TCP 443 | `netdiag port SERVICE 443` |
| TLS / cert | `netdiag tls SERVICE --json` |
| HTTP phases | `netdiag http "https://SERVICE/health" --timing --json` |
| Path | `netdiag trace SERVICE -m 15 --no-bgp-api` |

### TCP latency distribution (not ICMP)

```bash
netdiag latency SERVICE -p 443 -n 30 --json
```

### End-to-end path in one report

```bash
netdiag report SERVICE --preset api -o api-incident.md
```

---

## 4. VPN and split tunnel

### VPN-only diagnostics

```bash
netdiag vpn --json
netdiag vpn --corp CORP --json
```

Looks for tunnel interfaces (`utun`, `wg`, Tailscale, etc.), routes, resolver config, and public vs corp DNS drift.

### Service check while on VPN

```bash
netdiag oncall SERVICE --vpn --corp CORP --json
netdiag report SERVICE --vpn --corp CORP -o vpn-incident.md
```

### VPN preset (lighter than full oncall)

```bash
netdiag oncall SERVICE --preset vpn --corp CORP --json
```

Includes resolver compare and pings to `1.1.1.1` / `8.8.8.8` as path sanity checks.

### Config file (repeatable)

`~/.config/netdiag/config.toml`:

```toml
[defaults]
corp_host = "app.internal.corp"

[oncall]
preset = "oncall"
```

Then:

```bash
netdiag oncall SERVICE --vpn --json
```

---

## 5. TLS and certificate issues

```bash
netdiag tls SERVICE --json
netdiag oncall SERVICE --preset api --json | jq '.steps[] | select(.name == "TLS")'
```

`oncall` fails (exit `1`) when the cert is close to expiry - treat as a paging signal.

For HTTPS timing with SNI:

```bash
netdiag http "https://SERVICE/" --timing --json
```

---

## 6. Slow or flaky responses

### ICMP + jitter

```bash
netdiag ping SERVICE -c 20
```

### TCP connect + TLS + TTFB

```bash
netdiag http "https://SERVICE/" --timing --json
```

### Throughput (CDN, not your origin)

Measures download speed via Cloudflare edge (useful for “is my uplink bad?”):

```bash
netdiag speed --json
netdiag speed SERVICE --single-stream --bytes 1000000 --json
```

### Where delay appears on the path

```bash
netdiag trace SERVICE -m 20 -q 2
netdiag mtr SERVICE -c 10
```

---

## 7. Redirects and security headers (web)

```bash
netdiag redirects "https://SERVICE/" --json
netdiag headers "https://SERVICE/" --json
```

Full `oncall` / `web` preset runs these against the final URL after redirects.

---

## 8. Literal IP targets (load balancers, anycast)

When `SERVICE` is already an IP (e.g. `1.1.1.1`):

```bash
netdiag oncall 1.1.1.1 --json
```

DNS, redirect, header, and resolver-compare steps are **skipped** by design - you still get ping, ports, TLS, HTTP timing, and trace.

For connectivity-only smoke:

```bash
netdiag oncall 1.1.1.1 --preset api --json
```

---

## 9. Automation and CI

### Gate deploy / health job

```bash
netdiag oncall SERVICE --preset api --json
test $? -eq 0
```

### jq filters for alerts

```bash
# Any failed step
netdiag oncall SERVICE --json | jq -e '.ok'

# DNS resolver drift only
netdiag oncall SERVICE --json | jq '.steps[] | select(.name == "DNS resolvers" and .ok == false)'

# Ping loss
netdiag ping SERVICE -c 5 --json | jq '.loss_percent'
```

### Avoid external BGP APIs in locked-down CI

```bash
netdiag trace SERVICE -m 10 --no-bgp-api --json
```

---

## 10. Local machine context

When the problem might be “my laptop, not prod”:

```bash
netdiag dns-config --json
netdiag route --json
netdiag ifaces --json
netdiag connections --limit 20 --json
netdiag local-ports --json
netdiag listen 443 --json
```

### Who owns this connection?

`connections` shows **Process** (app name + PID) when `lsof` or `ss -p` is available:

```bash
netdiag connections --limit 10
# Proto  Local                    Remote                   State        Process
# tcp4   192.168.1.77:55820       3.86.150.204:443         ESTABLISHED  Cursor [829]
```

JSON fields per row: `command`, `pid`, `user`, `proto`, `local`, `remote`, `state`.

### What is listening on a port?

```bash
netdiag listen 8080 --json
netdiag local-ports --json | jq '.listeners[] | select(.bind | contains(":8080"))'
```

Pair with `netdiag vpn` when on corporate VPN.

---

## Preset cheat sheet

| Preset | Use when |
|--------|----------|
| `oncall` | Full incident bundle (default for `oncall` / strict `report`) |
| `api` | API hostname - 443, TLS, short trace, no header/redirect noise |
| `web` | Public site - 80/443, redirects, security headers |
| `vpn` | VPN path - resolver drift, tunnel sanity, corp compare |

List presets:

```bash
netdiag presets --json
```

---

## Related docs

- [CLI contract](CLI_CONTRACT.md) - exit codes and stable flags
- [Config example](config.example.toml) - defaults and corp host
- [README](../README.md) - install and command index
