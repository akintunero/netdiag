# CLI contract

Stable behavior for **production runbooks**, CI, and on-call automation.  
Applies from **v0.1.0** onward unless a major version notes otherwise.

For flags and subcommands: `netdiag --help` and `netdiag <command> --help`.

---

## Exit codes

| Code | Name | Meaning | Typical action |
|------|------|---------|----------------|
| `0` | `EX_OK` | Ran successfully; checks passed | Close alert / continue |
| `1` | `EX_FAIL` | Ran successfully; target or check failed | Page, escalate, retry |
| `2` | `EX_ERROR` | Cannot run reliably (config, missing tool, bad args) | Fix host, install tools, fix script |

```bash
netdiag oncall 1.1.1.1 --json
echo $?   # 0 = pass, 1 = fail, 2 = error
```

**Stability (v0.x):** These three meanings will not change. New failure modes map to `1` or `2`.

### Examples

| Situation | Code |
|-----------|------|
| `dns-compare` - all resolvers agree | `0` |
| `dns-compare` - resolver mismatch | `1` |
| `oncall` - all steps pass | `0` |
| `oncall` - ping loss or TLS expiring soon | `1` |
| `dns` - `dig` not installed | `2` |
| `doctor` - required `ping` missing | `2` |
| Invalid CLI arguments | `2` |

---

## Primary workflow

Memorize one command:

```bash
netdiag oncall <HOST> --json
```

With corporate DNS context:

```bash
netdiag oncall <HOST> --json --corp app.internal
```

Markdown artifact for tickets:

```bash
netdiag report <HOST> -o incident.md --vpn --corp app.internal
```

Pre-flight before runbooks:

```bash
netdiag doctor   # exit 0 = ready, 2 = missing required tools
```

---

## Stable flags (v0.x)

| Flag | Commands | Notes |
|------|----------|-------|
| `--json` | All subcommands | Schema may grow; existing keys stay |
| `--preset {web,api,vpn,oncall}` | `check`, `oncall`, `report` | Check bundle selection |
| `--corp HOST` | `check`, `oncall`, `report`, `vpn`, `dns-compare` | Corporate resolver context |
| `--no-bgp-api` | `trace`, `whois` | Skip external BGP HTTP APIs |
| `--vpn` | `oncall`, `report`, `vpn` | Include VPN-related checks |

---

## JSON output

- One JSON object per invocation when `--json` is set (some commands embed arrays under a key).
- Failures may include an `"error"` field with a human-readable message.
- Intended for `jq` in runbooks, e.g.:

```bash
netdiag oncall "$HOST" --json | jq '.steps[] | select(.ok == false)'
```

### `connections --json`

```json
{
  "connections": [
    {
      "proto": "tcp4",
      "local": "192.168.1.77:55820",
      "remote": "3.86.150.204:443",
      "state": "ESTABLISHED",
      "command": "Cursor",
      "pid": "829",
      "user": "oak"
    }
  ],
  "shown": 1
}
```

`command`, `pid`, and `user` are `null` when only `netstat` is available.

### `listen --json`

```json
{
  "port": 443,
  "listeners": [
    {
      "command": "nginx",
      "pid": "1234",
      "user": "www",
      "bind": "*:443"
    }
  ]
}
```

### `dns-compare --json`

Without `--corp`:

```json
{
  "name": "api.example.com",
  "type": "A",
  "resolvers": [ { "resolver": "system", "records": ["1.2.3.4"], ... } ]
}
```

With `--corp app.internal`:

```json
{
  "name": "api.example.com",
  "type": "A",
  "resolvers": [ ... ],
  "corp": {
    "host": "app.internal",
    "resolvers": [ ... ]
  }
}
```

Exit **`1`** if any resolver set for `name` or `corp` is inconsistent.

---

## Optional config

Path: `~/.config/netdiag/config.toml`  
Example: [config.example.toml](config.example.toml)

Config changes defaults only; it does **not** change exit code semantics.

---

## Versioning policy

| Series | Policy |
|--------|--------|
| **v0.x** | Additive only - new commands, JSON keys, optional flags |
| **v1.0+** | Breaking exit-code or flag removals only with major version + CHANGELOG migration notes |

See [CHANGELOG.md](../CHANGELOG.md) for release history.
