# Contributing to netdiag

Thanks for helping build a CLI operators reach for during incidents.

## Principles

- **Zero runtime PyPI dependencies** - probes wrap system tools and the stdlib
- **Predictable CLI** - exit codes `0` / `1` / `2`, documented in [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md)
- **Incident-friendly JSON** - new commands should support `--json`

## Development setup

```bash
git clone https://github.com/akintunero/netdiag.git
cd netdiag
python3 -m pip install -e ".[dev]"
pytest -q
```

Or install the published package for a smoke test without a clone:

```bash
python3 -m pip install netdiag-cli
netdiag doctor
```

Optional full CLI smoke (requires network):

```bash
bash scripts/cli_smoke.sh
```

## Good first contributions

- Parser tests using fixtures under `tests/fixtures/` (ping, traceroute, `dig`)
- Additional cookbook entries in [docs/cookbook.md](docs/cookbook.md)
- Platform notes (macOS vs Linux tool paths and flags)
- Clearer errors when `dig`, `traceroute`, or `ping` is missing
- Probes that do not add required dependencies to `pyproject.toml`

For larger features, open an issue first with the on-call or VPN use case.

## Pull request checklist

- [ ] `pytest -q` passes
- [ ] New behavior has tests (fixtures preferred over live network)
- [ ] README or [docs/](docs/) updated for new commands or flags (include `--help` examples and JSON samples in [CLI contract](docs/CLI_CONTRACT.md) when output shape changes)
- [ ] No new **required** runtime dependencies in `pyproject.toml`
- [ ] Scanning or probing commands note authorized-use expectations

## Code conventions

- Keep `cli.py` handlers thin; logic lives in `netdiag/` modules
- Use dataclasses for structured results; emit JSON via existing helpers
- Errors on stderr (`error:` prefix); respect exit codes in `exit_codes.py`
- Handle missing binaries with actionable messages, not tracebacks

## Security

See [SECURITY.md](SECURITY.md). Do not commit API keys or internal hostnames in fixtures. Report vulnerabilities privately before public issues.

## Releases (maintainers)

1. Bump `version` in `pyproject.toml` and `netdiag/__init__.py`
2. Update [CHANGELOG.md](CHANGELOG.md)
3. `python -m build && python -m twine check dist/*`
4. Upload to PyPI: `python3 -m twine upload dist/*` (project name `netdiag-cli`)
5. Tag the release on GitHub
