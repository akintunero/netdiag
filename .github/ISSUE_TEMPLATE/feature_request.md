---
name: Feature request
about: Suggest a command, flag, or workflow improvement
title: "[feature] "
labels: enhancement
---

## Problem

What troubleshooting step is painful today? (on-call, VPN, DNS, API outage, etc.)

## Proposed interface

```bash
netdiag ...
```

## Why netdiag

Why not a one-off script with `dig` / `mtr` / `curl`?

## Constraints

- [ ] No new **required** runtime PyPI dependencies
- [ ] Should support `--json` for automation
- [ ] Fits authorized-use / bounded scanning expectations
