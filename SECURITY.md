# Security policy

## Supported versions

Security fixes are applied on the latest release on the default branch (`main`).

| Version | Supported |
|---------|-----------|
| Latest `0.x` on `main` | Yes |
| Older tags | Best effort |

## Reporting a vulnerability

**Do not** open a public GitHub issue for security problems.

1. Open a [private security advisory](https://github.com/akintunero/netdiag/security/advisories/new), or  
2. Email **akintunero101@gmail.com** (or contact [@akintunero](https://github.com/akintunero))

Include:

- Description and impact
- Steps to reproduce
- Affected versions

We aim to acknowledge reports within **72 hours**.

## Scope

**In scope**

- Crashes, credential leaks, or unsafe defaults in netdiag itself
- Issues in how netdiag invokes system tools or parses their output

**Out of scope**

- Unauthorized scanning or probing of third-party networks
- Misconfiguration of targets you pass on the command line

netdiag runs network probes (`ping`, `traceroute`, `dig`, HTTP/TLS) against **hosts you specify**. Use it only on systems you own or are explicitly authorized to test.

## External services

BGP/ASN enrichment may call public APIs (BGPView, RIPEstat, Team Cymru). Use `--no-bgp-api` on `trace` and `whois` to limit outbound HTTP.
