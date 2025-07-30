from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRequirement:
    binary: str
    label: str
    category: str
    install_hint: str
    commands: tuple[str, ...]


@dataclass(frozen=True)
class ToolStatus:
    requirement: ToolRequirement
    found: bool
    path: str | None


@dataclass(frozen=True)
class DoctorReport:
    platform: str
    tools: tuple[ToolStatus, ...]

    @property
    def required_missing(self) -> tuple[ToolStatus, ...]:
        return tuple(
            t
            for t in self.tools
            if t.requirement.category == "required" and not t.found
        )

    @property
    def ok_for_runbooks(self) -> bool:
        return not self.required_missing


def _requirements() -> tuple[ToolRequirement, ...]:
    system = platform.system().lower()
    reqs: list[ToolRequirement] = [
        ToolRequirement(
            "ping",
            "ping",
            "required",
            "macOS: built-in. Linux: iputils-ping.",
            ("ping", "oncall", "check", "vpn"),
        ),
        ToolRequirement(
            "traceroute",
            "traceroute",
            "recommended",
            "macOS: built-in. Linux: traceroute or iputils-tracepath.",
            ("trace", "oncall", "mtr"),
        ),
        ToolRequirement(
            "dig",
            "dig",
            "recommended",
            "macOS: bind via Homebrew. Linux: dnsutils.",
            ("dns", "dns-trace", "dns-compare", "dns-all", "vpn", "oncall"),
        ),
    ]
    if system == "darwin":
        reqs.append(
            ToolRequirement(
                "scutil",
                "scutil",
                "optional",
                "macOS built-in (dns-config).",
                ("dns-config", "vpn"),
            )
        )
    else:
        reqs.append(
            ToolRequirement(
                "resolvectl",
                "resolvectl",
                "optional",
                "systemd-resolved (dns-config); falls back to /etc/resolv.conf.",
                ("dns-config",),
            )
        )
    reqs.extend(
        [
            ToolRequirement(
                "ss",
                "ss",
                "optional",
                "Linux: iproute2. Falls back to netstat.",
                ("connections",),
            ),
            ToolRequirement(
                "netstat",
                "netstat",
                "optional",
                "Usually preinstalled (route, ifaces, listen fallback).",
                ("route", "ifaces", "listen", "connections"),
            ),
            ToolRequirement(
                "lsof",
                "lsof",
                "optional",
                "macOS: useful for listen/local-ports.",
                ("listen", "local-ports"),
            ),
            ToolRequirement(
                "mtr",
                "mtr",
                "optional",
                "Optional; mtr command falls back to traceroute snapshot.",
                ("mtr",),
            ),
            ToolRequirement(
                "iperf3",
                "iperf3",
                "optional",
                "Only for: netdiag speed --iperf",
                ("speed",),
            ),
        ]
    )
    return tuple(reqs)


def run_doctor() -> DoctorReport:
    statuses: list[ToolStatus] = []
    for req in _requirements():
        path = shutil.which(req.binary)
        statuses.append(
            ToolStatus(
                requirement=req,
                found=path is not None,
                path=path,
            )
        )
    return DoctorReport(platform=platform.system(), tools=tuple(statuses))
