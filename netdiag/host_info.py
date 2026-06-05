from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class RouteEntry:
    destination: str
    gateway: str | None
    flags: str | None
    interface: str | None


@dataclass(frozen=True)
class InterfaceAddr:
    name: str
    family: str
    address: str
    prefixlen: int | None
    state: str | None


@dataclass(frozen=True)
class ListenProcess:
    command: str
    pid: str | None
    user: str | None
    bind: str


@dataclass(frozen=True)
class ConnectionEntry:
    proto: str
    local: str
    remote: str
    state: str
    command: str | None = None
    pid: str | None = None
    user: str | None = None


def list_routes() -> list[RouteEntry]:
    system = platform.system().lower()
    if system == "linux" and shutil.which("ip"):
        return _routes_linux_ip()
    return _routes_netstat()


def _routes_linux_ip() -> list[RouteEntry]:
    proc = subprocess.run(
        ["ip", "-j", "route", "show"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return _routes_netstat()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return _routes_netstat()

    entries: list[RouteEntry] = []
    for item in data:
        dest = item.get("dst", "default")
        if dest == "default":
            dest = "0.0.0.0/0"
        entries.append(
            RouteEntry(
                destination=dest,
                gateway=item.get("gateway"),
                flags=None,
                interface=item.get("dev"),
            )
        )
    return entries


def _routes_netstat() -> list[RouteEntry]:
    cmd = ["netstat", "-rn"]
    if platform.system().lower() == "linux":
        cmd = ["netstat", "-rn"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    entries: list[RouteEntry] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Routing") or line.startswith("Internet"):
            continue
        if "Destination" in line or "Gateway" in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        dest, gw = parts[0], parts[1]
        if gw in ("link#", "link#0") or gw.startswith("link#"):
            gw = None
        flags = parts[2] if len(parts) > 2 and not parts[2].startswith("en") else None
        iface = None
        for p in reversed(parts):
            if p.startswith(("en", "eth", "wlan", "utun", "lo", "br", "docker", "tun", "wg")):
                iface = p
                break
        entries.append(
            RouteEntry(
                destination=dest,
                gateway=gw if gw not in ("*", "0.0.0.0") else None,
                flags=flags,
                interface=iface,
            )
        )
    return entries


def list_interfaces() -> list[InterfaceAddr]:
    system = platform.system().lower()
    if system == "linux" and shutil.which("ip"):
        return _ifaces_linux_ip()
    return _ifaces_ifconfig()


def _ifaces_linux_ip() -> list[InterfaceAddr]:
    proc = subprocess.run(
        ["ip", "-j", "addr", "show"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        return _ifaces_ifconfig()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return _ifaces_ifconfig()

    addrs: list[InterfaceAddr] = []
    for iface in data:
        name = iface.get("ifname", "?")
        state = iface.get("operstate")
        for info in iface.get("addr_info", []):
            family = info.get("family", "?")
            local = info.get("local")
            if not local:
                continue
            prefix = info.get("prefixlen")
            label = "IPv4" if family == "inet" else "IPv6" if family == "inet6" else family
            addrs.append(
                InterfaceAddr(
                    name=name,
                    family=label,
                    address=local,
                    prefixlen=prefix,
                    state=state,
                )
            )
    return addrs


_IFCONFIG_INET = re.compile(
    r"^\s*inet6?\s+([^\s]+)(?:\s+netmask\s+0x([0-9a-fA-F]+))?(?:\s+prefixlen\s+(\d+))?",
    re.MULTILINE,
)


def _ifaces_ifconfig() -> list[InterfaceAddr]:
    proc = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10, check=False)
    addrs: list[InterfaceAddr] = []
    current: str | None = None
    for line in proc.stdout.splitlines():
        if line and not line.startswith("\t") and not line.startswith(" "):
            current = line.split(":")[0]
        m = _IFCONFIG_INET.search(line)
        if m and current:
            addr = m.group(1).split("%")[0]
            prefix = m.group(3)
            if prefix is None and m.group(2):
                bits = bin(int(m.group(2), 16)).count("1")
                prefix = str(bits)
            family = "IPv6" if "inet6" in line else "IPv4"
            addrs.append(
                InterfaceAddr(
                    name=current,
                    family=family,
                    address=addr,
                    prefixlen=int(prefix) if prefix else None,
                    state=None,
                )
            )
    return addrs


def listeners_on_port(port: int) -> list[ListenProcess]:
    if shutil.which("lsof"):
        proc = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        rows: list[ListenProcess] = []
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            rows.append(
                ListenProcess(
                    command=parts[0],
                    pid=parts[1],
                    user=parts[2],
                    bind=parts[-1],
                )
            )
        return rows

    proc = subprocess.run(
        ["netstat", "-an"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    needle = f".{port}"
    rows = []
    for line in proc.stdout.splitlines():
        if "LISTEN" not in line.upper():
            continue
        if needle not in line:
            continue
        rows.append(ListenProcess(command="?", pid=None, user=None, bind=line.strip()))
    return rows


def list_all_listeners() -> list[ListenProcess]:
    if shutil.which("lsof"):
        proc = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        rows: list[ListenProcess] = []
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            rows.append(
                ListenProcess(
                    command=parts[0],
                    pid=parts[1],
                    user=parts[2],
                    bind=parts[-1],
                )
            )
        return rows
    return _listeners_netstat()


def _listeners_netstat() -> list[ListenProcess]:
    proc = subprocess.run(["netstat", "-anv"], capture_output=True, text=True, timeout=15, check=False)
    rows: list[ListenProcess] = []
    for line in proc.stdout.splitlines():
        if "LISTEN" not in line.upper():
            continue
        rows.append(ListenProcess(command="?", pid=None, user=None, bind=line.strip()))
    return rows


def list_connections() -> list[ConnectionEntry]:
    if shutil.which("lsof"):
        rows = _connections_lsof()
        if rows:
            return rows

    if shutil.which("ss"):
        proc = subprocess.run(
            ["ss", "-H", "-n", "-t", "-u", "-p", "state", "established"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return _parse_ss_output(proc.stdout)

    proc = subprocess.run(["netstat", "-n"], capture_output=True, text=True, timeout=15, check=False)
    return _parse_netstat_connections(proc.stdout)


_LSOF_CONN_NAME = re.compile(
    r"^(?P<proto>TCP|UDP)\s+(?P<local>[^-]+)->(?P<remote>\S+)\s+\((?P<state>[^)]+)\)$"
)
_SS_PROC = re.compile(r'users:\(\("(?P<command>[^"]+)",pid=(?P<pid>\d+)')


def _connections_lsof() -> list[ConnectionEntry]:
    rows: list[ConnectionEntry] = []
    for extra in (["-iTCP", "-sTCP:ESTABLISHED"], ["-iUDP"]):
        proc = subprocess.run(
            ["lsof", "-nP", *extra],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            continue
        rows.extend(_parse_lsof_connections(proc.stdout))
    return rows


def _parse_lsof_connections(text: str) -> list[ConnectionEntry]:
    rows: list[ConnectionEntry] = []
    for line in text.splitlines():
        if line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        name_start = next((i for i, part in enumerate(parts) if part in ("TCP", "UDP")), None)
        if name_start is None:
            continue
        name = " ".join(parts[name_start:])
        match = _LSOF_CONN_NAME.match(name)
        if not match:
            continue
        proto = match.group("proto").lower()
        if proto == "tcp":
            proto = "tcp4"
        rows.append(
            ConnectionEntry(
                proto=proto,
                local=match.group("local"),
                remote=match.group("remote"),
                state=match.group("state"),
                command=parts[0],
                pid=parts[1],
                user=parts[2],
            )
        )
    return rows


def _parse_ss_output(text: str) -> list[ConnectionEntry]:
    rows: list[ConnectionEntry] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        local = parts[4] if len(parts) >= 6 else parts[3]
        remote = parts[5] if len(parts) >= 6 else parts[4]
        command: str | None = None
        pid: str | None = None
        proc_match = _SS_PROC.search(line)
        if proc_match:
            command = proc_match.group("command")
            pid = proc_match.group("pid")
        rows.append(
            ConnectionEntry(
                proto=proto,
                local=local,
                remote=remote,
                state=state,
                command=command,
                pid=pid,
                user=None,
            )
        )
    return rows


def _parse_netstat_connections(text: str) -> list[ConnectionEntry]:
    rows: list[ConnectionEntry] = []
    for line in text.splitlines():
        upper = line.upper()
        if "ESTABLISHED" not in upper and "ESTAB" not in upper:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        local = parts[3] if len(parts) > 3 else "?"
        remote = parts[4] if len(parts) > 4 else "?"
        state = "ESTABLISHED"
        for p in parts:
            if p.upper() in ("ESTABLISHED", "ESTAB", "SYN_SENT", "CLOSE_WAIT"):
                state = p
        rows.append(
            ConnectionEntry(
                proto=proto,
                local=local,
                remote=remote,
                state=state,
                command=None,
                pid=None,
                user=None,
            )
        )
    return rows
