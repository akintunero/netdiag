from __future__ import annotations

import platform
import sys
from importlib import metadata
from typing import Any, TextIO

from netdiag import __version__
from netdiag.banner import print_banner

PROJECT_NAME = "netdiag"
AUTHOR = "Olúmáyòwá Akinkuehinmi"
AUTHOR_EMAIL = "akintunero101@gmail.com"
GITHUB_USER = "akintunero"
GITHUB_PROFILE = f"https://github.com/{GITHUB_USER}"
HOMEPAGE = "https://github.com/akintunero/netdiag"
DOCUMENTATION = f"{HOMEPAGE}#readme"
ISSUES = f"{HOMEPAGE}/issues"
LICENSE = "MIT"
TAGLINE = "Network troubleshooting CLI for on-call and VPN debugging."


def installed_version() -> str:
    try:
        return metadata.version(PROJECT_NAME)
    except metadata.PackageNotFoundError:
        return __version__


def info_dict() -> dict[str, Any]:
    return {
        "name": PROJECT_NAME,
        "version": installed_version(),
        "tagline": TAGLINE,
        "author": AUTHOR,
        "email": AUTHOR_EMAIL,
        "github_user": GITHUB_USER,
        "github_profile": GITHUB_PROFILE,
        "homepage": HOMEPAGE,
        "documentation": DOCUMENTATION,
        "issues": ISSUES,
        "license": LICENSE,
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "primary_workflow": "netdiag oncall HOST --json",
    }


def print_info(*, stream: TextIO | None = None, show_banner: bool = True) -> None:
    out = stream or sys.stdout
    if show_banner:
        print_banner(stream=out)
    data = info_dict()
    out.write(f"{data['name']} {data['version']}\n")
    out.write(f"{data['tagline']}\n\n")
    out.write(f"Developer:   {data['author']}\n")
    out.write(f"Email:       {data['email']}\n")
    out.write(f"GitHub:      {data['github_profile']}\n")
    out.write(f"Repository:  {data['homepage']}\n")
    out.write(f"Docs:        {data['documentation']}\n")
    out.write(f"Issues:      {data['issues']}\n")
    out.write(f"License:     {data['license']}\n\n")
    out.write(f"Python:      {data['python']} ({data['python_implementation']})\n")
    out.write(f"Platform:    {data['platform']}\n\n")
    out.write(f"Workflow:    {data['primary_workflow']}\n")
