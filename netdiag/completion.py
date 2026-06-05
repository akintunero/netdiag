from __future__ import annotations

COMMANDS: tuple[str, ...] = (
    "trace",
    "whois",
    "ping",
    "latency",
    "check",
    "oncall",
    "vpn",
    "compare",
    "report",
    "dns",
    "dns-trace",
    "dns-compare",
    "dns-all",
    "dns-config",
    "port",
    "ports",
    "http",
    "tls",
    "ptr",
    "subnet",
    "ip",
    "route",
    "ifaces",
    "listen",
    "local-ports",
    "connections",
    "speed",
    "presets",
    "redirects",
    "headers",
    "mtr",
    "doctor",
    "completion",
)

PRESETS: tuple[str, ...] = ("web", "api", "vpn", "oncall")


def bash_completion() -> str:
    cmds = " ".join(COMMANDS)
    presets = " ".join(PRESETS)
    return f"""# netdiag bash completion - eval "$(netdiag completion bash)"
_netdiag() {{
  local cur prev opts
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  opts="{cmds}"

  if [[ ${{COMP_CWORD}} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
    return 0
  fi

  case "${{COMP_WORDS[1]}}" in
    oncall|check|report|dns-compare)
      case "${{prev}}" in
        --preset) COMPREPLY=( $(compgen -W "{presets}" -- "${{cur}}") ) ;;
      esac
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh" -- "${{cur}}") )
      ;;
  esac
}}
complete -F _netdiag netdiag
"""


def zsh_completion() -> str:
    cmds = " ".join(COMMANDS)
    presets = " ".join(PRESETS)
    return f"""#compdef netdiag
# eval "$(netdiag completion zsh)"

_netdiag() {{
  local -a commands presets
  commands=({cmds})
  presets=({presets})

  _arguments -C \\
    '1: :->command' \\
    '*:: :->args'

  case $state in
    command)
      _describe 'netdiag command' commands
      ;;
    args)
      case $line[1] in
        oncall|check|report)
          _arguments '--preset[check preset]:preset:($presets)' \\
            '--corp[corporate hostname]' \\
            '--json[JSON output]' \\
            '--url[HTTP URL]'
          ;;
        dns-compare)
          _arguments '--corp[corporate hostname]' '--type[record type]' '--json[JSON output]'
          ;;
        vpn)
          _arguments '--corp[corporate hostname]' '--dns-name[public DNS name]' '--json'
          ;;
        completion)
          _arguments '1:shell:(bash zsh)'
          ;;
        *)
          _arguments '--json[JSON output]'
          ;;
      esac
      ;;
  esac
}}

_netdiag "$@"
"""
