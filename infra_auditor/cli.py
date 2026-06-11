#!/usr/bin/env python3
"""infra-auditor CLI - Infrastructure compliance and security auditor."""

import argparse
import sys
from . import __version__
from .auditor import Auditor
from .config import Config, TargetConfig, CheckConfig
from .reporters import TerminalReporter, JSONReporter, MarkdownReporter


def _configure_output_streams():
    """Best effort: emit UTF-8 even when stdout/stderr are redirected.

    On Windows a piped or redirected stream defaults to the legacy locale
    encoding (e.g. cp1252), which cannot represent the report glyphs and
    makes ``print`` raise ``UnicodeEncodeError``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def _print_report(text):
    """Print *text*, replacing any glyph the stream cannot encode."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(encoding, errors="replace").decode(encoding))


def main():
    _configure_output_streams()
    parser = argparse.ArgumentParser(
        prog="infra-auditor",
        description="Infrastructure compliance and security auditor",
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--host", "-H", default="localhost", help="Target host (default: localhost)"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=22, help="SSH port (default: 22)"
    )
    parser.add_argument("--user", "-u", help="SSH username")
    parser.add_argument("--key", "-i", help="SSH private key file")
    parser.add_argument(
        "--insecure-host-key",
        action="store_true",
        help="Disable SSH host key verification (insecure; not recommended)",
    )
    parser.add_argument(
        "--os-type", choices=["macos", "linux", "windows"], help="Override OS detection"
    )
    parser.add_argument("--config", "-c", help="Path to YAML configuration file")
    parser.add_argument("--checks", help="Comma-separated list of checks to run")
    parser.add_argument("--skip-checks", help="Comma-separated list of checks to skip")
    parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format",
    )
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only show failing checks (terminal format)",
    )
    parser.add_argument(
        "--list-checks", action="store_true", help="List available checks and exit"
    )
    args = parser.parse_args()
    if args.list_checks:
        from .checks.base import CheckRegistry

        print("Available checks:")
        for check_id, check_class in CheckRegistry.all().items():
            print(f"  {check_id:20} - {check_class.name}")
            print(f"  {' ':20}   {check_class.description}")
            print(f"  {' ':20}   OS: {', '.join(check_class.supported_os)}")
            print()
        return 0
    if args.config:
        config = Config.from_yaml(args.config)
    else:
        config = Config()
        config.targets = [
            TargetConfig(
                host=args.host,
                port=args.port,
                username=args.user,
                key_file=args.key,
                os_type=args.os_type,
                insecure_host_key=args.insecure_host_key,
            )
        ]
    if args.checks:
        from .checks.base import CheckRegistry

        enabled = set(args.checks.split(","))
        for check_id in CheckRegistry.list_checks():
            if check_id not in enabled:
                config.checks[check_id] = CheckConfig(enabled=False)
    if args.skip_checks:
        for check_id in args.skip_checks.split(","):
            config.checks[check_id] = CheckConfig(enabled=False)
    auditor = Auditor(config)
    result = auditor.audit()
    # Files are always written as UTF-8, so they keep the unicode glyphs;
    # stdout falls back to ASCII glyphs if its encoding cannot encode them.
    unicode_glyphs = True if args.output else None
    if args.format == "json":
        reporter = JSONReporter()
    elif args.format == "markdown":
        reporter = MarkdownReporter(unicode_glyphs=unicode_glyphs)
    else:
        reporter = TerminalReporter(
            use_color=not args.no_color,
            quiet=args.quiet,
            unicode_glyphs=unicode_glyphs,
        )
    report = reporter.report(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        _print_report(report)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
