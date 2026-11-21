"""mailposture command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import audit
from .dkim import DEFAULT_SELECTORS
from .doh import DoHResolver, StaticResolver, load_static
from .report import to_html, to_json, to_text
from .score import grade_at_least

FIXTURES = Path(__file__).resolve().parent.parent / "data" / "fixtures"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mailposture",
        description="Audit SPF, DMARC, DKIM and transport security for a domain.",
    )
    p.add_argument("domain", help="domain to audit, e.g. example.com")
    p.add_argument("--format", choices=("text", "json", "html"), default="text")
    p.add_argument("--out", help="write the report to a file")
    p.add_argument("--doh", default="https://cloudflare-dns.com/dns-query",
                   help="DNS-over-HTTPS endpoint")
    p.add_argument("--fixture", help="offline fixture JSON (no network)")
    p.add_argument("--demo", choices=("weak", "good"), help="run a bundled fixture")
    p.add_argument("--selector", action="append", default=[],
                   help="extra DKIM selector to probe (repeatable)")
    p.add_argument("--fetch-policy", action="store_true",
                   help="also fetch and inspect the MTA-STS policy over HTTPS")
    p.add_argument("--min-grade", help="exit 1 if the grade is below this (A-F)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _resolver(args) -> DoHResolver | StaticResolver:
    if args.demo:
        return load_static(FIXTURES / f"{args.demo}.json")
    if args.fixture:
        return load_static(args.fixture)
    return DoHResolver(endpoint=args.doh)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:  # Windows consoles default to cp1252
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):  # pragma: no cover
                pass

    resolver = _resolver(args)
    selectors = list(DEFAULT_SELECTORS) + [s for s in args.selector
                                           if s not in DEFAULT_SELECTORS]

    try:
        report = audit(args.domain, resolver, selectors=selectors,
                       fetch_policy=args.fetch_policy)
    except Exception as exc:  # noqa: BLE001 - keep the CLI friendly
        print(f"error: audit failed: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = to_json(report)
    elif args.format == "html":
        rendered = to_html(report)
    else:
        rendered = to_text(report)

    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out} (grade {report.grade}, score {report.score})",
              file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if args.min_grade and not grade_at_least(report.grade, args.min_grade):
        print(f"grade {report.grade} is below required {args.min_grade.upper()}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
