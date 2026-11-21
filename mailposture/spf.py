"""SPF parsing and recursive evaluation (RFC 7208).

The interesting part is not "does the record start with v=spf1". It is the
*recursive* DNS lookup budget: includes and redirects chain, and every chain
step counts toward the 10-lookup / 2-void-lookup limits. That is where most
real-world SPF records break, and most checkers do not model it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .doh import Resolver

MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MAX_LOOKUPS = 10
MAX_VOID = 2
MAX_DEPTH = 10


@dataclass
class Term:
    qualifier: str  # one of + - ~ ?
    kind: str
    value: str = ""
    cidr: int | None = None
    raw: str = ""

    @property
    def effect(self) -> str:
        return QUALIFIERS.get(self.qualifier, "pass")


@dataclass
class SpfResult:
    domain: str
    raw: str = ""
    record_count: int = 0
    terms: list[Term] = field(default_factory=list)
    modifiers: dict[str, str] = field(default_factory=dict)
    lookups: int = 0
    void_lookups: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tree: list[str] = field(default_factory=list)
    all_qualifier: str | None = None
    macro_usage: bool = False

    @property
    def exists(self) -> bool:
        return self.record_count > 0

    @property
    def lookup_over_budget(self) -> bool:
        return self.lookups > MAX_LOOKUPS

    @property
    def void_over_budget(self) -> bool:
        return self.void_lookups > MAX_VOID


def _valid_ip(value: str, version: int) -> bool:
    host = value.split("/", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == version


def parse_record(raw: str) -> tuple[list[Term], dict[str, str], list[str]]:
    """Parse one SPF TXT record into terms, modifiers and error strings."""
    terms: list[Term] = []
    modifiers: dict[str, str] = {}
    errors: list[str] = []
    tokens = raw.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        errors.append("record does not start with v=spf1")

    for token in tokens[1:]:
        if "=" in token and token[0] not in QUALIFIERS:
            name, _, value = token.partition("=")
            modifiers[name.lower()] = value
            continue

        qualifier = "+"
        if token and token[0] in QUALIFIERS:
            qualifier, token = token[0], token[1:]

        head, sep, value = token.partition(":")
        cidr = None
        if "/" in value:
            value, _, cidr_text = value.partition("/")
            if cidr_text.isdigit():
                cidr = int(cidr_text)
        if "/" in head:  # bare a/24, mx/24
            head, _, cidr_text = head.partition("/")
            if cidr_text.isdigit():
                cidr = int(cidr_text)

        kind = head.lower()
        if kind not in MECHANISMS:
            errors.append(f"unknown mechanism: {token}")
            continue
        if kind in {"include", "exists"} and not value:
            errors.append(f"{kind} requires a domain")
            continue
        if kind == "ip4" and not _valid_ip(value, 4):
            errors.append(f"invalid ip4 value: {value}")
        if kind == "ip6" and not _valid_ip(value, 6):
            errors.append(f"invalid ip6 value: {value}")
        if kind == "include" and cidr is not None:
            errors.append("include does not accept a CIDR length")

        terms.append(Term(qualifier=qualifier, kind=kind, value=value,
                          cidr=cidr, raw=token))

    return terms, modifiers, errors


def _expand_macro(value: str, domain: str) -> str | None:
    """Expand the macros we can resolve without a DNS query context."""
    out = value.replace("%%", "\0").replace("%{d}", domain)
    out = out.replace("%{o}", domain).replace("%{s}", domain)
    out = out.replace("\0", "%")
    if "%{" in out:
        return None
    return out


class SpfEvaluator:
    def __init__(self, resolver: Resolver, max_lookups: int = MAX_LOOKUPS,
                 max_void: int = MAX_VOID):
        self.resolver = resolver
        self.max_lookups = max_lookups
        self.max_void = max_void
        self.lookups = 0
        self.void = 0
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.tree: list[str] = []
        self.macro_usage = False

    # -- helpers ---------------------------------------------------------
    def _spf_records(self, domain: str) -> list[str]:
        return [txt for txt in self.resolver.txt(domain)
                if txt.strip().lower().startswith("v=spf1")]

    def _lookup(self, term: Term, domain: str) -> str | None:
        target = _expand_macro(term.value, domain) if term.value else domain
        if target is None:
            self.macro_usage = True
            self.warnings.append(f"macro mechanism not evaluated: {term.raw}")
            return None
        self.lookups += 1
        return target.rstrip(".").lower()

    def _count_void(self, target: str, kind: str) -> None:
        if kind == "mx":
            empty = not self.resolver.mx(target)
        else:
            empty = not self.resolver.a(target)
        if empty:
            self.void += 1
            self.warnings.append(f"void lookup: {kind}:{target}")

    # -- evaluation ------------------------------------------------------
    def evaluate(self, domain: str) -> SpfResult:
        domain = domain.strip().lower().rstrip(".")
        records = self._spf_records(domain)
        result = SpfResult(domain=domain)
        if not records:
            result.errors.append("no SPF record found")
            return result
        if len(records) > 1:
            self.errors.append(f"multiple SPF records ({len(records)})")

        raw = records[0]
        terms, modifiers, errors = parse_record(raw)
        self.errors.extend(errors)
        self.tree.append(domain)
        self._walk(domain, terms, modifiers, depth=0, seen={domain})

        result.raw = raw
        result.record_count = len(records)
        result.terms = terms
        result.modifiers = modifiers
        result.lookups = self.lookups
        result.void_lookups = self.void
        result.errors = self.errors
        result.warnings = self.warnings
        result.tree = self.tree
        result.macro_usage = self.macro_usage
        for term in terms:
            if term.kind == "all":
                result.all_qualifier = term.qualifier
                break
        return result

    def _walk(self, domain: str, terms: list[Term], modifiers: dict[str, str],
              depth: int, seen: set[str]) -> None:
        if depth > MAX_DEPTH:
            self.errors.append("include depth limit exceeded")
            return
        prefix = "  " * depth

        for term in terms:
            if term.kind == "all":
                continue
            if term.kind == "ip4" or term.kind == "ip6":
                continue
            if term.kind == "include":
                target = self._lookup(term, domain)
                if target is None:
                    continue
                self.tree.append(f"{prefix}include:{target}")
                if target in seen:
                    self.errors.append(f"include loop at {target}")
                    continue
                nested = self._spf_records(target)
                if not nested:
                    self.void += 1
                    self.errors.append(f"include target has no SPF: {target}")
                    continue
                nested_terms, nested_mods, nested_errors = parse_record(nested[0])
                self.errors.extend(f"{target}: {e}" for e in nested_errors)
                if len(nested) > 1:
                    self.errors.append(f"multiple SPF records at {target}")
                self._walk(target, nested_terms, nested_mods, depth + 1,
                           seen | {target})
            elif term.kind in {"a", "mx", "ptr", "exists"}:
                target = self._lookup(term, domain)
                if target is None:
                    continue
                self.tree.append(f"{prefix}{term.kind}:{target}")
                if term.kind != "ptr":
                    self._count_void(target, term.kind)

        # redirect= is only evaluated when there is no all mechanism.
        if "redirect" in modifiers and not any(t.kind == "all" for t in terms):
            target = _expand_macro(modifiers["redirect"], domain)
            self.lookups += 1
            if target is None:
                self.macro_usage = True
                self.warnings.append("redirect macro not evaluated")
                return
            target = target.rstrip(".").lower()
            self.tree.append(f"{prefix}redirect:{target}")
            if target in seen:
                self.errors.append(f"redirect loop at {target}")
                return
            nested = self._spf_records(target)
            if not nested:
                self.errors.append(f"redirect target has no SPF: {target}")
                return
            nested_terms, nested_mods, nested_errors = parse_record(nested[0])
            self.errors.extend(f"{target}: {e}" for e in nested_errors)
            self._walk(target, nested_terms, nested_mods, depth + 1,
                       seen | {target})
