"""DMARC record discovery and parsing."""

from __future__ import annotations

from dataclasses import dataclass, field

from .doh import Resolver

POLICIES = {"none", "quarantine", "reject"}
ALIGNMENTS = {"r", "s"}
KNOWN_TAGS = {"v", "p", "sp", "pct", "rua", "ruf", "fo", "rf", "ri", "adkim",
              "aspf", "fo", "rf", "np", "t", "psd"}


@dataclass
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    unknown_tags: list[str] = field(default_factory=list)

    def get(self, name: str, default: str = "") -> str:
        return self.tags.get(name, default)

    @property
    def policy(self) -> str:
        return self.get("p").lower()

    @property
    def subdomain_policy(self) -> str:
        return self.get("sp").lower() or self.policy

    @property
    def percent(self) -> int:
        raw = self.get("pct", "100")
        try:
            return max(0, min(100, int(raw)))
        except ValueError:
            return 100


def parse(raw: str) -> DmarcRecord:
    record = DmarcRecord(raw=raw)
    parts = [p.strip() for p in raw.split(";")]
    for index, part in enumerate(parts):
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if not sep:
            record.errors.append(f"tag without value: {part}")
            continue
        if index == 0 and name != "v":
            record.errors.append("record does not start with v=DMARC1")
        if name == "v" and value.upper() != "DMARC1":
            record.errors.append(f"unexpected version: {value}")
        if name not in KNOWN_TAGS:
            record.unknown_tags.append(name)
        record.tags[name] = value

    if "v" not in record.tags:
        record.errors.append("missing v= tag")
    policy = record.policy
    if not policy:
        record.errors.append("missing p= policy")
    elif policy not in POLICIES:
        record.errors.append(f"invalid p= value: {policy}")
    alignment = record.get("adkim").lower()
    if alignment and alignment not in ALIGNMENTS:
        record.errors.append(f"invalid adkim= value: {alignment}")
    alignment = record.get("aspf").lower()
    if alignment and alignment not in ALIGNMENTS:
        record.errors.append(f"invalid aspf= value: {alignment}")
    return record


def discover(domain: str, resolver: Resolver) -> tuple[list[str], list[DmarcRecord]]:
    """Return raw DMARC TXT records and their parsed forms at _dmarc.<domain>."""
    name = f"_dmarc.{domain}".lower()
    raws = [txt for txt in resolver.txt(name)
            if txt.strip().upper().startswith("V=DMARC1")]
    return raws, [parse(raw) for raw in raws]
