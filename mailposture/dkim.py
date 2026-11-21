"""DKIM selector discovery and key hygiene checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from .der import rsa_modulus_bits
from .doh import Resolver

# Common selectors in the wild. There is no way to enumerate DKIM selectors,
# so this is best-effort and the report says so.
DEFAULT_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mandrill", "amazonses", "everlytics", "cm",
    "protonmail", "protonmail2", "protonmail3", "zoho", "sendgrid", "mailchimp",
)


@dataclass
class DkimKey:
    selector: str
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    key_bits: int | None = None
    revoked: bool = False
    testing: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def record_name(self) -> str:
        return self.selector


def parse_key(selector: str, raw: str) -> DkimKey:
    key = DkimKey(selector=selector, raw=raw)
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            key.errors.append(f"malformed tag: {part}")
            continue
        key.tags[name.strip().lower()] = value.strip()

    if key.tags.get("v", "DKIM1").upper() != "DKIM1":
        key.errors.append(f"unexpected version: {key.tags.get('v')}")

    flags = key.tags.get("t", "").lower().split(":")
    key.testing = "y" in flags

    public = key.tags.get("p", None)
    if public is None:
        key.errors.append("missing p= public key")
        key.revoked = True
        return key
    if public == "":
        key.revoked = True
        return key

    key_type = key.tags.get("k", "rsa").lower()
    if key_type != "rsa":
        key.errors.append(f"non-RSA key type: {key_type}")
        return key
    try:
        key.key_bits = rsa_modulus_bits(public)
    except ValueError as exc:
        key.errors.append(f"cannot parse public key: {exc}")
    return key


def probe(domain: str, resolver: Resolver,
          selectors: tuple[str, ...] | list[str] = DEFAULT_SELECTORS
          ) -> list[DkimKey]:
    found = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}".lower()
        for raw in resolver.txt(name):
            if raw.strip().upper().startswith("V=DKIM1") or "p=" in raw:
                found.append(parse_key(selector, raw))
    return found
