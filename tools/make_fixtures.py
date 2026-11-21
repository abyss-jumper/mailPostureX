#!/usr/bin/env python3
"""Generate the two offline fixtures used by tests, demos and the README.

The RSA keys are *synthetic*: a DER SubjectPublicKeyInfo wrapping a number with
the right bit length. They are structurally valid for the purpose of measuring
key size and are useless as real keys, which is exactly what we want in a
fixture.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "fixtures"


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def spki_b64(bits: int) -> str:
    modulus = (1 << (bits - 1)) | (1 << (bits - 2)) | 0xC0FFEE | 1
    rsa_oid = bytes.fromhex("06092a864886f70d010101")
    algorithm = _tlv(0x30, rsa_oid + b"\x05\x00")
    public_key = _tlv(0x30, _integer(modulus) + _integer(65537))
    bit_string = _tlv(0x03, b"\x00" + public_key)
    return base64.b64encode(_tlv(0x30, algorithm + bit_string)).decode()


def chunked_txt(value: str, size: int = 200) -> str:
    """Split a long TXT value into RFC 1035-style quoted chunks."""
    parts = [value[i:i + size] for i in range(0, len(value), size)] or [""]
    return " ".join(f'"{part}"' for part in parts)


def weak_fixture() -> dict:
    domain = "example.com"
    includes = " ".join(f"include:_spf{i}.example.com" for i in range(1, 12))
    queries = {
        f"{domain}|TXT": [chunked_txt(f"v=spf1 {includes} ~all")],
        f"{domain}|MX": ["10 mail.example.com."],
        "mail.example.com|A": ["192.0.2.25"],
        "_dmarc.example.com|TXT": [
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=50"
        ],
        "default._domainkey.example.com|TXT": [
            f"v=DKIM1; k=rsa; t=y; p={spki_b64(1024)}"
        ],
    }
    for i in range(1, 12):
        queries[f"_spf{i}.example.com|TXT"] = [f"v=spf1 ip4:203.0.113.{i} -all"]
    return {"queries": queries, "ad": []}


def good_fixture() -> dict:
    domain = "example.org"
    return {
        "queries": {
            f"{domain}|TXT": ["v=spf1 include:_spf.example.org -all"],
            "_spf.example.org|TXT": ["v=spf1 ip4:192.0.2.0/24 -all"],
            f"{domain}|MX": ["10 mail.example.org."],
            "mail.example.org|A": ["192.0.2.10"],
            "_dmarc.example.org|TXT": [
                "v=DMARC1; p=reject; sp=reject; pct=100; "
                "adkim=s; aspf=s; rua=mailto:dmarc@example.org"
            ],
            "default._domainkey.example.org|TXT": [
                f"v=DKIM1; k=rsa; p={spki_b64(2048)}"
            ],
            "_mta-sts.example.org|TXT": ["v=STSv1; id=20260101T000000"],
            "_smtp._tls.example.org|TXT": [
                "v=TLSRPTv1; rua=mailto:tlsrpt@example.org"
            ],
        },
        "ad": [domain],
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, payload in (("weak.json", weak_fixture()),
                          ("good.json", good_fixture())):
        path = OUT / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
