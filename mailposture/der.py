"""Tiny DER reader — enough to measure an RSA modulus.

Used for DKIM ``p=`` keys, which are base64 DER (usually SubjectPublicKeyInfo,
sometimes PKCS#1). Both contain the RSA modulus as a large INTEGER.
"""

from __future__ import annotations

import base64
import binascii


def _tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or pos + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise ValueError("truncated DER value")
    return tag, data[pos:pos + length], pos + length


def _walk(tag: int, value: bytes, out: list[int]) -> None:
    if tag == 0x02:  # INTEGER
        out.append(int.from_bytes(value, "big"))
        return
    if tag == 0x03:  # BIT STRING: first byte is the unused-bit count
        value = value[1:]
    elif tag not in (0x30, 0x31, 0x04):  # SEQUENCE, SET, OCTET STRING
        return
    pos = 0
    while pos < len(value):
        inner_tag, inner_value, pos = _tlv(value, pos)
        _walk(inner_tag, inner_value, out)


def rsa_modulus_bits(b64: str) -> int:
    """Return the bit length of the RSA modulus in a base64 DER key."""
    compact = "".join(b64.split())
    if not compact:
        raise ValueError("empty key")
    compact += "=" * (-len(compact) % 4)
    try:
        der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64 key: {exc}") from exc

    integers: list[int] = []
    pos = 0
    while pos < len(der):
        tag, value, pos = _tlv(der, pos)
        _walk(tag, value, integers)
    if not integers:
        raise ValueError("no INTEGER found in key")
    return max(integers, key=int.bit_length).bit_length()
