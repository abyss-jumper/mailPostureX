"""Synthetic RSA SPKI builder shared by the tests."""

from __future__ import annotations

import base64


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
    algorithm = _tlv(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    public_key = _tlv(0x30, _integer(modulus) + _integer(65537))
    bit_string = _tlv(0x03, b"\x00" + public_key)
    return base64.b64encode(_tlv(0x30, algorithm + bit_string)).decode()


def pkcs1_b64(bits: int) -> str:
    modulus = (1 << (bits - 1)) | (1 << (bits - 2)) | 0xBEEF | 1
    return base64.b64encode(
        _tlv(0x30, _integer(modulus) + _integer(65537))
    ).decode()
