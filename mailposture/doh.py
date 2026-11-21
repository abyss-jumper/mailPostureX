"""Minimal DNS-over-HTTPS resolver.

Why DoH instead of raw UDP DNS? Because it needs zero third-party packages and
works from locked-down CI runners where outbound UDP/53 is often blocked.

The transaction layer is a single callable so tests can replay fixtures with no
network at all.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_ENDPOINT = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "mailposture/0.1 (+https://github.com/)"

_TXT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class Record:
    name: str
    rtype: str
    ttl: int
    data: str


@dataclass
class QueryResult:
    status: int  # DNS RCODE: 0 = NOERROR, 3 = NXDOMAIN
    records: list[Record] = field(default_factory=list)
    ad: bool = False  # authenticated data (DNSSEC validated)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 0


def _unquote_txt(data: str) -> str:
    """Join a quoted TXT rdata into one string, per RFC 1035 chunking."""
    chunks = _TXT_RE.findall(data)
    if not chunks:
        return data.strip()
    return "".join(chunk.replace('\\"', '"').replace("\\\\", "\\") for chunk in chunks)


class Resolver:
    """Interface implemented by the live and static resolvers."""

    def query(self, name: str, rtype: str) -> QueryResult:
        raise NotImplementedError

    def txt(self, name: str) -> list[str]:
        return [_unquote_txt(r.data) for r in self.query(name, "TXT").records
                if r.rtype == "TXT"]

    def mx(self, name: str) -> list[tuple[int, str]]:
        out = []
        for rec in self.query(name, "MX").records:
            if rec.rtype != "MX":
                continue
            pref, sep, host = rec.data.partition(" ")
            if not sep:
                continue
            # A null MX ("0 .") deliberately resolves to the empty host.
            out.append((int(pref) if pref.isdigit() else 0,
                        host.strip().rstrip(".").lower()))
        return out

    def a(self, name: str) -> list[str]:
        return [r.data for r in self.query(name, "A").records if r.rtype == "A"]

    def dnssec_validated(self, name: str) -> bool | None:
        return None


class DoHResolver(Resolver):
    def __init__(self, endpoint: str = DEFAULT_ENDPOINT,
                 timeout: float = 10.0, transport=None):
        self.endpoint = endpoint
        self.timeout = timeout
        self._transport = transport or self._http_transport
        self._cache: dict[tuple[str, str], QueryResult] = {}

    def _http_transport(self, url: str) -> dict:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def query(self, name: str, rtype: str) -> QueryResult:
        name = name.strip().lower().rstrip(".")
        key = (name, rtype.upper())
        if key in self._cache:
            return self._cache[key]
        params = urllib.parse.urlencode({"name": name, "type": rtype.upper()})
        url = f"{self.endpoint}?{params}"
        try:
            payload = self._transport(url)
        except Exception as exc:  # noqa: BLE001 - reported as SERVFAIL
            result = QueryResult(status=2, error=str(exc))
            self._cache[key] = result
            return result

        status = int(payload.get("Status", 2))
        records = []
        for answer in payload.get("Answer", []) or []:
            records.append(
                Record(
                    name=str(answer.get("name", name)).lower().rstrip("."),
                    rtype=_TYPE_NAMES.get(answer.get("type"), str(answer.get("type"))),
                    ttl=int(answer.get("TTL", 0)),
                    data=str(answer.get("data", "")),
                )
            )
        result = QueryResult(status=status, records=records,
                             ad=bool(payload.get("AD", False)))
        self._cache[key] = result
        return result

    def dnssec_validated(self, name: str) -> bool | None:
        return self.query(name, "A").ad


_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT",
               28: "AAAA", 43: "DS", 48: "DNSKEY", 52: "TLSA", 257: "CAA"}


class StaticResolver(Resolver):
    """Offline resolver backed by a fixture.

    Fixture shape::

        {
          "ad": ["example.com"],
          "queries": {
            "example.com|TXT": ["v=spf1 -all"],
            "example.com|MX": ["10 mail.example.com."],
            "_dmarc.example.com|TXT": ["v=DMARC1; p=reject"]
          }
        }

    Keys that are absent return NXDOMAIN; keys mapped to an empty list return
    NODATA (NOERROR, zero records).
    """

    def __init__(self, queries: dict[str, list[str]], ad: list[str] | None = None):
        self.queries = {k.upper().replace("|", "|"): v for k, v in queries.items()}
        self.queries = {self._norm(k): v for k, v in self.queries.items()}
        self.ad = {n.lower().rstrip(".") for n in (ad or [])}

    @staticmethod
    def _norm(key: str) -> str:
        name, _, rtype = key.partition("|")
        return f"{name.strip().lower().rstrip('.')}|{rtype.strip().upper()}"

    def query(self, name: str, rtype: str) -> QueryResult:
        key = self._norm(f"{name}|{rtype.upper()}")
        if key not in self.queries:
            return QueryResult(status=3)
        records = [
            Record(name=name.lower().rstrip("."), rtype=rtype.upper(), ttl=300,
                   data=str(value))
            for value in self.queries[key]
        ]
        return QueryResult(status=0, records=records,
                           ad=name.lower().rstrip(".") in self.ad)

    def dnssec_validated(self, name: str) -> bool | None:
        return name.lower().rstrip(".") in self.ad


def load_static(path: str) -> StaticResolver:
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    return StaticResolver(payload.get("queries", {}), payload.get("ad", []))
