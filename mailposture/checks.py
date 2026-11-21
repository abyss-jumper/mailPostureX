"""The audit itself: every check, in one readable place."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Callable

from .dkim import DEFAULT_SELECTORS, DkimKey, probe
from .dmarc import DmarcRecord, discover as discover_dmarc
from .doh import Resolver
from .score import Audit, Finding
from .spf import SpfEvaluator, SpfResult

USER_AGENT = "mailposture/0.1 (+https://github.com/)"


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------
def spf_findings(spf: SpfResult) -> list[Finding]:
    out: list[Finding] = []
    if not spf.exists:
        return [Finding(
            "SPF001", "high", "No SPF record",
            "The domain publishes no v=spf1 TXT record, so receivers cannot "
            "distinguish your sending infrastructure from anyone else's.",
            "Publish a single SPF record covering every sender, ending in -all.",
            "RFC 7208 §3",
        )]

    if spf.record_count > 1:
        out.append(Finding(
            "SPF002", "high", "Multiple SPF records",
            f"{spf.record_count} SPF records exist; receivers must treat this "
            "as permerror, which means SPF provides no protection.",
            "Merge them into one record.",
            "RFC 7208 §3.2",
        ))
    if spf.errors:
        out.append(Finding(
            "SPF003", "medium", "SPF record problems",
            "; ".join(spf.errors[:6]),
            "Fix the syntax and missing include targets listed above.",
            "RFC 7208 §4.6",
        ))
    if spf.lookup_over_budget:
        out.append(Finding(
            "SPF004", "high", "SPF exceeds the 10-DNS-lookup limit",
            f"{spf.lookups} DNS-querying mechanisms (includes, a, mx, ptr, "
            "exists, redirect) were counted. Receivers must return permerror "
            "once the limit is exceeded, which silently disables SPF.",
            "Flatten or remove nested includes; keep the count at 10 or below.",
            "RFC 7208 §4.6.4",
        ))
    if spf.void_over_budget:
        out.append(Finding(
            "SPF005", "medium", "Too many void SPF lookups",
            f"{spf.void_lookups} mechanisms resolved to no records. RFC 7208 "
            "allows at most two before returning permerror.",
            "Remove mechanisms for domains that no longer exist.",
            "RFC 7208 §4.6.4",
        ))

    all_qualifier = spf.all_qualifier
    if all_qualifier == "+":
        out.append(Finding(
            "SPF006", "critical", "SPF ends in +all",
            "Every host on the internet is an authorised sender. This is worse "
            "than having no SPF record.",
            "Change +all to -all (or at minimum ~all).",
            "RFC 7208 §5.1",
        ))
    elif all_qualifier is None:
        out.append(Finding(
            "SPF007", "medium", "SPF has no all mechanism",
            "Without an all mechanism the default result is neutral, so SPF "
            "does not reject unauthorised senders.",
            "End the record with -all.",
            "RFC 7208 §5.1",
        ))
    elif all_qualifier == "?":
        out.append(Finding(
            "SPF008", "medium", "SPF ends in ?all",
            "A neutral result explicitly abstains from making a decision.",
            "Use -all, or ~all while migrating.",
            "RFC 7208 §5.1",
        ))
    elif all_qualifier == "~":
        out.append(Finding(
            "SPF009", "low", "SPF ends in ~all (softfail)",
            "Softfail marks unauthorised mail but does not reject it. It is a "
            "reasonable migration state, not a destination.",
            "Move to -all once all legitimate senders are covered.",
            "RFC 7208 §5.1",
        ))

    if any(term.kind == "ptr" for term in spf.terms):
        out.append(Finding(
            "SPF010", "low", "SPF uses the ptr mechanism",
            "ptr is deprecated, slow, and unreliable; several receivers ignore it.",
            "Replace ptr with explicit ip4/ip6 or include mechanisms.",
            "RFC 7208 §5.5",
        ))
    if spf.macro_usage:
        out.append(Finding(
            "SPF011", "info", "SPF uses macros",
            "Macros were not expanded by this auditor, so a small part of the "
            "record was not simulated.",
            "Review macro expansions manually.",
            "RFC 7208 §7",
        ))
    return out


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------
def dmarc_findings(raws: list[str], records: list[DmarcRecord]) -> list[Finding]:
    if not raws:
        return [Finding(
            "DMARC001", "critical", "No DMARC record",
            "Without DMARC, anyone can spoof the From: domain and receivers "
            "have no policy to apply. SPF/DKIM become advisory only.",
            "Publish v=DMARC1; p=none; rua=mailto:dmarc@yourdomain as a first "
            "step, then move to p=quarantine and p=reject.",
            "RFC 7489 §6.3",
        )]
    out: list[Finding] = []
    if len(records) > 1:
        out.append(Finding(
            "DMARC002", "high", "Multiple DMARC records",
            "Receivers treat multiple records as invalid, so the policy is "
            "effectively ignored.",
            "Keep exactly one v=DMARC1 record at _dmarc.",
            "RFC 7489 §6.6.3",
        ))

    record = records[0]
    if record.errors:
        out.append(Finding(
            "DMARC003", "medium", "DMARC record problems",
            "; ".join(record.errors),
            "Fix the tags listed above.",
            "RFC 7489 §6.3",
        ))
    if record.unknown_tags:
        out.append(Finding(
            "DMARC004", "info", "Unknown DMARC tags",
            "Unrecognised tags: " + ", ".join(sorted(record.unknown_tags)),
            "Remove typo'd tags; unknown tags may be ignored by receivers.",
            "RFC 7489 §6.3",
        ))

    policy = record.policy
    if policy == "none":
        out.append(Finding(
            "DMARC005", "high", "DMARC policy is p=none",
            "The record only asks receivers to report. Spoofed mail is still "
            "delivered to inboxes.",
            "Move to p=quarantine, then p=reject.",
            "RFC 7489 §6.3",
        ))
    elif policy == "quarantine":
        out.append(Finding(
            "DMARC006", "low", "DMARC policy is p=quarantine",
            "Spoofed mail is sent to spam rather than rejected.",
            "Move to p=reject once reports are clean.",
            "RFC 7489 §6.3",
        ))

    if record.percent < 100:
        out.append(Finding(
            "DMARC007", "medium", f"DMARC applies to only {record.percent}% of mail",
            "pct<100 leaves the remaining percentage unprotected.",
            "Set pct=100 (or remove the tag) after validating reports.",
            "RFC 7489 §6.3",
        ))

    rua = record.get("rua")
    if not rua:
        out.append(Finding(
            "DMARC008", "medium", "No DMARC aggregate reporting address",
            "rua= is absent, so you get no visibility into authentication "
            "failures or spoofing attempts.",
            "Add rua=mailto:dmarc-reports@yourdomain.",
            "RFC 7489 §6.3",
        ))
    elif "mailto:" not in rua.lower():
        out.append(Finding(
            "DMARC009", "low", "DMARC rua is not a mailto: URI",
            "Report URIs must use the mailto: scheme.",
            "Rewrite rua= as a comma-separated list of mailto: URIs.",
            "RFC 7489 §6.2",
        ))

    if "sp" not in record.tags and policy in {"quarantine", "reject"}:
        out.append(Finding(
            "DMARC010", "low", "Subdomains inherit the policy implicitly",
            "Organisational domains often have laxer subdomain senders. An "
            "explicit sp= makes the intent clear.",
            "Add sp=reject (or sp=quarantine) explicitly.",
            "RFC 7489 §6.3",
        ))
    if record.get("adkim", "r").lower() == "r" or record.get("aspf", "r").lower() == "r":
        out.append(Finding(
            "DMARC011", "info", "Relaxed identifier alignment",
            "adkim/aspf relaxed (the default) lets a subdomain of an aligned "
            "domain pass. Strict alignment is tighter.",
            "Consider adkim=s; aspf=s for transactional domains.",
            "RFC 7489 §3.1",
        ))
    return out


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------
def dkim_findings(keys: list[DkimKey], selectors_probed: int) -> list[Finding]:
    out: list[Finding] = []
    for key in keys:
        if key.errors:
            out.append(Finding(
                "DKIM001", "medium", f"DKIM key problems ({key.selector})",
                "; ".join(key.errors),
                "Re-publish a valid DKIM1 TXT record.",
                "RFC 6376 §3.6.1",
            ))
        if key.revoked:
            out.append(Finding(
                "DKIM002", "high", f"DKIM key revoked ({key.selector})",
                "p= is empty, which tells receivers the selector is revoked. "
                "Mail signed with it will fail.",
                "Remove the selector from your MTA config or publish a new key.",
                "RFC 6376 §3.6.1",
            ))
            continue
        if key.key_bits is not None:
            if key.key_bits < 1024:
                out.append(Finding(
                    "DKIM003", "critical",
                    f"DKIM key is only {key.key_bits} bits ({key.selector})",
                    "Keys below 1024 bits are considered factorable.",
                    "Rotate to a 2048-bit RSA key.",
                    "RFC 8301 §3.2",
                ))
            elif key.key_bits < 2048:
                out.append(Finding(
                    "DKIM004", "medium",
                    f"DKIM key is {key.key_bits} bits ({key.selector})",
                    "RFC 8301 requires signers to use at least 1024 bits; 2048 "
                    "is the current recommendation and what most receivers "
                    "expect for long-lived keys.",
                    "Rotate to a 2048-bit key.",
                    "RFC 8301 §3.2",
                ))
        if key.testing:
            out.append(Finding(
                "DKIM005", "low", f"DKIM testing mode enabled ({key.selector})",
                "t=y tells receivers to treat signatures as test traffic.",
                "Remove t=y once the selector is in production.",
                "RFC 6376 §3.6.1",
            ))

    if not keys:
        out.append(Finding(
            "DKIM006", "low", "No DKIM key found on common selectors",
            f"Probed {selectors_probed} well-known selectors and found no key. "
            "DKIM may still be configured on a custom selector — selectors are "
            "not enumerable.",
            "If you sign with DKIM, note your selector in the README or pass "
            "--selector to check it explicitly.",
            "RFC 6376",
        ))
    return out


# ---------------------------------------------------------------------------
# MX / transport / DNS
# ---------------------------------------------------------------------------
def _fetch_https(url: str, timeout: float = 10.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read().decode("utf-8", "replace")


def mx_findings(resolver: Resolver, domain: str,
                mx_hosts: list[tuple[int, str]]) -> list[Finding]:
    out: list[Finding] = []
    if not mx_hosts:
        out.append(Finding(
            "MAIL001", "medium", "No MX records",
            "The domain cannot receive mail and does not declare a null MX. "
            "If the domain should not receive mail, say so explicitly.",
            "Either publish working MX records or a null MX (0 .).",
            "RFC 5321 §5.1",
        ))
        return out

    if any(host in {"", "."} for _, host in mx_hosts):
        out.append(Finding(
            "MAIL002", "info", "Null MX published",
            "0 . declares that this domain does not accept email. That is the "
            "correct way to prevent backscatter for non-mail domains.",
            "No action needed.",
            "RFC 7505",
        ))
        return out

    for _, host in mx_hosts:
        if not resolver.a(host):
            out.append(Finding(
                "MAIL003", "low", f"MX host has no A/AAAA record ({host})",
                "Receivers resolve the MX target before delivering; a missing "
                "address causes temporary failures.",
                "Publish an A/AAAA record or point the MX at a live host.",
                "RFC 5321 §5.1",
            ))
    return out


def transport_findings(resolver: Resolver, domain: str,
                       fetch_policy: bool = False,
                       policy_fetcher: Callable[[str], str] = _fetch_https
                       ) -> tuple[list[Finding], dict]:
    out: list[Finding] = []
    facts: dict = {}

    mta_sts = [t for t in resolver.txt(f"_mta-sts.{domain}")
               if t.lower().startswith("v=stsv1")]
    facts["mta_sts"] = bool(mta_sts)
    if not mta_sts:
        out.append(Finding(
            "MAIL010", "low", "No MTA-STS record",
            "SMTP is opportunistic by default; without MTA-STS a downgrade to "
            "plaintext or a lookalike MX is undetectable.",
            "Publish a _mta-sts TXT record and an enforce policy.",
            "RFC 8461",
        ))
    else:
        record = mta_sts[0]
        if "id=" not in record:
            out.append(Finding(
                "MAIL011", "low", "MTA-STS record has no id=",
                "The id= value is how receivers detect policy changes.",
                "Add id=<version> and bump it whenever the policy changes.",
                "RFC 8461 §3.1",
            ))
        if fetch_policy:
            url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            try:
                body = policy_fetcher(url)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                out.append(Finding(
                    "MAIL012", "medium", "MTA-STS policy is unreachable",
                    f"TXT record exists but {url} failed: {exc}",
                    "Serve the policy over valid HTTPS with the right content type.",
                    "RFC 8461 §3.2",
                ))
            else:
                fields = dict(
                    line.split(":", 1) for line in body.splitlines() if ":" in line
                )
                mode = fields.get("mode", "").strip()
                facts["mta_sts_mode"] = mode
                if mode != "enforce":
                    out.append(Finding(
                        "MAIL013", "high",
                        f"MTA-STS policy mode is {mode or 'missing'}",
                        "Only mode: enforce actually prevents downgrade attacks.",
                        "Set mode: enforce once MX/TLS is stable.",
                        "RFC 8461 §3.2",
                    ))
                try:
                    max_age = int(fields.get("max_age", "0"))
                except ValueError:
                    max_age = 0
                if max_age < 86400:
                    out.append(Finding(
                        "MAIL014", "low", "MTA-STS max_age is short",
                        f"max_age={max_age}s means receivers re-fetch constantly "
                        "and forget the policy quickly.",
                        "Use max_age=604800 (one week) or more.",
                        "RFC 8461 §3.2",
                    ))

    tls_rpt = [t for t in resolver.txt(f"_smtp._tls.{domain}")
               if t.lower().startswith("v=tlsrptv1")]
    facts["tls_rpt"] = bool(tls_rpt)
    if not tls_rpt:
        out.append(Finding(
            "MAIL015", "low", "No TLS-RPT record",
            "Without TLS reporting you cannot see active downgrade attempts.",
            "Add _smtp._tls TXT: v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.",
            "RFC 8460",
        ))

    bimi = resolver.txt(f"default._bimi.{domain}")
    facts["bimi"] = bool(bimi)
    if bimi:
        out.append(Finding(
            "MAIL016", "info", "BIMI record published",
            "Brand indicators are configured.",
            "",
            "RFC 9090 draft",
        ))

    return out, facts


def dns_findings(resolver: Resolver, domain: str,
                 mx_hosts: list[tuple[int, str]]) -> tuple[list[Finding], dict]:
    out: list[Finding] = []
    facts: dict = {}
    validated = resolver.dnssec_validated(domain)
    facts["dnssec"] = validated
    if validated is False:
        out.append(Finding(
            "DNS001", "low", "DNSSEC is not validating",
            "Without DNSSEC, DNS answers can be spoofed in transit, which "
            "undermines MTA-STS, DANE and DMARC discovery alike.",
            "Sign the zone and publish a DS record at the registrar.",
            "RFC 4033",
        ))
    elif validated is True:
        out.append(Finding(
            "DNS002", "info", "DNSSEC validated",
            "The resolver returned the authenticated-data flag for this domain.",
            "",
            "RFC 4035",
        ))

    tlsa_found = False
    for _, host in mx_hosts:
        if host in {"", "."}:
            continue
        for raw in resolver.query(f"_25._tcp.{host}", "TLSA").records:
            tlsa_found = True
            facts.setdefault("tlsa", []).append(f"{host}: {raw.data}")
    if tlsa_found:
        out.append(Finding(
            "DNS003", "info", "DANE TLSA records present",
            "Receivers that validate DNSSEC can pin the MX TLS certificate.",
            "",
            "RFC 7672",
        ))
    return out, facts


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def audit(domain: str, resolver: Resolver,
          selectors: tuple[str, ...] | list[str] = DEFAULT_SELECTORS,
          fetch_policy: bool = False,
          policy_fetcher: Callable[[str], str] = _fetch_https) -> Audit:
    domain = domain.strip().lower().rstrip(".")
    result = Audit(domain=domain)

    spf = SpfEvaluator(resolver).evaluate(domain)
    result.findings += spf_findings(spf)
    result.facts["spf"] = {
        "record": spf.raw,
        "records": spf.record_count,
        "lookups": spf.lookups,
        "void_lookups": spf.void_lookups,
        "all": spf.all_qualifier,
        "tree": spf.tree,
    }

    raws, dmarc_records = discover_dmarc(domain, resolver)
    result.findings += dmarc_findings(raws, dmarc_records)
    result.facts["dmarc"] = {
        "record": raws[0] if raws else "",
        "policy": dmarc_records[0].policy if dmarc_records else None,
        "pct": dmarc_records[0].percent if dmarc_records else None,
        "rua": dmarc_records[0].get("rua") if dmarc_records else "",
    }

    keys = probe(domain, resolver, selectors)
    result.findings += dkim_findings(keys, len(selectors))
    result.facts["dkim"] = [
        {"selector": k.selector, "bits": k.key_bits, "revoked": k.revoked,
         "testing": k.testing}
        for k in keys
    ]

    mx_hosts = resolver.mx(domain)
    result.findings += mx_findings(resolver, domain, mx_hosts)
    result.facts["mx"] = [{"preference": p, "host": h} for p, h in mx_hosts]

    transport, transport_facts = transport_findings(
        resolver, domain, fetch_policy=fetch_policy, policy_fetcher=policy_fetcher)
    result.findings += transport
    result.facts.update(transport_facts)

    dns, dns_facts = dns_findings(resolver, domain, mx_hosts)
    result.findings += dns
    result.facts.update(dns_facts)

    return result
