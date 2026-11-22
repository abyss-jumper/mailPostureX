# mailposture

Audit a domain's email security posture from the outside: SPF, DMARC, DKIM key
hygiene, MX routing, MTA-STS, TLS-RPT, DANE and DNSSEC in one command, with a
grade and an explanation for every point lost.

Zero dependencies. DNS goes over **DoH** (DNS-over-HTTPS) so it works from
locked-down CI runners and containers where outbound UDP/53 is blocked. Nothing
is resolved in the clear.

```text
$ mailposture example.com --demo weak
mailposture · example.com
Grade F     score 41/100     10 finding(s)
========================================================================
[HIGH    ] DMARC005  DMARC policy is p=none
           The record only asks receivers to report. Spoofed mail is still
           delivered to inboxes.
           fix: Move to p=quarantine, then p=reject.

[HIGH    ] SPF004  SPF exceeds the 10-DNS-lookup limit
           11 DNS-querying mechanisms (includes, a, mx, ptr, exists, redirect)
           were counted. Receivers must return permerror once the limit is
           exceeded, which silently disables SPF.
           fix: Flatten or remove nested includes; keep the count at 10 or
           below.

[MEDIUM  ] DKIM004  DKIM key is 1024 bits (default)
           ...
[LOW     ] MAIL010  No MTA-STS record
           ...
[LOW     ] SPF009  SPF ends in ~all (softfail)
           ...
------------------------------------------------------------------------
SPF     v=spf1 include:_spf1.example.com ... include:_spf11.example.com ~all
DMARC   v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=50
MX      10 mail.example.com
DKIM    default:1024bit
SPF DNS lookups  11/10   void 0/2
```

## Install

```bash
git clone https://github.com/abyss-jumper/mailpostureX
cd mailposture
python -m pip install -e .
mailposture example.com           # live audit
mailposture example.com --demo weak   # offline, uses a bundled fixture
```

Python 3.9+, no third-party packages.

## Usage

```bash
mailposture example.com                        # text report
mailposture example.com --format json          # machine-readable
mailposture example.com --format html --out audit.html
mailposture example.com --fetch-policy         # also fetch mta-sts policy over HTTPS
mailposture example.com --selector s2048       # probe a custom DKIM selector
mailposture example.com --min-grade B          # exit 1 if the grade is worse than B
mailposture example.com --doh https://dns.google/dns-query
```

Exit codes: `0` audited, `1` below `--min-grade`, `2` usage or transport failure.

### CI gate

```yaml
- run: pip install git+https://github.com/abyss-jumper/mailpostureX
- run: mailposture example.com --min-grade B --format json --out audit.json
- run: cat audit.json
```

## What gets checked

| area | checks |
|---|---|
| SPF | presence, duplicates, syntax, **recursive lookup budget (10)**, **void lookups (2)**, `+all` / `?all` / `~all`, missing `all`, deprecated `ptr`, include loops, dead include targets |
| DMARC | presence, duplicates, `p=` / `sp=`, `pct<100`, missing `rua`, non-mailto `rua`, relaxed alignment, unknown tags |
| DKIM | key discovery on 20 common selectors, revoked `p=`, key size (`<1024`, `<2048`), `t=y` testing mode, DER parse errors |
| MX | missing MX, null MX (RFC 7505), MX target without A/AAAA |
| transport | MTA-STS TXT + optional live policy fetch (`mode`, `max_age`), TLS-RPT, BIMI presence |
| DNS | DNSSEC authenticated-data flag, DANE/TLSA on MX hosts |

Grading: `critical −30`, `high −15`, `medium −7`, `low −3`, `info 0`, clamped to
`[0, 100]`. `A ≥ 90`, `B ≥ 80`, `C ≥ 70`, `D ≥ 60`, `F` below that.

## The SPF lookup budget

This is the reason the project exists. SPF's 10-lookup limit applies
*recursively*: an `include:` costs one lookup, and every mechanism inside the
included record costs more. Most "SPF checkers" count the top-level tokens and
stop, which is why domains with 6 visible includes can still be at 14 lookups and
silently failing.

`SpfEvaluator` walks the include tree, counts every DNS-querying mechanism
(`include`, `a`, `mx`, `ptr`, `exists`, `redirect`), counts void lookups, tracks
depth, and detects loops. The full tree is available in the JSON output under
`facts.spf.tree`.

```
SPF DNS lookups  11/10   void 0/2
```

## Offline mode

Two fixtures ship with the repo (`data/fixtures/weak.json`, `good.json`) and are
regenerated deterministically by `tools/make_fixtures.py`. The RSA keys in them
are synthetic DER blobs with the right modulus size — structurally useful,
cryptographically worthless.

`--fixture my.json` accepts the same format:

```json
{
  "ad": ["example.com"],
  "queries": {
    "example.com|TXT": ["v=spf1 include:_spf.example.com -all"],
    "example.com|MX": ["10 mail.example.com."],
    "mail.example.com|A": ["192.0.2.1"],
    "_dmarc.example.com|TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
  }
}
```

Absent keys return NXDOMAIN; empty lists return NODATA.

## Design notes

- **DoH JSON API**, not raw DNS: no dependencies, works behind egress proxies.
- **DKIM selectors are not enumerable.** The tool probes 20 common ones and says
  so when it finds nothing; a "missing DKIM" result is a prompt to check, not a
  verdict.
- **MTA-STS policy fetch is opt-in** (`--fetch-policy`) because it makes an
  HTTPS request to the audited domain. The TXT record is always checked.
- **Point-in-time, not compliance.** This is an external observation; it cannot
  see what your MTAs actually sign, nor your internal sending inventory.

## Layout

```
mailposture/
  doh.py      DoH + JSON parsing, static fixture resolver
  spf.py      parser and recursive evaluator (the interesting part)
  dmarc.py    record discovery and tag parsing
  dkim.py     selector probing + key hygiene
  der.py      tiny DER reader for RSA modulus size
  checks.py   all checks, assembled into an Audit
  score.py    findings model + weighted grade
  report.py   text / json / html
  cli.py
tests/        69 unittest cases, no network, no fixtures untouched
tools/make_fixtures.py
```

```bash
python -m unittest discover -s tests -v
python tools/make_fixtures.py
```
