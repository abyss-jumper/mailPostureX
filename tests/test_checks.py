import unittest
from pathlib import Path

from mailposture.checks import audit
from mailposture.doh import StaticResolver, load_static

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "data" / "fixtures"


class FixtureAuditTests(unittest.TestCase):
    def test_weak_fixture_fails(self):
        report = audit("example.com", load_static(FIXTURES / "weak.json"))
        self.assertEqual(report.grade, "F")
        ids = {f.id for f in report.findings}
        self.assertIn("SPF004", ids)   # >10 lookups
        self.assertIn("DMARC005", ids)  # p=none
        self.assertIn("DKIM004", ids)  # 1024-bit key
        self.assertIn("MAIL010", ids)  # no MTA-STS

    def test_weak_fixture_lookup_count(self):
        report = audit("example.com", load_static(FIXTURES / "weak.json"))
        self.assertEqual(report.facts["spf"]["lookups"], 11)
        self.assertEqual(report.facts["spf"]["void_lookups"], 0)

    def test_good_fixture_scores_a(self):
        report = audit("example.org", load_static(FIXTURES / "good.json"))
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.score, 100)
        self.assertTrue(report.facts["dnssec"])

    def test_report_serialises(self):
        report = audit("example.com", load_static(FIXTURES / "weak.json"))
        payload = report.as_dict()
        self.assertEqual(payload["grade"], "F")
        self.assertTrue(payload["findings"])
        self.assertEqual(payload["counts"]["high"],
                         sum(1 for f in report.findings if f.severity == "high"))


class MtaStsTests(unittest.TestCase):
    def _resolver(self):
        return StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
            "example.com|MX": ["10 mail.example.com."],
            "mail.example.com|A": ["192.0.2.1"],
            "_dmarc.example.com|TXT": ["v=DMARC1; p=reject; rua=mailto:a@b.test"],
            "_mta-sts.example.com|TXT": ["v=STSv1; id=1"],
            "_smtp._tls.example.com|TXT": ["v=TLSRPTv1; rua=mailto:t@b.test"],
        })

    def test_unreachable_policy(self):
        def boom(url):
            raise OSError("connection refused")

        report = audit("example.com", self._resolver(), fetch_policy=True,
                       policy_fetcher=boom)
        self.assertIn("MAIL012", {f.id for f in report.findings})

    def test_policy_not_enforcing(self):
        report = audit("example.com", self._resolver(), fetch_policy=True,
                       policy_fetcher=lambda url: "mode: testing\nmax_age: 60\n")
        ids = {f.id for f in report.findings}
        self.assertIn("MAIL013", ids)
        self.assertIn("MAIL014", ids)

    def test_enforcing_policy_is_clean(self):
        report = audit("example.com", self._resolver(), fetch_policy=True,
                       policy_fetcher=lambda url: "mode: enforce\nmax_age: 604800\n")
        ids = {f.id for f in report.findings}
        self.assertNotIn("MAIL013", ids)
        self.assertNotIn("MAIL014", ids)


class MailRoutingTests(unittest.TestCase):
    def test_no_mx(self):
        report = audit("example.com", StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
        }))
        self.assertIn("MAIL001", {f.id for f in report.findings})

    def test_null_mx_is_informational(self):
        report = audit("example.com", StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
            "example.com|MX": ["0 ."],
        }))
        ids = {f.id for f in report.findings}
        self.assertIn("MAIL002", ids)
        self.assertNotIn("MAIL001", ids)

    def test_mx_without_address(self):
        report = audit("example.com", StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
            "example.com|MX": ["10 mail.example.com."],
        }))
        self.assertIn("MAIL003", {f.id for f in report.findings})


class DmarcPolicyTests(unittest.TestCase):
    def test_p_none_is_high(self):
        report = audit("example.com", StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
            "_dmarc.example.com|TXT": ["v=DMARC1; p=none"],
        }))
        finding = next(f for f in report.findings if f.id == "DMARC005")
        self.assertEqual(finding.severity, "high")

    def test_missing_dmarc_is_critical(self):
        report = audit("example.com", StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
        }))
        finding = next(f for f in report.findings if f.id == "DMARC001")
        self.assertEqual(finding.severity, "critical")


if __name__ == "__main__":
    unittest.main()
