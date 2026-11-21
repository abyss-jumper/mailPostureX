import unittest

from mailposture.dmarc import parse
from mailposture.dkim import parse_key
from mailposture.doh import StaticResolver
from mailposture.dmarc import discover

from _keys import spki_b64


class DmarcParseTests(unittest.TestCase):
    def test_full_record(self):
        rec = parse("v=DMARC1; p=reject; sp=quarantine; pct=100; "
                    "rua=mailto:a@b.test; adkim=s; aspf=s")
        self.assertEqual(rec.policy, "reject")
        self.assertEqual(rec.subdomain_policy, "quarantine")
        self.assertEqual(rec.percent, 100)
        self.assertEqual(rec.errors, [])

    def test_none_policy(self):
        rec = parse("v=DMARC1; p=none")
        self.assertEqual(rec.policy, "none")

    def test_pct_is_clamped(self):
        self.assertEqual(parse("v=DMARC1; p=reject; pct=250").percent, 100)
        self.assertEqual(parse("v=DMARC1; p=reject; pct=-1").percent, 0)

    def test_invalid_policy_flagged(self):
        self.assertTrue(parse("v=DMARC1; p=block").errors)

    def test_missing_version_flagged(self):
        self.assertTrue(parse("p=reject").errors)

    def test_unknown_tags_collected(self):
        rec = parse("v=DMARC1; p=reject; frobnicate=1")
        self.assertIn("frobnicate", rec.unknown_tags)

    def test_discover_filters_non_dmarc(self):
        resolver = StaticResolver({
            "_dmarc.example.com|TXT": ["v=spf1 -all", "v=DMARC1; p=reject"],
        })
        raws, records = discover("example.com", resolver)
        self.assertEqual(len(raws), 1)
        self.assertEqual(records[0].policy, "reject")


class DkimParseTests(unittest.TestCase):
    def test_valid_2048_key(self):
        key = parse_key("default", f"v=DKIM1; k=rsa; p={spki_b64(2048)}")
        self.assertEqual(key.key_bits, 2048)
        self.assertFalse(key.revoked)
        self.assertEqual(key.errors, [])

    def test_revoked_key(self):
        key = parse_key("s1", "v=DKIM1; k=rsa; p=")
        self.assertTrue(key.revoked)

    def test_testing_flag(self):
        key = parse_key("s1", f"v=DKIM1; t=y; p={spki_b64(1024)}")
        self.assertTrue(key.testing)

    def test_missing_p(self):
        key = parse_key("s1", "v=DKIM1; k=rsa")
        self.assertTrue(key.revoked)
        self.assertTrue(any("missing p=" in e for e in key.errors))

    def test_bad_base64(self):
        key = parse_key("s1", "v=DKIM1; k=rsa; p=%%%")
        self.assertIsNone(key.key_bits)
        self.assertTrue(key.errors)

    def test_non_rsa(self):
        key = parse_key("s1", "v=DKIM1; k=ed25519; p=abcdef")
        self.assertTrue(any("non-RSA" in e for e in key.errors))


if __name__ == "__main__":
    unittest.main()
