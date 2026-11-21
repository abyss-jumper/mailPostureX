import unittest

from mailposture.doh import DoHResolver, StaticResolver, _unquote_txt


class TxtParsingTests(unittest.TestCase):
    def test_single_chunk(self):
        self.assertEqual(_unquote_txt('"v=spf1 -all"'), "v=spf1 -all")

    def test_multiple_chunks_are_joined(self):
        self.assertEqual(_unquote_txt('"v=spf1 " "include:a.test " "-all"'),
                         "v=spf1 include:a.test -all")

    def test_unquoted_passthrough(self):
        self.assertEqual(_unquote_txt("plain text"), "plain text")

    def test_escaped_quote(self):
        self.assertEqual(_unquote_txt(r'"a\"b"'), 'a"b')


class StaticResolverTests(unittest.TestCase):
    def setUp(self):
        self.resolver = StaticResolver({
            "example.com|TXT": ["v=spf1 -all"],
            "example.com|MX": ["10 mail.example.com.", "20 backup.example.com."],
            "mail.example.com|A": ["192.0.2.1"],
        })

    def test_txt(self):
        self.assertEqual(self.resolver.txt("example.com"), ["v=spf1 -all"])

    def test_mx_sorted_by_record_order(self):
        self.assertEqual(self.resolver.mx("example.com"),
                         [(10, "mail.example.com"), (20, "backup.example.com")])

    def test_missing_key_is_nxdomain(self):
        self.assertEqual(self.resolver.query("nope.test", "TXT").status, 3)

    def test_present_empty_key_is_nodata(self):
        resolver = StaticResolver({"example.com|TXT": []})
        result = resolver.query("example.com", "TXT")
        self.assertEqual(result.status, 0)
        self.assertEqual(result.records, [])

    def test_dnssec_flag(self):
        resolver = StaticResolver({}, ad=["example.com"])
        self.assertTrue(resolver.dnssec_validated("example.com."))


class DoHResolverTests(unittest.TestCase):
    def test_parses_payload_and_filters_cname(self):
        payload = {
            "Status": 0,
            "AD": True,
            "Answer": [
                {"name": "www.example.com", "type": 5, "TTL": 60,
                 "data": "example.com."},
                {"name": "example.com", "type": 16, "TTL": 60,
                 "data": '"v=spf1 -all"'},
            ],
        }
        seen = {}

        def transport(url):
            seen["url"] = url
            return payload

        resolver = DoHResolver(transport=transport)
        self.assertEqual(resolver.txt("example.com"), ["v=spf1 -all"])
        self.assertTrue(resolver.dnssec_validated("example.com"))
        self.assertIn("name=example.com", seen["url"])

    def test_transport_failure_is_servfail(self):
        def transport(url):
            raise OSError("boom")

        resolver = DoHResolver(transport=transport)
        result = resolver.query("example.com", "TXT")
        self.assertEqual(result.status, 2)
        self.assertIn("boom", result.error)

    def test_answers_cached(self):
        calls = []

        def transport(url):
            calls.append(url)
            return {"Status": 0, "Answer": []}

        resolver = DoHResolver(transport=transport)
        resolver.txt("example.com")
        resolver.txt("example.com")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
