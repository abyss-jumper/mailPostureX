import unittest

from mailposture.doh import StaticResolver
from mailposture.spf import SpfEvaluator, parse_record


class ParseTests(unittest.TestCase):
    def test_basic_terms(self):
        terms, modifiers, errors = parse_record(
            "v=spf1 ip4:192.0.2.0/24 include:_spf.test -all")
        self.assertEqual(errors, [])
        self.assertEqual([t.kind for t in terms], ["ip4", "include", "all"])
        self.assertEqual(terms[0].cidr, 24)
        self.assertEqual(terms[2].qualifier, "-")
        self.assertEqual(modifiers, {})

    def test_qualifiers(self):
        terms, _, _ = parse_record("v=spf1 ~all")
        self.assertEqual(terms[0].qualifier, "~")

    def test_redirect_modifier(self):
        terms, modifiers, _ = parse_record("v=spf1 redirect=_spf.test")
        self.assertEqual(terms, [])
        self.assertEqual(modifiers["redirect"], "_spf.test")

    def test_invalid_ip_flagged(self):
        _, _, errors = parse_record("v=spf1 ip4:999.1.1.1 -all")
        self.assertTrue(any("invalid ip4" in e for e in errors))

    def test_ipv6_requires_v6(self):
        _, _, errors = parse_record("v=spf1 ip6:192.0.2.1 -all")
        self.assertTrue(any("invalid ip6" in e for e in errors))

    def test_unknown_mechanism(self):
        _, _, errors = parse_record("v=spf1 frobnicate -all")
        self.assertTrue(any("unknown mechanism" in e for e in errors))

    def test_bad_version(self):
        _, _, errors = parse_record("v=spf2.0 -all")
        self.assertTrue(errors)

    def test_include_without_domain(self):
        _, _, errors = parse_record("v=spf1 include: -all")
        self.assertTrue(any("requires a domain" in e for e in errors))


def resolver_with(spf: str, extra: dict | None = None) -> StaticResolver:
    queries = {"example.com|TXT": [spf]}
    queries.update(extra or {})
    return StaticResolver(queries)


class EvaluationTests(unittest.TestCase):
    def test_no_record(self):
        result = SpfEvaluator(StaticResolver({})).evaluate("example.com")
        self.assertFalse(result.exists)
        self.assertIn("no SPF record", result.errors[0])

    def test_simple_record(self):
        result = SpfEvaluator(resolver_with("v=spf1 -all")).evaluate("example.com")
        self.assertTrue(result.exists)
        self.assertEqual(result.all_qualifier, "-")
        self.assertEqual(result.lookups, 0)

    def test_multiple_records(self):
        resolver = StaticResolver({
            "example.com|TXT": ["v=spf1 -all", "v=spf1 ~all"],
        })
        result = SpfEvaluator(resolver).evaluate("example.com")
        self.assertEqual(result.record_count, 2)
        self.assertTrue(any("multiple" in e for e in result.errors))

    def test_include_counts_as_one_lookup(self):
        resolver = resolver_with(
            "v=spf1 include:_spf.test -all",
            {"_spf.test|TXT": ["v=spf1 ip4:192.0.2.1 -all"]},
        )
        result = SpfEvaluator(resolver).evaluate("example.com")
        self.assertEqual(result.lookups, 1)
        self.assertEqual(result.void_lookups, 0)

    def test_nested_includes_count_toward_limit(self):
        queries = {"example.com|TXT": ["v=spf1 " + " ".join(
            f"include:s{i}.test" for i in range(11)) + " -all"]}
        for i in range(11):
            queries[f"s{i}.test|TXT"] = ["v=spf1 ip4:192.0.2.1 -all"]
        result = SpfEvaluator(StaticResolver(queries)).evaluate("example.com")
        self.assertEqual(result.lookups, 11)
        self.assertTrue(result.lookup_over_budget)

    def test_include_loop_detected(self):
        resolver = StaticResolver({
            "example.com|TXT": ["v=spf1 include:a.test -all"],
            "a.test|TXT": ["v=spf1 include:example.com -all"],
        })
        result = SpfEvaluator(resolver).evaluate("example.com")
        self.assertTrue(any("loop" in e for e in result.errors))

    def test_missing_include_target_is_void(self):
        result = SpfEvaluator(
            resolver_with("v=spf1 include:gone.test -all")
        ).evaluate("example.com")
        self.assertEqual(result.void_lookups, 1)
        self.assertTrue(any("no SPF" in e for e in result.errors))

    def test_mx_mechanism_without_mx_is_void(self):
        result = SpfEvaluator(
            resolver_with("v=spf1 mx -all")
        ).evaluate("example.com")
        self.assertEqual(result.lookups, 1)
        self.assertEqual(result.void_lookups, 1)

    def test_redirect_when_no_all(self):
        resolver = resolver_with(
            "v=spf1 redirect=_spf.test",
            {"_spf.test|TXT": ["v=spf1 -all"]},
        )
        result = SpfEvaluator(resolver).evaluate("example.com")
        self.assertEqual(result.lookups, 1)
        self.assertIsNone(result.all_qualifier)

    def test_macros_are_flagged_not_crashed(self):
        result = SpfEvaluator(
            resolver_with("v=spf1 exists:%{i}._spf.test -all")
        ).evaluate("example.com")
        self.assertTrue(result.macro_usage)


if __name__ == "__main__":
    unittest.main()
