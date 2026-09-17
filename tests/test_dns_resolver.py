import unittest
from unittest.mock import Mock, patch
import dns.resolver

from enumerator.dns_resolver import (
    PUBLIC_RESOLVERS,
    check_domain_multi_resolver,
    resolve_batch_multi_resolvers,
    _query_resolver_single,
)


class TestMultiDNSResolver(unittest.TestCase):
    def test_public_resolvers_configuration(self):
        """Verifies that all required public DNS providers are properly registered."""
        providers = {r["provider"] for r in PUBLIC_RESOLVERS}
        expected_providers = {"Cloudflare", "Google", "OpenDNS", "Quad9", "AdGuard", "Control D", "Level3"}
        for expected in expected_providers:
            self.assertIn(expected, providers, f"Missing expected public DNS provider: {expected}")

        # Ensure primary IPs match known Tier-1 anycast addresses
        ip_map = {r["name"]: r["ip"] for r in PUBLIC_RESOLVERS}
        self.assertEqual(ip_map.get("Cloudflare Primary"), "1.1.1.1")
        self.assertEqual(ip_map.get("Google Primary"), "8.8.8.8")
        self.assertEqual(ip_map.get("OpenDNS Primary"), "208.67.222.222")
        self.assertEqual(ip_map.get("Quad9 Primary"), "9.9.9.9")

    def test_empty_host_handling(self):
        """Empty or whitespace hostnames should return unresolved without querying."""
        res = check_domain_multi_resolver("   ")
        self.assertEqual(res["status"], "unresolved")
        self.assertFalse(res["alive"])
        self.assertTrue(res["dead_confirmed"])
        self.assertEqual(res["ips"], [])

    def test_live_domain_resolution(self):
        """Real resolution test for a globally known domain across public resolvers."""
        res = check_domain_multi_resolver("google.com")
        self.assertEqual(res["status"], "resolved")
        self.assertTrue(res["alive"])
        self.assertIsNotNone(res["resolver"])
        self.assertTrue(len(res["ips"]) > 0)
        self.assertFalse(res["dead_confirmed"])

    def test_dead_domain_checks_all_resolvers(self):
        """Non-existent domain must be checked across all configured resolvers before being declared dead."""
        fake_domain = "nonexistent-subdomain-definitelydead-98127394871.test"
        res = check_domain_multi_resolver(fake_domain)
        self.assertEqual(res["status"], "unresolved")
        self.assertFalse(res["alive"])
        self.assertTrue(res["dead_confirmed"])
        self.assertEqual(res["ips"], [])
        # Tested count should encompass the public resolvers and system fallback
        self.assertGreaterEqual(res["tested_count"], len(PUBLIC_RESOLVERS))
        self.assertIn("Cloudflare", "".join(res["checked_resolvers"]))
        self.assertIn("Google", "".join(res["checked_resolvers"]))

    def test_batch_multi_resolver(self):
        """Batch resolution handles multiple hosts with bounded concurrency."""
        hosts = ["google.com", "fake-domain-xyz-12349071234.invalid"]
        results = resolve_batch_multi_resolvers(hosts, max_workers=2)
        self.assertIn("google.com", results)
        self.assertIn("fake-domain-xyz-12349071234.invalid", results)
        self.assertEqual(results["google.com"]["status"], "resolved")
        self.assertEqual(results["fake-domain-xyz-12349071234.invalid"]["status"], "unresolved")

    def test_specific_resolver_selection(self):
        """Allows targeting a specific provider such as Cloudflare or Google."""
        res_cf = check_domain_multi_resolver("google.com", specific_resolver="cloudflare")
        self.assertEqual(res_cf["status"], "resolved")
        self.assertIn("Cloudflare", res_cf["resolver"])

        res_goog = check_domain_multi_resolver("google.com", specific_resolver="google")
        self.assertEqual(res_goog["status"], "resolved")
        self.assertIn("Google", res_goog["resolver"])

        # Targeted query on non-existent domain queries only that provider
        res_fake_cf = check_domain_multi_resolver("nonexistent-test-1234981.xyz", specific_resolver="cloudflare")
        self.assertEqual(res_fake_cf["status"], "unresolved")
        self.assertLessEqual(res_fake_cf["tested_count"], 2)


if __name__ == "__main__":
    unittest.main()
