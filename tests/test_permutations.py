"""
Unit tests for Subdomain Permutation Engine.
"""
import unittest
from enumerator.permutation_engine import generate_permutations, scan_permutations


class TestPermutationEngine(unittest.TestCase):
    def test_generate_permutations_with_seeds(self):
        root = "example.com"
        seeds = ["api.example.com", "dev.example.com"]
        candidates = generate_permutations(root, seeds, max_candidates=50)
        
        self.assertIsInstance(candidates, list)
        self.assertGreater(len(candidates), 0)
        
        cand_names = [c["candidate"] for c in candidates]
        # Should generate prefixes and suffixes with words like dev, stage, test, api
        self.assertTrue(any("api-" in c or "-api" in c or "api." in c for c in cand_names))
        for c in candidates:
            self.assertTrue(c["candidate"].endswith("example.com"))
            self.assertIn("rule", c)
            self.assertIn("seed", c)

    def test_generate_permutations_empty_seeds_uses_fallbacks(self):
        root = "tesla.com"
        candidates = generate_permutations(root, [], max_candidates=20)
        self.assertIsInstance(candidates, list)
        self.assertGreater(len(candidates), 0)
        for c in candidates:
            self.assertTrue(c["candidate"].endswith("tesla.com"))

    def test_scan_permutations_structure(self):
        res = scan_permutations("example.com", ["api.example.com"], max_candidates=5, max_workers=2)
        self.assertIn("domain", res)
        self.assertIn("total_candidates", res)
        self.assertIn("total_live", res)
        self.assertIn("results", res)
        self.assertEqual(res["developed_by"], "SubZero Community")


if __name__ == '__main__':
    unittest.main()
