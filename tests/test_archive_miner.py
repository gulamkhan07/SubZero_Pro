"""
Unit tests for Historical Archive & Wayback URL Miner.
Developed by: Gulam
"""
import unittest
from unittest.mock import patch, MagicMock
from enumerator.archive_miner import mine_archive_urls, _clean_host


class TestArchiveMiner(unittest.TestCase):
    def test_clean_host(self):
        self.assertEqual(_clean_host("sub.example.com:8080"), "sub.example.com")
        self.assertEqual(_clean_host("WWW.EXAMPLE.COM."), "www.example.com")
        self.assertEqual(_clean_host(""), "")

    @patch('enumerator.archive_miner.fetch_wayback_urls')
    @patch('enumerator.archive_miner.fetch_alienvault_urls')
    def test_mine_archive_urls_categorization(self, mock_otx, mock_wayback):
        mock_wayback.return_value = [
            "http://api.example.com/v1/users?token=secret123&redirect=https://login.example.com",
            "https://dev.example.com/.env",
            "http://backup.example.com/db_backup.sql",
            "http://example.com/index.html?id=42&user=admin",
            "http://stage.example.com/wp-config.php"
        ]
        mock_otx.return_value = [
            "http://old.example.com/api/v2/products",
            "http://example.com/.git/config"
        ]

        result = mine_archive_urls("example.com", limit=100)

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["developed_by"], "Gulam")
        self.assertGreater(result["total_urls"], 0)

        # Historical subdomains
        subs = result["historical_subdomains"]
        self.assertIn("api.example.com", subs)
        self.assertIn("dev.example.com", subs)
        self.assertIn("backup.example.com", subs)
        self.assertIn("old.example.com", subs)

        # Sensitive files
        sensitive_urls = [s["url"] for s in result["sensitive_files"]]
        self.assertTrue(any(".env" in u for u in sensitive_urls))
        self.assertTrue(any(".sql" in u for u in sensitive_urls))
        self.assertTrue(any(".git" in u for u in sensitive_urls))
        self.assertTrue(any("wp-config.php" in u for u in sensitive_urls))

        # Parameter URLs
        param_urls = [p["url"] for p in result["parameter_urls"]]
        self.assertTrue(any("token=" in u for u in param_urls))
        self.assertTrue(any("redirect=" in u for u in param_urls))

        # API endpoints
        apis = result["api_endpoints"]
        self.assertTrue(any("/api/v2/" in u or "/v1/" in u for u in apis))


if __name__ == '__main__':
    unittest.main()
