import unittest
from enumerator.ip_intel import classify_ip, classify_ips

class TestIPIntel(unittest.TestCase):
    def test_cloudflare_ip_detection(self):
        # 104.21.5.12 is in Cloudflare's 104.16.0.0/13
        res = classify_ip("104.21.5.12")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Cloudflare WAF")
        self.assertEqual(res["badge_type"], "cloudflare")

    def test_cloudfront_ip_detection(self):
        # 54.192.1.1 is in AWS CloudFront's 54.192.0.0/16
        res = classify_ip("54.192.1.1")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "AWS CloudFront")
        self.assertEqual(res["badge_type"], "cloudfront")

    def test_aws_direct_origin_detection(self):
        # 34.205.12.5 is in AWS EC2's 34.192.0.0/12
        res = classify_ip("34.205.12.5")
        self.assertFalse(res["is_cdn"])
        self.assertTrue(res["is_origin"])
        self.assertIn("AWS EC2", res["waf_provider"])
        self.assertEqual(res["badge_type"], "origin")
        self.assertIn("Direct Origin", res["label"])

    def test_dedicated_custom_origin_ip(self):
        # 198.51.100.5 (documentation IP not in CDN ranges)
        res = classify_ip("198.51.100.5")
        self.assertFalse(res["is_cdn"])
        self.assertTrue(res["is_origin"])
        self.assertEqual(res["badge_type"], "origin")
        self.assertIn("Direct Origin", res["label"])

    def test_empty_or_invalid_ip(self):
        res_empty = classify_ip("")
        self.assertEqual(res_empty["label"], "Unresolved")

        res_invalid = classify_ip("not.an.ip")
        self.assertEqual(res_invalid["label"], "Invalid IP")

    def test_classify_ips_list(self):
        res = classify_ips(["104.21.5.12", "172.67.182.90"])
        self.assertEqual(res["primary_ip"], "104.21.5.12")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(len(res["all_ips"]), 2)

if __name__ == "__main__":
    unittest.main()
