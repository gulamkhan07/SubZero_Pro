import unittest
from enumerator.ip_intel import classify_ip, classify_ips, classify_cname, detect_waf_from_http

class TestIPIntel(unittest.TestCase):
    # 1. Cloudflare WAF
    def test_cloudflare_ip_detection(self):
        # 104.21.5.12 is in Cloudflare's 104.16.0.0/13
        res = classify_ip("104.21.5.12")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Cloudflare WAF")
        self.assertEqual(res["badge_type"], "cloudflare")

    def test_cloudflare_ipv6_detection(self):
        # 2606:4700:4700::1111 is Cloudflare's 2606:4700::/32
        res = classify_ip("2606:4700:4700::1111")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Cloudflare WAF")
        self.assertEqual(res["badge_type"], "cloudflare")

    def test_cloudflare_http_detection(self):
        res = detect_waf_from_http({"cf-ray": "823479124-BOM", "server": "cloudflare"}, "", 403)
        self.assertIsNotNone(res)
        self.assertEqual(res["waf_provider"], "Cloudflare WAF")
        self.assertEqual(res["badge_type"], "cloudflare")
        self.assertTrue(res["is_blocked"])

    # 2. AWS WAF
    def test_aws_waf_ip_detection(self):
        # 54.192.1.1 is in AWS CloudFront/WAF 54.192.0.0/16
        res = classify_ip("54.192.1.1")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "AWS WAF")
        self.assertEqual(res["badge_type"], "aws")

    def test_aws_waf_http_detection(self):
        res = detect_waf_from_http({"x-amz-cf-id": "Abc123xyz=="}, "Request blocked by AWS WAF", 403)
        self.assertIsNotNone(res)
        self.assertEqual(res["waf_provider"], "AWS WAF")
        self.assertEqual(res["badge_type"], "aws")

    # 3. Microsoft Azure WAF
    def test_azure_waf_ip_detection(self):
        # 13.107.246.10 is in Azure Front Door / WAF 13.107.246.0/24
        res = classify_ip("13.107.246.10")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Microsoft Azure WAF")
        self.assertEqual(res["badge_type"], "azure")

    def test_azure_waf_cname_and_http(self):
        cname_res = classify_cname("portal.azurefd.net")
        self.assertIsNotNone(cname_res)
        self.assertEqual(cname_res["waf_provider"], "Microsoft Azure WAF")

        http_res = detect_waf_from_http({"x-azure-ref": "0abcdef"}, "", 403)
        self.assertIsNotNone(http_res)
        self.assertEqual(http_res["waf_provider"], "Microsoft Azure WAF")

    # 4. Google Cloud Armor
    def test_google_cloud_armor_ip_detection(self):
        # 34.120.5.5 is in Google Cloud Armor Anycast 34.120.0.0/16
        res = classify_ip("34.120.5.5")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Google Cloud Armor")
        self.assertEqual(res["badge_type"], "google")

    def test_google_cloud_armor_http(self):
        http_res = detect_waf_from_http({"via": "1.1 google", "server": "GSE"}, "", 403)
        self.assertIsNotNone(http_res)
        self.assertEqual(http_res["waf_provider"], "Google Cloud Armor")

    # 5. Akamai App & API Protector (including nayaraenergy.com IP!)
    def test_akamai_ip_detection_nayara(self):
        # 23.215.55.173 is nayaraenergy.com's live IP in 23.192.0.0/10
        res = classify_ip("23.215.55.173")
        self.assertTrue(res["is_cdn"])
        self.assertFalse(res["is_origin"])
        self.assertEqual(res["waf_provider"], "Akamai App & API Protector")
        self.assertEqual(res["badge_type"], "akamai")

    def test_akamai_http_grn_header(self):
        # Akamai-GRN header received from nayaraenergy.com
        res = detect_waf_from_http(
            {"akamai-grn": "0.ba1e3f17.1790073385.509aa65f"},
            "<html><head><title>Unauthorized Request Blocked</title></head></html>",
            403
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["waf_provider"], "Akamai App & API Protector")
        self.assertEqual(res["badge_type"], "akamai")
        self.assertTrue(res["is_blocked"])

    # 6. F5 Distributed Cloud WAF
    def test_f5_waf_detection(self):
        # 84.17.65.10 in 84.17.65.0/24
        res = classify_ip("84.17.65.10")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "F5 Distributed Cloud WAF")
        self.assertEqual(res["badge_type"], "f5")

        cname_res = classify_cname("app.volterra.io")
        self.assertEqual(cname_res["waf_provider"], "F5 Distributed Cloud WAF")

        http_res = detect_waf_from_http({"server": "BigIP"}, "The requested URL was rejected", 403)
        self.assertEqual(http_res["waf_provider"], "F5 Distributed Cloud WAF")

    # 7. Imperva WAF
    def test_imperva_waf_detection(self):
        # 199.83.128.5 in 199.83.128.0/21
        res = classify_ip("199.83.128.5")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "Imperva WAF")
        self.assertEqual(res["badge_type"], "imperva")

        cname_res = classify_cname("test.incapdns.net")
        self.assertEqual(cname_res["waf_provider"], "Imperva WAF")

        http_res = detect_waf_from_http({"x-iinfo": "1-2345-6789"}, "", 403)
        self.assertEqual(http_res["waf_provider"], "Imperva WAF")

    # 8. Fortinet FortiWeb
    def test_fortinet_fortiweb_detection(self):
        # 154.52.1.1 in 154.52.0.0/16
        res = classify_ip("154.52.1.1")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "Fortinet FortiWeb")
        self.assertEqual(res["badge_type"], "fortinet")

        cname_res = classify_cname("site.fortiweb-cloud.com")
        self.assertEqual(cname_res["waf_provider"], "Fortinet FortiWeb")

        http_res = detect_waf_from_http({"server": "FortiWeb"}, "", 403)
        self.assertEqual(http_res["waf_provider"], "Fortinet FortiWeb")

    # 9. Radware Cloud WAF
    def test_radware_waf_detection(self):
        # 192.230.128.5 in 192.230.128.0/18
        res = classify_ip("192.230.128.5")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "Radware Cloud WAF")
        self.assertEqual(res["badge_type"], "radware")

        cname_res = classify_cname("app.cwaf.radware.com")
        self.assertEqual(cname_res["waf_provider"], "Radware Cloud WAF")

        http_res = detect_waf_from_http({"x-rdwr-tag": "test"}, "", 403)
        self.assertEqual(http_res["waf_provider"], "Radware Cloud WAF")

    # Additional Origin & Utility tests
    def test_fastly_ipv6_detection(self):
        res = classify_ip("2a04:4e42::1")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "Fastly CDN")
        self.assertEqual(res["badge_type"], "fastly")

    def test_vercel_and_netlify_detection(self):
        res_vercel = classify_ip("76.76.21.21")
        self.assertTrue(res_vercel["is_cdn"])
        self.assertEqual(res_vercel["waf_provider"], "Vercel Edge")

        res_netlify = classify_ip("75.2.60.5")
        self.assertTrue(res_netlify["is_cdn"])
        self.assertEqual(res_netlify["waf_provider"], "Netlify Edge")

    def test_aws_direct_origin_detection(self):
        res = classify_ip("34.205.12.5")
        self.assertFalse(res["is_cdn"])
        self.assertTrue(res["is_origin"])
        self.assertIn("AWS EC2", res["waf_provider"])
        self.assertEqual(res["badge_type"], "origin")
        self.assertIn("Direct Origin", res["label"])

    def test_empty_or_invalid_ip(self):
        res_empty = classify_ip("")
        self.assertEqual(res_empty["label"], "Unresolved")

        res_invalid = classify_ip("not.an.ip")
        self.assertEqual(res_invalid["label"], "Invalid IP")

    def test_classify_ips_with_cname(self):
        res = classify_ips(["198.51.100.5"], cname="d12345.cloudfront.net")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(res["waf_provider"], "AWS WAF")
        self.assertEqual(res["badge_type"], "aws")

    def test_classify_ips_list(self):
        res = classify_ips(["104.21.5.12", "172.67.182.90"])
        self.assertEqual(res["primary_ip"], "104.21.5.12")
        self.assertTrue(res["is_cdn"])
        self.assertEqual(len(res["all_ips"]), 2)

    # Newly Added Cloud Origin Providers Tests
    def test_new_cloud_origin_providers(self):
        # Vultr (45.76.10.20 in 45.76.0.0/16)
        vultr = classify_ip("45.76.10.20")
        self.assertTrue(vultr["is_origin"])
        self.assertFalse(vultr["is_cdn"])
        self.assertEqual(vultr["waf_provider"], "Vultr")

        # Scaleway (51.15.20.30 in 51.15.0.0/16)
        scaleway = classify_ip("51.15.20.30")
        self.assertTrue(scaleway["is_origin"])
        self.assertEqual(scaleway["waf_provider"], "Scaleway")

        # Tencent Cloud (43.129.5.10 in 43.128.0.0/11)
        tencent = classify_ip("43.129.5.10")
        self.assertTrue(tencent["is_origin"])
        self.assertEqual(tencent["waf_provider"], "Tencent Cloud")

        # Huawei Cloud (119.3.10.5 in 119.3.0.0/16)
        huawei = classify_ip("119.3.10.5")
        self.assertTrue(huawei["is_origin"])
        self.assertEqual(huawei["waf_provider"], "Huawei Cloud")

        # Contabo (161.97.80.12 in 161.97.64.0/18)
        contabo = classify_ip("161.97.80.12")
        self.assertTrue(contabo["is_origin"])
        self.assertEqual(contabo["waf_provider"], "Contabo")

        # Alibaba Cloud (47.90.1.2 in 47.0.0.0/8)
        alibaba = classify_ip("47.90.1.2")
        self.assertTrue(alibaba["is_origin"])
        self.assertEqual(alibaba["waf_provider"], "Alibaba Cloud")

    # Newly Added WAF & CDN CNAME and HTTP Tests
    def test_new_waf_cname_signatures(self):
        self.assertEqual(classify_cname("img.kunluncan.com")["waf_provider"], "Alibaba Cloud CDN")
        self.assertEqual(classify_cname("static.qcloudcdn.com")["waf_provider"], "Tencent Cloud CDN")
        self.assertEqual(classify_cname("web.cdnhwc1.com")["waf_provider"], "Huawei Cloud CDN")
        self.assertEqual(classify_cname("firewall.barracudawaf.com")["waf_provider"], "Barracuda WAF")
        self.assertEqual(classify_cname("gateway.netscaler.com")["waf_provider"], "Citrix NetScaler AppFirewall")
        self.assertEqual(classify_cname("edge.arvancloud.ir")["waf_provider"], "ArvanCloud CDN")

    def test_new_waf_http_signatures(self):
        # Barracuda
        res_barr = detect_waf_from_http({"barra_counter_session": "123"}, "", 200)
        self.assertEqual(res_barr["waf_provider"], "Barracuda WAF")
        self.assertEqual(res_barr["badge_type"], "barracuda")

        # Citrix NetScaler
        res_citrix = detect_waf_from_http({"citrix_ns_id": "xyz"}, "", 200)
        self.assertEqual(res_citrix["waf_provider"], "Citrix NetScaler AppFirewall")
        self.assertEqual(res_citrix["badge_type"], "citrix")

        # Alibaba Cloud
        res_ali = detect_waf_from_http({"eagleeye-traceid": "abc1234"}, "", 200)
        self.assertEqual(res_ali["waf_provider"], "Alibaba Cloud WAF")
        self.assertEqual(res_ali["badge_type"], "alibaba")

        # ArvanCloud
        res_arvan = detect_waf_from_http({"ar-poweredby": "Arvan Cloud"}, "", 200)
        self.assertEqual(res_arvan["waf_provider"], "ArvanCloud CDN")
        self.assertEqual(res_arvan["badge_type"], "arvancloud")

    # Dubai & UAE Sovereign Cloud Origin Providers Tests
    def test_dubai_uae_cloud_origin_providers(self):
        # Moro Hub Cloud (Dubai Govt / DEWA) - 66.220.48.10
        moro = classify_ip("66.220.48.10")
        self.assertTrue(moro["is_origin"])
        self.assertFalse(moro["is_cdn"])
        self.assertIn("Moro Hub", moro["waf_provider"])

        # e& Enterprise Cloud (Etisalat UAE) - 195.229.10.5
        etisalat = classify_ip("195.229.10.5")
        self.assertTrue(etisalat["is_origin"])
        self.assertIn("e& Enterprise", etisalat["waf_provider"])

        # du Enterprise Cloud (EITC UAE) - 80.227.96.15
        du = classify_ip("80.227.96.15")
        self.assertTrue(du["is_origin"])
        self.assertIn("du Enterprise", du["waf_provider"])

        # Core42 / G42 Cloud (UAE Sovereign Cloud) - 185.201.24.50
        g42 = classify_ip("185.201.24.50")
        self.assertTrue(g42["is_origin"])
        self.assertIn("Core42", g42["waf_provider"])

    # Dubai & UAE WAF & CDN Tests (Check Point, Palo Alto, AppTrana, Wallarm, Help AG)
    def test_dubai_uae_waf_detection(self):
        # Check Point CloudGuard WAF
        self.assertEqual(classify_cname("portal.cloudguard.app")["waf_provider"], "Check Point CloudGuard WAF")
        cp_http = detect_waf_from_http({"x-cp-appsec": "1"}, "", 403)
        self.assertEqual(cp_http["waf_provider"], "Check Point CloudGuard WAF")
        self.assertEqual(cp_http["badge_type"], "checkpoint")

        # Palo Alto Prisma WAF
        self.assertEqual(classify_cname("firewall.prismacloud.io")["waf_provider"], "Palo Alto Prisma WAF")
        pa_http = detect_waf_from_http({"x-pan-waf": "blocked"}, "", 403)
        self.assertEqual(pa_http["waf_provider"], "Palo Alto Prisma WAF")
        self.assertEqual(pa_http["badge_type"], "paloalto")

        # AppTrana / Indusface WAF
        self.assertEqual(classify_cname("shop.indusface.net")["waf_provider"], "AppTrana WAF (Indusface)")
        at_http = detect_waf_from_http({"x-indusface-waf": "active"}, "", 200)
        self.assertEqual(at_http["waf_provider"], "AppTrana WAF (Indusface)")
        self.assertEqual(at_http["badge_type"], "apptrana")

        # Wallarm WAF
        self.assertEqual(classify_cname("api.wallarm.com")["waf_provider"], "Wallarm WAF")
        wal_http = detect_waf_from_http({"x-wallarm-attack": "detected"}, "", 403)
        self.assertEqual(wal_http["waf_provider"], "Wallarm WAF")
        self.assertEqual(wal_http["badge_type"], "wallarm")

        # Help AG / e& Managed WAF
        self.assertEqual(classify_cname("bank.helpag.com")["waf_provider"], "Help AG / e& Managed WAF (UAE)")
        hag_http = detect_waf_from_http({"server": "HelpAG-Cloud"}, "", 403)
        self.assertEqual(hag_http["waf_provider"], "Help AG / e& Managed WAF (UAE)")
        self.assertEqual(hag_http["badge_type"], "helpag")

if __name__ == "__main__":
    unittest.main()


