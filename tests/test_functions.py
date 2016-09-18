# coding=utf-8
import json
from zlib import crc32
from pprint import pprint
from urllib.parse import quote_plus, unquote_plus
import requests
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import *


class TestFunctions(ZmirrorTestBase):
    """testing using https://httpbin.org/"""

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('eu.httpbin.org',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        verbose_level = 4
        possible_charsets = None

    def test__cache_clean(self):
        self.reload_zmirror({"enable_keep_alive_per_domain": True})
        self.zmirror.cache_clean(is_force_flush=True)

    def test__cron_task_container(self):
        self.zmirror.cron_task_container(dict(
            target=print,
        ))

    def test__try_match_and_add_domain_to_rewrite_white_list(self):
        self.assertFalse(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org"))
        self.assertTrue(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org", force_add=True))
        self.reload_zmirror({"enable_automatic_domains_whitelist": True,
                             "domains_whitelist_auto_add_glob_list": ('*.httpbin.org',)}
                            )
        self.assertTrue(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org"))

    def test__add_temporary_domain_alias(self):
        self.zmirror.add_temporary_domain_alias("non-exist1.httpbin.org", "non-exist2.httpbin.org")
        self.zmirror.parse.temporary_domain_alias = None
        self.zmirror.add_temporary_domain_alias("non-exist1.httpbin.org", "non-exist2.httpbin.org")

    def test__get_ext_domain_inurl_scheme_prefix(self):
        self.assertEqual("", self.zmirror.get_ext_domain_inurl_scheme_prefix("x"))

    def test__decode_mirror_url(self):
        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org/233.html?x=3"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/233.html?x=3", result["path_query"])
        self.assertEqual("/233.html", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(self.url("/extdomains/https-eu.httpbin.org/233.html?x=3"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/233.html?x=3", result["path_query"])
        self.assertEqual("/233.html", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org/"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org/?x=233&d=a"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/?x=233&d=a", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org?x=233&d=a"))
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual("/?x=233&d=a", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(
            self.url("/extdomains/eu.httpbin.org/233.html?x=3")
                .replace("/", r"\/").replace(".", r"\.")
        )
        self.assertEqual("eu.httpbin.org", result["domain"])
        self.assertEqual(True, result["is_https"])
        self.assertEqual(r'\/233\.html?x=3', result["path_query"])
        self.assertEqual(r"\/233\.html", result["path"])

        result = self.zmirror.decode_mirror_url(
            self.url("/eu.httpbin.org?x=233&d=a"))
        self.assertEqual(self.C.target_domain, result["domain"])
        self.assertEqual("/eu.httpbin.org?x=233&d=a", result["path_query"])
        self.assertEqual("/eu.httpbin.org", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(
            self.url("/?x=233&d=a"))
        self.assertEqual(self.C.target_domain, result["domain"])
        self.assertEqual("/?x=233&d=a", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(
            self.url("//"))
        self.assertEqual(self.C.target_domain, result["domain"])
        self.assertEqual("/", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

        result = self.zmirror.decode_mirror_url(
            self.url("//?x=233"))
        self.assertEqual(self.C.target_domain, result["domain"])
        self.assertEqual("/?x=233", result["path_query"])
        self.assertEqual("/", result["path"])
        self.assertEqual(True, result["is_https"])

    def test__is_ip_not_in_allow_range(self):
        self.reload_zmirror({"human_ip_verification_enabled": True})
        with self.app.test_client() as c:
            c.get("/about_zmirror")
            self.zmirror.ip_whitelist_add("8.7.6.5")
            self.assertFalse(self.zmirror.is_ip_not_in_allow_range("8.7.6.5"))
            self.assertTrue(self.zmirror.is_ip_not_in_allow_range("8.7.6.6"))
            self.assertFalse(self.zmirror.is_ip_not_in_allow_range("127.0.0.1"))

    def test__encode_mirror_url(self):
        self.assertEqual(
            "/extdomains/eu.httpbin.org/foo?x=233",
            self.zmirror.encode_mirror_url("/extdomains/eu.httpbin.org/foo?x=233")
        )
        self.assertEqual(
            "/foo?x=233",
            self.zmirror.encode_mirror_url("/foo?x=233")
        )
        self.assertEqual(
            "/extdomains/eu.httpbin.org/foo?x=233",
            self.zmirror.encode_mirror_url("/foo?x=233", remote_domain="eu.httpbin.org")
        )
        self.assertEqual(
            "//" + self.C.my_host_name + "/extdomains/eu.httpbin.org/foo?x=233",
            self.zmirror.encode_mirror_url("//eu.httpbin.org/foo?x=233")
        )
        self.assertEqual(
            self.C.my_host_scheme + self.C.my_host_name + "/extdomains/eu.httpbin.org/foo?x=233",
            self.zmirror.encode_mirror_url("http://eu.httpbin.org/foo?x=233")
        )
        self.assertEqual(
            "/extdomains/eu.httpbin.org/foo?x=233",
            self.zmirror.encode_mirror_url("http://eu.httpbin.org/foo?x=233", is_scheme=False)
        )
        self.assertEqual(
            slash_esc(self.C.my_host_scheme + self.C.my_host_name + "/extdomains/eu.httpbin.org/foo?x=233"),
            self.zmirror.encode_mirror_url("http://eu.httpbin.org/foo?x=233", is_escape=True)
        )

    def test__is_target_domain_use_https(self):
        self.assertTrue(self.zmirror.is_target_domain_use_https("httpbin.org"))

        self.reload_zmirror({"force_https_domains": {"httpbin.org", "eu.httpbin.org"}})
        self.assertTrue(self.zmirror.is_target_domain_use_https("eu.httpbin.org"))
        self.assertFalse(self.zmirror.is_target_domain_use_https("ex.httpbin.org"))

    def test__add_ssrf_allowed_domain(self):
        self.zmirror.add_ssrf_allowed_domain("www.example.com")
        self.assertIn("www.example.com", self.zmirror.allowed_domains_set)

    def test__check_global_ua_pass(self):
        self.assertFalse(self.zmirror.check_global_ua_pass(None))
        self.assertTrue(self.zmirror.check_global_ua_pass(
            self.zmirror.global_ua_white_name)
        )

    def test__is_content_type_using_cdn(self):
        self.assertTrue(self.zmirror.is_content_type_using_cdn("image/jpg"))
        self.assertFalse(self.zmirror.is_content_type_using_cdn("text/html"))
        self.assertFalse(self.zmirror.is_content_type_using_cdn("text/html; encoding=utf-8"))

    def test__generate_error_page(self):
        with self.app.test_client() as c:
            c.get("/about_zmirror")
            try:
                raise SystemError("dummy error")
            except:
                page = self.zmirror.generate_error_page(is_traceback=True)
            self.assertIsInstance(page, Response)
            self.assertIn(b"dummy error", page.data)

            try:
                raise SystemError("dummy error")
            except:
                page = self.zmirror.generate_error_page(is_traceback=True, content_only=True)
            self.assertIsInstance(page, str)
            self.assertIn("dummy error", page)

            try:
                raise SystemError("dummy error")
            except:
                page = self.zmirror.generate_error_page(content_only=True)
            self.assertIsInstance(page, str)
            self.assertIn("None or not displayed", page)

            self.assertIn(b"hello world", self.zmirror.generate_error_page(
                errormsg=b"hello world"
            ).data)

    def test__generate_304_response(self):
        self.assertEqual(304, self.zmirror.generate_304_response().status_code)

    def test__is_denied_because_of_spider(self):
        self.assertFalse(self.zmirror.is_denied_because_of_spider("spider-qiniu"))
        self.assertTrue(self.zmirror.is_denied_because_of_spider("baiduSpider"))

    def test__embed_real_url_to_embedded_url(self):
        """https://httpbin.org/get?a=233"""
        self.assertEqual(
            self.url("/get_zm26_.YT0yMzM=._zm26_.jpg"),
            self.zmirror.embed_real_url_to_embedded_url(
                self.url("/get?a=233"), "image/jpeg",
            )
        )
        self.assertEqual(
            slash_esc(self.url("/get_zm26_.YT0yMzM=._zm26_.jpg")),
            self.zmirror.embed_real_url_to_embedded_url(
                self.url("/get?a=233"), "image/jpeg", escape_slash=True,
            )
        )

    def test__encoding_detect(self):
        self.zmirror.force_decode_remote_using_encode = "utf-8"
        self.assertEqual(
            "utf-8",
            self.zmirror.encoding_detect("测试中文".encode(encoding="gbk"))
        )

        self.zmirror.force_decode_remote_using_encode = None
        self.zmirror.possible_charsets = ["gbk", "utf-8"]
        self.assertEqual(
            "utf-8",
            self.zmirror.encoding_detect("测试中文".encode(encoding="utf-8"))
        )

        self.zmirror.possible_charsets = None
        self.zmirror.cchardet_available = False
        self.assertIsNone(self.zmirror.encoding_detect("测试中文".encode(encoding="utf-8")))

    def test__get_group(self):
        import re
        m = re.match(r"""(?P<non_exist>\d+)?(?P<dog>dog)""", "dog")
        self.assertEqual("", self.zmirror.get_group("non_exist", m))
        self.assertEqual("", self.zmirror.get_group("cat", m))
        self.assertEqual("dog", self.zmirror.get_group("dog", m))

        m = re.match(r"""(?P<non_exist>\d+)?(?P<dog>dog)""", "cat")
        self.assertEqual("", self.zmirror.get_group("non_exist", m))
        self.assertEqual("", self.zmirror.get_group("cat", m))
        self.assertEqual("", self.zmirror.get_group("dog", m))

    def test__guess_colon_from_slash(self):
        self.assertEqual(":", self.zmirror.guess_colon_from_slash("/"))
        self.assertEqual("%253A", self.zmirror.guess_colon_from_slash("%252F"))
        self.assertEqual("%253a", self.zmirror.guess_colon_from_slash("%252f"))
        self.assertEqual("%3A", self.zmirror.guess_colon_from_slash("%2F"))
        self.assertEqual("%3a", self.zmirror.guess_colon_from_slash("%2f"))

    def test__extract_mime_from_content_type(self):
        f = self.zmirror.extract_mime_from_content_type

        self.assertEqual("text/html", f("text/html"))
        self.assertEqual("text/html", f("text/HTML"))
        self.assertEqual("text/html", f("text/html; encoding=utf-8"))
        self.assertEqual("text/html", f("text/html;encoding=utf-8"))
        self.assertEqual("text/html", f("text/HTML;encoding=utf-8"))
