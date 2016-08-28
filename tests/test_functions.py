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

    def test_cache_clean(self):
        self.reload_zmirror({"enable_keep_alive_per_domain": True})
        self.zmirror.cache_clean(is_force_flush=True)

    def test_cron_task_container(self):
        self.zmirror.cron_task_container(dict(
            target=print,
        ))

    def test_try_match_and_add_domain_to_rewrite_white_list(self):
        self.assertFalse(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org"))
        self.assertTrue(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org", force_add=True))
        self.reload_zmirror({"enable_automatic_domains_whitelist": True,
                             "domains_whitelist_auto_add_glob_list": ('*.httpbin.org')}
                            )
        self.assertTrue(self.zmirror.try_match_and_add_domain_to_rewrite_white_list("www2.httpbin.org"))

    def test_add_temporary_domain_alias(self):
        self.zmirror.add_temporary_domain_alias("non-exist1.httpbin.org", "non-exist2.httpbin.org")

    def test_get_ext_domain_inurl_scheme_prefix(self):
        self.assertEqual("", self.zmirror.get_ext_domain_inurl_scheme_prefix("x"))

    def test_decode_mirror_url(self):
        result = self.zmirror.decode_mirror_url(self.url("/extdomains/eu.httpbin.org/233.html?x=3"))
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
