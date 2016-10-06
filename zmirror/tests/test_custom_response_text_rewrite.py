# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *


class TestCustomResponseRewriter(ZmirrorTestBase):
    """testing using https://httpbin.org/"""

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('eu.httpbin.org',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        # verbose_level = 4
        possible_charsets = None

        custom_text_rewriter_enable = True

    def test_homepage(self):
        """https://httpbin.org/"""

        self.rv = self.client.get(self.url("/"), environ_base=env())  # type: Response
        self.assertIn(b'httpbin', self.rv.data, msg=self.dump())

    def test_relative_redirect_to(self):
        """https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%2F"""
        self.rv = self.client.get(
            self.url("/redirect-to"),
            query_string="url=http%3A%2F%2Fexample.com%2F",
            environ_base=env(),
            headers=headers(),
        )  # type: Response

        self.assertIn("example.com", self.rv.location, msg=self.dump())

    def test_relative_redirect_to_2(self):
        """https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%2F"""
        self.rv = self.client.get(
            self.url("/redirect-to"),
            query_string="url=http%3A%2F%2Feu.httpbin.org%2F",
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        self.assertEqual(self.url("/extdomains/eu.httpbin.org/"), self.rv.location, msg=self.dump())
