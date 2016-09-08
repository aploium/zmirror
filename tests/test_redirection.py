# coding=utf-8
import json
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import *


class TestRedirection(ZmirrorTestBase):
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

        url_custom_redirect_enable = True
        url_custom_redirect_list = {
            "/redirect_test": "/get?StarWars=MayTheForceBeWithYou",
        }
        url_custom_redirect_regex = [
            (r'^/the_ultimate_answer/(?P<ans>.*)$', '/get?answer=\g<ans>'),
        ]
        shadow_url_redirect_regex = [
            (r'^/shadow_redirect/(?P<foo>.*)$', '/get?dog=\g<foo>'),
        ]
        plain_replace_domain_alias = [
            ("just-a-non-exist-domain.com", "example.com"),
        ]

    def test_explicit_basic_redirection(self):
        """/redirect_test --> /get?StarWars=MayTheForceBeWithYou"""
        self.rv = self.client.get(
            self.url("/redirect_test"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        self.assertEqual(307, self.rv.status_code, msg=self.dump())
        self.assertIn(self.C.url_custom_redirect_list["/redirect_test"]
                      , self.rv.location, msg=self.dump())

    def test_explicit_regex_redirect(self):
        """/the_ultimate_answer/42 --> /get?answer=42"""
        self.rv = self.client.get(
            self.url("/the_ultimate_answer/42"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        self.assertEqual(307, self.rv.status_code, msg=self.dump())
        self.assertIn("/get?answer=42", self.rv.location, msg=self.dump())

    def test_shadow_regex_redirect(self):
        """/shadow_redirect/furry-dog --> /get?dog=furry-dog"""
        self.rv = self.client.get(
            self.url("/shadow_redirect/furry-dog"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        self.assertEqual(200, self.rv.status_code, msg=self.dump())
        self.assertEqual("/get?dog=furry-dog", self.zmirror.parse.remote_path_query, msg=self.dump())
        print(self.rv.data.decode())
        self.assertEqual(
            "furry-dog",
            json.loads(self.rv.data.decode())["args"].get("dog"),
            msg=self.dump()
        )
