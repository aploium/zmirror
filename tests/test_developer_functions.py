# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *


class TestDeveloperFunctions(ZmirrorTestBase):
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

    def test__developer_dump_all_traffics(self):
        """https://httpbin.org/"""

        self.reload_zmirror({"developer_dump_all_traffics": True})

        self.client.get(self.url("/"))

        shutil.rmtree(zmirror_file("traffic"))

    def test__developer_temporary_disable_ssrf_prevention(self):
        """http://exmaple.com"""

        self.reload_zmirror({"developer_temporary_disable_ssrf_prevention": True})

        self.rv = self.client.get(self.url("/extdomains/example.com"))
        self.assertIn(b"This domain is established to be used for illustrative", self.rv.data, msg=self.dump())
