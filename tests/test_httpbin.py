# coding=utf-8
import json
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import env, headers, DEFAULT_USER_AGENT, load_rv_json



class TestHttpbin(ZmirrorTestBase):
    """testing using https://httpbin.org/"""

    class ZmirrorInitConfig(ZmirrorTestBase.ZmirrorInitConfig):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('http://eu.httpbin.org/',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        verbose_level = 3
        possible_charsets = None

    def test_homepage(self):
        """https://httpbin.org/"""

        rv = self.app.get("https://b.test.com/", environ_base=env())
        assert isinstance(rv, Response)
        self.assertIn(b'httpbin', rv.data)

    def test_user_agent(self):
        """https://httpbin.org/user-agent"""

        rv = self.app.get(
            "https://b.test.com/user-agent",
            environ_base=env(),
            headers=headers()
        )

        self.assertEqual(load_rv_json(rv)['user-agent'], DEFAULT_USER_AGENT)
