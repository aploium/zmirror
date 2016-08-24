# coding=utf-8
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import env, headers, DEFAULT_USER_AGENT, load_rv_json


class TestHttpbin(ZmirrorTestBase):
    """testing using https://httpbin.org/"""

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('http://eu.httpbin.org/',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        verbose_level = 3
        possible_charsets = None

        developer_do_not_verify_ssl = True
        is_use_proxy = True
        requests_proxies = dict(
            http='http://127.0.0.1:8882',
            https='https://127.0.0.1:8882',
        )

    def test_homepage(self):
        """https://httpbin.org/"""

        rv = self.client.get(self.url("/"), environ_base=env())
        assert isinstance(rv, Response)
        self.assertIn(b'httpbin', rv.data)

    def test_user_agent(self):
        """https://httpbin.org/user-agent"""

        rv = self.client.get(
            self.url("/user-agent"),
            environ_base=env(),
            headers=headers()
        )

        assert isinstance(rv, Response)
        self.assertEqual(load_rv_json(rv)['user-agent'], DEFAULT_USER_AGENT)

    def test_headers(self):
        """https://httpbin.org/headers"""

        rv = self.client.get(
            self.url("/headers"),
            environ_base=env(),
            headers=headers(others={
                "Host": self.C.my_host_name,
                "Referer": self.url("/extdomains/eu.httpbin.org/headers"),
                "Cookie": "_ga=GA1.2.1161994079.1471765883",
                "Hello-World": "love_luciaz",
            }),
        )

        json = load_rv_json(rv)['headers']
        print(json)
        self.assertEqual(self.C.my_host_name, json['Host'], msg=json)
        self.assertEqual("https://eu.httpbin.org/headers", json['Referer'], msg=json)
        self.assertEqual("_ga=GA1.2.1161994079.1471765883", json['Cookie'], msg=json)
        self.assertEqual("love_luciaz", json['Hello-World'], msg=json)

    def test_thread_local_ver(self):
        """https://httpbin.org/"""
        with self.app.test_client() as c:

            rv = c.get(self.url("/"), environ_base=env())

            print(dir(self.zmirror.parse))
            print(self.zmirror.parse.remote_domain)

            assert isinstance(rv, Response)
            self.assertIn(b'httpbin', rv.data)