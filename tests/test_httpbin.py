# coding=utf-8
import json
from flask import Response
import requests

from .base_class import ZmirrorTestBase
from .utils import env, headers, DEFAULT_USER_AGENT, load_rv_json, var_attributes_value_to_text


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

        # developer_do_not_verify_ssl = True
        # is_use_proxy = True
        # requests_proxies = dict(
        #     http='http://127.0.0.1:8882',
        #     https='https://127.0.0.1:8882',
        # )

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
        with self.app.test_client() as c:
            rv = c.get(
                self.url("/headers"),
                environ_base=env(),
                headers=headers(
                    accept_encoding="gzip, deflate, sdch, br",
                    others={
                        "Host": self.C.my_host_name,
                        "Referer": self.url("/extdomains/eu.httpbin.org/headers"),
                        "Cookie": "_ga=GA1.2.1161994079.1471765883",
                        "Hello-World": "love_luciaz",
                    }),
            )

            # 黑盒检查
            parse_values = var_attributes_value_to_text(self.zmirror.parse)
            self.assertEqual("application/json", self.zmirror.parse.content_type)

            self.assertEqual(
                "gzip, deflate",
                self.zmirror.parse.client_header['accept-encoding'],
                msg=parse_values
            )
            self.assertEqual(
                "https://eu.httpbin.org/headers",
                self.zmirror.parse.client_header['referer'],
                msg=parse_values
            )
            self.assertEqual(
                "love_luciaz",
                self.zmirror.parse.client_header['hello-world'],
                msg=parse_values
            )
            self.assertEqual("httpbin.org", self.zmirror.parse.remote_domain)
            self.assertEqual("/headers", self.zmirror.parse.remote_path)

            remote_resp = self.zmirror.parse.remote_response  # type: requests.Response
            remote_resp_json = json.loads(remote_resp.text)  # type: dict
            self.assertEqual(self.C.target_domain, remote_resp_json['headers']['Host'])

            # 白盒检查
            h = load_rv_json(rv)['headers']
            self.assertEqual(self.C.my_host_name, h['Host'], msg=h)
            self.assertEqual("https://eu.httpbin.org/headers", h['Referer'], msg=h)
            self.assertEqual("_ga=GA1.2.1161994079.1471765883", h['Cookie'], msg=h)
            self.assertEqual("love_luciaz", h['Hello-World'], msg=h)
            self.assertEqual("gzip, deflate", h['Accept-Encoding'], msg=h)

    def test_thread_local_var(self):
        """https://httpbin.org/"""
        with self.app.test_client() as c:
            rv = c.get(self.url("/"), environ_base=env())

            print(dir(self.zmirror.parse))
            print(self.zmirror.parse.remote_domain)

            assert isinstance(rv, Response)
            self.assertIn(b'httpbin', rv.data)
