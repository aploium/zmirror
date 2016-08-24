# coding=utf-8
import json
from pprint import pprint
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
        external_domains = ('eu.httpbin.org',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        verbose_level = 3
        possible_charsets = None

        developer_string_trace = "omains/http://eu.h"

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

            # 白盒检查
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

            # 黑盒检查
            h = load_rv_json(rv)['headers']
            self.assertEqual(self.C.my_host_name, h['Host'], msg=h)
            self.assertEqual(self.url("/extdomains/eu.httpbin.org/headers"), h['Referer'], msg=h)
            self.assertEqual("_ga=GA1.2.1161994079.1471765883", h['Cookie'], msg=h)
            self.assertEqual("love_luciaz", h['Hello-World'], msg=h)
            self.assertEqual("gzip, deflate", h['Accept-Encoding'], msg=h)

    def test_post_json(self):
        """POST https://httpbin.org/post"""

        with self.app.test_client() as c:
            rv = c.post(
                self.url("/post"),
                environ_base=env(),
                content_type="application/json",
                data=json.dumps(
                    {"x": 233,
                     "domain1": self.C.my_host_name,
                     "url1": "http://eu.httpbin.org/",
                     "url2": self.url("/post"),
                     "url3": "https://%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name,
                     "url4": "//%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name,
                     "url5": "http://%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name,
                     "url6": "http://%s/extdomains/httpbin.org/xxx.png?a=235" % self.C.my_host_name,
                     "chinese": "吱吱我爱你~ :)",
                     }
                ),
                headers=headers(
                    others={
                        "Accept": "application/json",
                    }
                ),
            )

            # 白盒检查
            parse_values = var_attributes_value_to_text(self.zmirror.parse)
            remote_resp = self.zmirror.parse.remote_response  # type: requests.Response
            remote_resp_json = json.loads(remote_resp.text)  # type: dict
            zmirror_req = remote_resp.request  # type: requests.PreparedRequest

            self.assertEqual(
                "application/json",
                self.zmirror.parse.client_header['content-type'],
                msg=parse_values
            )

            print(parse_values)
            print("---------- remote_resp_json --------")
            pprint(remote_resp_json)
            print("---------- zmirror_req.headers --------")
            pprint(zmirror_req.headers)
            print("---------- zmirror_req.body --------")
            pprint(json.loads(zmirror_req.body.decode()))

            # 黑盒检查
            r = load_rv_json(rv)
            print("---------- r --------")
            pprint(r)
            r_json = r['json']
            self.assertEqual("吱吱我爱你~ :)", r_json['chinese'])
            self.assertEqual(self.C.my_host_name, r_json['domain1'])

            self.assertEqual("https://%s/extdomains/eu.httpbin.org/" % self.C.my_host_name, r_json['url1'])
            self.assertEqual("https://%s/post" % self.C.my_host_name, r_json['url2'])
            self.assertEqual("https://%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name, r_json['url3'])
            self.assertEqual("https://%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name, r_json['url4'])
            self.assertEqual("https://%s/extdomains/eu.httpbin.org/xxx?a=235" % self.C.my_host_name, r_json['url5'])
            self.assertEqual("https://%s/xxx.png?a=235" % self.C.my_host_name, r_json['url6'])
