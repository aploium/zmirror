# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *


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

        # developer_string_trace = r"http:\\/\\/httpbin.org\\/extdomains\\/httpbin.org\\/4xxx.png?a=238"

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
            req_json = {
                "x": 233,
                "domain1": self.C.my_host_name,
                "domain2": self.C.external_domains[0],
                "url1": "https://eu.httpbin.org/",
                "url2": self.url("/post"),
                "url3": "https://%s/extdomains/eu.httpbin.org/1xxx?a=235" % self.C.my_host_name,
                "url4": "//%s/extdomains/eu.httpbin.org/2xxx?a=236" % self.C.my_host_name,
                "url5": "http://%s/extdomains/eu.httpbin.org/3xxx?a=237" % self.C.my_host_name,
                "url6": "http://%s/extdomains/httpbin.org/4xxx.png?a=238" % self.C.my_host_name,

                "chinese": "吱吱我爱你~ :)",
            }
            for u in range(1, 7):
                req_json["url%dq" % u] = quote_plus(req_json["url%d" % u])
                req_json["url%de" % u] = slash_esc(req_json["url%d" % u])
                req_json["url%deq" % u] = quote_plus(req_json["url%de" % u])

            rv = c.post(
                self.url("/post"),
                environ_base=env(),
                content_type="application/json",
                data=json.dumps(req_json),
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
            print("---------- zmirror_req.headers --------")
            pprint(zmirror_req.headers)
            print("---------- zmirror_req.body --------")
            req_body = json.loads(zmirror_req.body.decode(encoding='utf-8'))  # type: dict
            pprint(json.loads(zmirror_req.body.decode()))

            self.assertEqual("吱吱我爱你~ :)", req_body['chinese'])
            self.assertEqual(self.C.target_domain, req_body['domain1'])
            self.assertEqual(self.C.external_domains[0], req_body['domain2'])

            self.assertEqual("https://eu.httpbin.org/", req_body['url1'])
            self.assertEqual("https://httpbin.org/post", req_body['url2'])
            self.assertEqual("https://eu.httpbin.org/1xxx?a=235", req_body['url3'])
            self.assertEqual("//eu.httpbin.org/2xxx?a=236", req_body['url4'])
            self.assertEqual("https://eu.httpbin.org/3xxx?a=237", req_body['url5'])
            self.assertEqual("https://httpbin.org/4xxx.png?a=238", req_body['url6'])

            print("---------- remote_resp_json --------")
            pprint(remote_resp_json)
            j = remote_resp_json['json']
            self.assertEqual("吱吱我爱你~ :)", j['chinese'])
            self.assertEqual(self.C.target_domain, j['domain1'])
            self.assertEqual(self.C.external_domains[0], j['domain2'])

            self.assertEqual("https://eu.httpbin.org/", j['url1'])
            self.assertEqual("https://httpbin.org/post", j['url2'])
            self.assertEqual("https://eu.httpbin.org/1xxx?a=235", j['url3'])
            self.assertEqual("//eu.httpbin.org/2xxx?a=236", j['url4'])
            self.assertEqual("https://eu.httpbin.org/3xxx?a=237", j['url5'])
            self.assertEqual("https://httpbin.org/4xxx.png?a=238", j['url6'])

            # 黑盒检查
            print("---------- r-data --------")
            print(rv.data.decode())
            r = load_rv_json(rv)
            print("---------- r --------")
            pprint(r)
            r_json = r['json']
            self.assertEqual("application/json", r["headers"]['Content-Type'])
            self.assertEqual(self.C.my_host_name, r["headers"]['Host'])

            self.assertEqual(233, r_json['x'])
            self.assertEqual("吱吱我爱你~ :)", r_json['chinese'])

            self.assertEqual(self.C.my_host_name, r_json['domain1'])
            self.assertEqual(self.C.my_host_name + '/extdomains/' + self.C.external_domains[0], r_json['domain2'])

            # 未加处理的url, 标准答案
            answers = [
                None,
                self.url("/extdomains/eu.httpbin.org/"),
                self.url("/post"),
                self.url("/extdomains/eu.httpbin.org/1xxx?a=235"),
                "//{}/extdomains/eu.httpbin.org/2xxx?a=236".format(self.C.my_host_name),
                self.url("/extdomains/eu.httpbin.org/3xxx?a=237"),
                self.url("/4xxx.png?a=238"),
            ]
            for i in range(1, 7):
                # 未加处理的url
                self.assertEqual(answers[i], r_json['url{}'.format(i)], msg=i)
                # slash_escape 后的 url
                self.assertEqual(slash_esc(answers[i]), r_json['url{}e'.format(i)], msg=i)
                # quote_plus 后的 url
                self.assertEqual(quote_plus(answers[i]), r_json['url{}q'.format(i)], msg=i)
                # 先 slash_escape 再 quote_plus 后的 url
                self.assertEqual(quote_plus(slash_esc(answers[i])), r_json['url{}eq'.format(i)], msg=i)
