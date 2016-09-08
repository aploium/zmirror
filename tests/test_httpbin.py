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
        # verbose_level = 4
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

        self.rv = self.client.get(
            self.url("/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        self.assertIn(b'httpbin', self.rv.data, msg=self.dump())

    def test__enable_keep_alive_per_domain(self):
        """https://httpbin.org/"""
        self.reload_zmirror({"enable_keep_alive_per_domain": True})

        self.rv = self.client.get(
            self.url("/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        self.assertIn(b'httpbin', self.rv.data, msg=self.dump())

    def test_main_domain_as_external(self):
        self.rv = self.client.get(
            self.url("/extdomains//" + self.C.target_domain),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        self.assertEqual(307, self.rv.status_code, self.dump())

    def test_main_domain_as_external_with_end_slash(self):
        self.rv = self.client.get(
            self.url("/extdomains/" + self.C.target_domain + "/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        self.assertEqual(307, self.rv.status_code, self.dump())

    def test_user_agent(self):
        """https://httpbin.org/user-agent"""

        self.rv = self.client.get(
            self.url("/user-agent"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response

        self.assertEqual(load_rv_json(self.rv)['user-agent'], DEFAULT_USER_AGENT, msg=self.dump())

    def test_headers(self):
        """https://httpbin.org/headers"""
        with self.app.test_client() as c:
            self.rv = c.get(
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
            )  # type: Response

            # 白盒检查
            parse_values = attributes(self.zmirror.parse)
            self.assertEqual("application/json", self.zmirror.parse.content_type, msg=self.dump())

            self.assertEqual(
                "gzip, deflate",
                self.zmirror.parse.client_header['accept-encoding'],
                msg=parse_values
            )
            self.assertEqual(
                "https://eu.httpbin.org/headers",
                self.zmirror.parse.client_header['referer'],
                msg=self.dump()
            )
            self.assertEqual(
                "love_luciaz",
                self.zmirror.parse.client_header['hello-world'],
                msg=self.dump()
            )
            self.assertEqual("httpbin.org", self.zmirror.parse.remote_domain, msg=self.dump())
            self.assertEqual("/headers", self.zmirror.parse.remote_path, msg=self.dump())

            remote_resp = self.zmirror.parse.remote_response  # type: requests.Response
            remote_resp_json = json.loads(remote_resp.text)  # type: dict
            self.assertEqual(self.C.target_domain, remote_resp_json['headers']['Host'], msg=self.dump())

            # 黑盒检查
            h = load_rv_json(self.rv)['headers']
            self.assertEqual(self.C.my_host_name, h['Host'], msg=self.dump())
            self.assertEqual(self.url("/extdomains/eu.httpbin.org/headers"), h['Referer'], msg=self.dump())
            self.assertEqual("_ga=GA1.2.1161994079.1471765883", h['Cookie'], msg=self.dump())
            self.assertEqual("love_luciaz", h['Hello-World'], msg=self.dump())
            self.assertEqual("gzip, deflate", h['Accept-Encoding'], msg=self.dump())

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

            self.rv = c.post(
                self.url("/post"),
                environ_base=env(),
                content_type="application/json",
                data=json.dumps(req_json),
                headers=headers(
                    others={
                        "Accept": "application/json",
                    }
                ),
            )  # type: Response

            # 白盒检查
            parse_values = attributes(self.zmirror.parse)
            remote_resp = self.zmirror.parse.remote_response  # type: requests.Response
            remote_resp_json = json.loads(remote_resp.text)  # type: dict
            zmirror_req = remote_resp.request  # type: requests.PreparedRequest

            self.assertEqual(
                "application/json",
                self.zmirror.parse.client_header['content-type'],
                msg=self.dump()
            )

            # print(parse_values)
            # print("---------- zmirror_req.headers --------")
            # pprint(zmirror_req.headers)
            # print("---------- zmirror_req.body --------")
            req_body = json.loads(zmirror_req.body.decode(encoding='utf-8'))  # type: dict
            # pprint(json.loads(zmirror_req.body.decode()))

            self.assertEqual("吱吱我爱你~ :)", req_body['chinese'], msg=self.dump())
            self.assertEqual(self.C.target_domain, req_body['domain1'], msg=self.dump())
            self.assertEqual(self.C.external_domains[0], req_body['domain2'], msg=self.dump())

            self.assertEqual("https://eu.httpbin.org/", req_body['url1'], msg=self.dump())
            self.assertEqual("https://httpbin.org/post", req_body['url2'], msg=self.dump())
            self.assertEqual("https://eu.httpbin.org/1xxx?a=235", req_body['url3'], msg=self.dump())
            self.assertEqual("//eu.httpbin.org/2xxx?a=236", req_body['url4'], msg=self.dump())
            self.assertEqual("https://eu.httpbin.org/3xxx?a=237", req_body['url5'], msg=self.dump())
            self.assertEqual("https://httpbin.org/4xxx.png?a=238", req_body['url6'], msg=self.dump())

            # print("---------- remote_resp_json --------")
            # pprint(remote_resp_json)
            j = remote_resp_json['json']
            self.assertEqual("吱吱我爱你~ :)", j['chinese'], msg=self.dump())
            self.assertEqual(self.C.target_domain, j['domain1'], msg=self.dump())
            self.assertEqual(self.C.external_domains[0], j['domain2'], msg=self.dump())

            self.assertEqual("https://eu.httpbin.org/", j['url1'], msg=self.dump())
            self.assertEqual("https://httpbin.org/post", j['url2'], msg=self.dump())
            self.assertEqual("https://eu.httpbin.org/1xxx?a=235", j['url3'], msg=self.dump())
            self.assertEqual("//eu.httpbin.org/2xxx?a=236", j['url4'], msg=self.dump())
            self.assertEqual("https://eu.httpbin.org/3xxx?a=237", j['url5'], msg=self.dump())
            self.assertEqual("https://httpbin.org/4xxx.png?a=238", j['url6'], msg=self.dump())

            # 黑盒检查
            # print("---------- r-data --------")
            # print(self.rv.data.decode())
            r = load_rv_json(self.rv)
            # print("---------- r --------")
            # pprint(r)
            r_json = r['json']
            self.assertEqual("application/json", r["headers"]['Content-Type'], msg=self.dump())
            self.assertEqual(self.C.my_host_name, r["headers"]['Host'], msg=self.dump())

            self.assertEqual(233, r_json['x'], msg=self.dump())
            self.assertEqual("吱吱我爱你~ :)", r_json['chinese'], msg=self.dump())

            self.assertEqual(self.C.my_host_name, r_json['domain1'], msg=self.dump())
            self.assertEqual(self.C.my_host_name + '/extdomains/' + self.C.external_domains[0], r_json['domain2'],
                             msg=self.dump())

            self.zmirror.dump_zmirror_snapshot()

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
                self.assertEqual(answers[i], r_json['url{}'.format(i)], msg=self.dump())
                # slash_escape 后的 url
                self.assertEqual(slash_esc(answers[i]), r_json['url{}e'.format(i)], msg=self.dump())
                # quote_plus 后的 url
                self.assertEqual(quote_plus(answers[i]), r_json['url{}q'.format(i)], msg=self.dump())
                # 先 slash_escape 再 quote_plus 后的 url
                self.assertEqual(quote_plus(slash_esc(answers[i])), r_json['url{}eq'.format(i)], msg=self.dump())

    def test_remote_set_cookie(self):
        """https://httpbin.org/cookies/set?name=value"""
        self.rv = self.client.get(
            self.url("/cookies/set?k1=value1&k2=value2"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response

        self.assertEqual(2, len(self.rv.headers.get_all("Set-Cookie")), msg=self.dump())
        for set_cookie_header in self.rv.headers.get_all("Set-Cookie"):
            if not ("k1=value1" in set_cookie_header
                    or "k2=value2" in set_cookie_header):
                raise ValueError("cookie set error" + self.dump())
        self.assertEqual(302, self.rv.status_code, msg=self.dump())

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
