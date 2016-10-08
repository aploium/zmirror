# coding=utf-8
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *


class TestConnectionPool(ZmirrorTestBase):
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

        enable_connection_keep_alive = True

        # developer_string_trace = r"http:\\/\\/httpbin.org\\/extdomains\\/httpbin.org\\/4xxx.png?a=238"

        # developer_do_not_verify_ssl = True
        # is_use_proxy = True
        # requests_proxies = dict(
        #     http='http://127.0.0.1:8882',
        #     https='https://127.0.0.1:8882',
        # )

    def test_keep_alive(self):
        """https://httpbin.org/"""

        self.rv = self.client.head(
            self.url("/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        time_non_alive = self.zmirror.parse.remote_response.elapsed

        max_fail_count = 3
        for _ in range(10):
            self.rv2 = self.client.head(
                self.url("/"),
                environ_base=env(),
                headers=headers(),
            )  # type: Response
            time_alive = self.zmirror.parse.remote_response.elapsed
            print("TestKeepAlive: NonAlive:", time_non_alive, "Alive:", time_alive)
            try:
                self.assertGreater(time_non_alive, time_alive, msg=self.dump())
            except:
                max_fail_count -= 1
                if not max_fail_count:
                    raise

    def test_clear(self):
        self.rv = self.client.head(
            self.url("/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response

        self.zmirror.connection_pool.clear()
        self.zmirror.connection_pool.clear(force_flush=True)
