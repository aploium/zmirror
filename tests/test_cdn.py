# coding=utf-8
import json
from zlib import crc32
from pprint import pprint
from urllib.parse import quote_plus, unquote_plus
import requests
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import *


class TestCDN(ZmirrorTestBase):
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
        possible_charsets = None

        enable_static_resource_CDN = True
        CDN_domains = ("cdn1.zmirror-unittest.com",
                       "cdn2.zmirror-unittest.com",
                       "cdn3.zmirror-unittest.com"
                       )

    def test_img_cdn(self):
        """测试使用CDN的图片 https://httpbin.org/image/jpeg"""
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/jpeg"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/jpeg", self.rv.content_type, msg=self.dump())
        self.assertEqual(200, self.rv.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv.data), msg=self.dump())

        with self.app.test_client() as c:
            # 第二次请求, 会重定向到CDN
            self.rv2 = c.get(
                self.url("/image/jpeg"),
                environ_base=env(),
                headers=headers()
            )  # type: Response

            self.assertEqual(  # 此时应出现重定向
                self.zmirror.cdn_redirect_code_if_cannot_hard_rewrite
                , self.rv2.status_code, msg=self.dump()
            )
            self.assertEqual(
                "https://cdn2.zmirror-unittest.com/image/jpeg",
                self.rv2.location, msg=self.dump()
            )

        with self.app.test_client() as c:
            # 改变URL, 理论上这个应该不会应用CDN
            self.rv2 = c.get(
                self.url("/image/jpeg?q=2"),
                environ_base=env(),
                headers=headers()
            )  # type: Response

            self.assertEqual("image/jpeg", self.rv2.content_type, msg=self.dump())
            self.assertEqual(200, self.rv2.status_code, msg=self.dump())
            self.assertEqual(0x97ca823f, crc32(self.rv2.data), msg=self.dump())

        with self.app.test_client() as c:
            # 改变URL, 由于url的hash不同, 会被分配到 cdn3
            self.rv2 = c.get(
                self.url("/image/jpeg?q=2"),
                environ_base=env(),
                headers=headers()
            )  # type: Response

            self.assertEqual(  # 此时应出现重定向
                self.zmirror.cdn_redirect_code_if_cannot_hard_rewrite
                , self.rv2.status_code, msg=self.dump())
            self.assertEqual(
                # 查询参数会被编码进url
                "https://cdn3.zmirror-unittest.com/image/jpeg_{salt}_.cT0y._{salt}_.jpg".format(
                    salt=self.zmirror.cdn_url_query_encode_salt
                ),
                self.rv2.location, msg=self.dump()
            )

    def test_long_query_str_encode_compress(self):
        """当查询串过长时, 会进行gzip压缩"""

        query_str = "a=" + rand_unicode(50) + "&b=" + rand_unicode(50)
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/jpeg"),
            query_string=query_str,
            environ_base=env(),
            headers=headers(),
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/jpeg", self.rv.content_type, msg=self.dump())
        self.assertEqual(200, self.rv.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv.data), msg=self.dump())

        with self.app.test_client() as c:
            # 改变URL, 会触发CDN, 并且带有返回编码并压缩后的查询串
            self.rv2 = c.get(
                self.url("/image/jpeg"),
                query_string=query_str,
                environ_base=env(),
                headers=headers(),
            )  # type: Response

            self.assertEqual(  # 此时应出现重定向
                self.zmirror.cdn_redirect_code_if_cannot_hard_rewrite
                , self.rv2.status_code, msg=self.dump())
            self.assertIn(
                "/image/jpeg_{salt}z_.".format(salt=self.zmirror.cdn_url_query_encode_salt),
                self.rv2.location, msg=self.dump())

        # 使用白名单中的UA请求, 此时应该不进行CDN重定向, 而直接返回图片本体
        self.rv3 = self.client.get(
            self.rv2.location,
            environ_base=env(),
            headers=headers(
                user_agent=DEFAULT_USER_AGENT + " " + self.zmirror.spider_ua_white_list[0]
            )
        )  # type: Response
        self.assertEqual("image/jpeg", self.rv3.content_type, msg=self.dump())
        self.assertEqual(200, self.rv3.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv3.data), msg=self.dump())

    def test_cdn_excluded_ua(self):
        """测试不进行CDN重定向的UA (通常为CDN提供商的内容抓取爬虫)"""
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/jpeg?love=luciaz"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/jpeg", self.rv.content_type, msg=self.dump())
        self.assertEqual(200, self.rv.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv.data), msg=self.dump())

        # 出现CDN重定向的第二次请求
        self.rv2 = self.client.get(
            self.url("/image/jpeg?love=luciaz"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        self.assertEqual(  # 此时应出现重定向
            self.zmirror.cdn_redirect_code_if_cannot_hard_rewrite
            , self.rv2.status_code, msg=self.dump())
        self.assertEqual(
            # 查询参数会被编码进url
            "https://cdn3.zmirror-unittest.com/image/jpeg_{salt}_.bG92ZT1sdWNpYXo=._{salt}_.jpg".format(
                salt=self.zmirror.cdn_url_query_encode_salt
            ),
            self.rv2.location, msg=self.dump()
        )

        # 使用白名单中的UA请求, 此时应该不进行CDN重定向, 而直接返回图片本体
        self.rv3 = self.client.get(
            self.url("/image/jpeg?love=luciaz"),
            environ_base=env(),
            headers=headers(
                user_agent=DEFAULT_USER_AGENT + " " + self.zmirror.spider_ua_white_list[0]
            )
        )  # type: Response

        self.assertEqual("image/jpeg", self.rv3.content_type, msg=self.dump())
        self.assertEqual(200, self.rv3.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv3.data), msg=self.dump())

        # 使用白名单中的UA请求 编码后的图片url, 同样应该返回图片本体
        rv4 = self.client.get(
            self.url("/image/jpeg_{salt}_.bG92ZT1sdWNpYXo=._{salt}_.jpg"
                     .format(salt=self.zmirror.cdn_url_query_encode_salt)
                     ),
            environ_base=env(),
            headers=headers(
                user_agent=DEFAULT_USER_AGENT + " " + self.zmirror.spider_ua_white_list[0]
            )
        )  # type: Response

        self.assertEqual("image/jpeg", rv4.content_type, msg=self.dump())
        self.assertEqual(200, rv4.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(rv4.data), msg=self.dump())

    def test_img_cdn_hard_rewrite(self):
        """测试重写html中CDN的链接 https://httpbin.org/"""
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/jpeg"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/jpeg", self.rv.content_type, msg=self.dump())
        self.assertEqual(200, self.rv.status_code, msg=self.dump())
        self.assertEqual(0x97ca823f, crc32(self.rv.data), msg=self.dump())

        with self.app.test_client() as c:
            # 请求包含 https://httpbin.org/image/jpeg 的页面, 其中这张图片的链接会被重写成CDN
            self.rv2 = c.get(
                self.url("/base64/PGltZyBzcmM9Imh0dHBzOi8vaHR0cGJpbi5vcmcvaW1hZ2UvanBlZyI+Cg=="),
                environ_base=env(),
                headers=headers()
            )  # type: Response
            self.assertIn(b"cdn2.zmirror-unittest.com/image/jpeg", self.rv2.data, msg=self.dump())

    def test_img_cdn_too_small(self):
        """测试一个由于体积过小, 而不进入CDN的图片
        测试使用 https://httpbin.org/image/png 这个图片只有8KB,
        小于使用CDN的阈值(默认10KB), 所以它不会进入CDN
        """
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/png"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/png", self.rv.content_type, msg=self.dump())
        self.assertIn(b'\x89PNG', self.rv.data, msg=self.dump())
        self.assertEqual(8090, len(self.rv.data), msg=self.dump())

        with self.app.test_client() as c:
            # 第二次请求, 由于图片太小, 也不会使用CDN
            self.rv2 = c.get(
                self.url("/image/png"),
                environ_base=env(),
                headers=headers()
            )  # type: Response

            self.assertEqual(200, self.rv2.status_code, msg=self.dump())  # 应该返回200, 而不是重定向
            self.assertEqual("image/png", self.rv2.content_type, msg=self.dump())
            self.assertEqual(self.rv.data, self.rv2.data, msg=self.dump())

    def test_small_img_cdn_hard_rewrite(self):
        """测试上面那个由于体积过小, 而不进入软CDN的PNG图片, 而会被硬重写"""
        # 第一次请求, 没有使用CDN
        self.rv = self.client.get(
            self.url("/image/png"),
            environ_base=env(),
            headers=headers()
        )  # type: Response

        # 由于flaks的惰性, 需要先实际获取一次结果, 缓存才能实际被存储生效
        self.assertEqual("image/png", self.rv.content_type, msg=self.dump())
        self.assertIn(b'\x89PNG', self.rv.data, msg=self.dump())
        self.assertEqual(8090, len(self.rv.data), msg=self.dump())

        with self.app.test_client() as c:
            # 请求包含 https://httpbin.org/image/png 的页面, 其中这张图片的链接会被重写成CDN
            self.rv2 = c.get(
                self.url("/base64/PGltZyBzcmM9Imh0dHBzOi8vaHR0cGJpbi5vcmcvaW1hZ2UvcG5nIj4K"),
                environ_base=env(),
                headers=headers()
            )  # type: Response
            self.assertIn(b"cdn2.zmirror-unittest.com/image/png", self.rv2.data, msg=self.dump())
