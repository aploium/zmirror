# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus, urlencode

from .base_class import ZmirrorTestBase
from .utils import *


class TestCacheSystem(ZmirrorTestBase):
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

        # developer_do_not_verify_ssl = True
        # is_use_proxy = True
        # requests_proxies = dict(
        #     http='http://127.0.0.1:8882',
        #     https='https://127.0.0.1:8882',
        # )

    def setUp(self):
        super().setUp()
        import zmirror.cache_system as cache_system
        self.cache = cache_system.FileCache()

    def tearDown(self):
        if hasattr(self, "cache"):
            self.cache.flush_all()
            del self.cache
        super().tearDown()

    def test_img_cache(self):
        # 第一次请求, 从服务器获取, 没有cache
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
            self.rv2 = c.get(
                self.url("/image/png"),
                environ_base=env(),
                headers=headers()
            )  # type: Response

            self.assertEqual("FileHit", self.rv2.headers.get("x-zmirror-cache"), msg=self.dump())
            self.assertEqual("image/png", self.rv2.content_type, msg=self.dump())
            self.assertEqual(self.rv.data, self.rv2.data, msg=self.dump())

    def test_io_and_many_files(self):
        import os
        from time import time

        start = time()
        for i in range(10000):  # 顺便测试能不能承受大量文件
            obj = os.urandom(16 * 1024)
            self.cache.put_obj(i, obj, info_dict={"bin": obj})
        for i in range(10000):
            info = self.cache.get_info(i)
            obj = self.cache.get_obj(i)
            self.assertEqual(info['bin'], obj)
        print("test_io_and_many_files IO total time:", time() - start)

        # test clean delete
        all_cache_file_path = [v[0] for v in self.cache.items_dict.values()]
        start = time()
        del self.cache
        print("test_io_and_many_files DELETE ALL total time:", time() - start)
        for path in all_cache_file_path:
            self.assertFalse(os.path.exists(path), msg=path)

    def test_cache_system_expire(self):
        from time import sleep
        self.cache.put_obj("x", [233], expires=3)  # 5秒后过期
        self.assertEqual(233, self.cache.get_obj("x")[0])  # 立即获取, 是能成功获取到的
        print("等待5秒..让缓存过期")
        for i in range(5):
            sleep(0.5)
            print(".." + str(4 - i))
            sleep(0.5)
        self.assertIs(None, self.cache.get_obj("x"))  # 此时应该已经被删除了, 返回None

    def test_not_changed(self):
        from time import time
        modify_time = time()
        self.cache.put_obj("x", {2: 3, 3: 3}, last_modified=modify_time)
        self.cache.put_obj("z", b"777")
        self.assertTrue(self.cache.is_unchanged("x", modify_time))

        # 应该返回 False
        self.assertFalse(self.cache.is_unchanged("x", None))
        self.assertFalse(self.cache.is_unchanged("y", None))
        self.assertFalse(self.cache.is_unchanged("z", time()))

    def test_get_info(self):
        self.cache.put_obj("x", [2, 3, 3], info_dict={"name": b"test1"})
        self.assertEqual(b"test1", self.cache.get_info("x")["name"])
        self.assertIs(None, self.cache.get_info("NonExistKey"))

    def test_get_obj_failed(self):
        self.cache.put_obj("x", b"zmirror")
        self.assertEqual(b"zmirror", self.cache.get_obj("x"))  # 保证已经读取成功
        os.remove(self.cache.items_dict["x"][0])  # 删除缓存对应的文件, 导致缓存加载失败
        self.assertIs(None, self.cache.get_obj("x"))  # 由于文件已经删掉, 所以应该是读取失败的
        self.assertIs(None, self.cache.get_obj("NonExistKey"))

    def test_check_all_expire(self):
        from time import sleep
        self.cache.put_obj("x", 235)
        # 强制清空缓存, 效果等效于 cache.flush_all()
        self.cache.check_all_expire(force_flush_all=True)
        self.assertIs(None, self.cache.get_obj("x"))

        for i in range(1, 10):
            self.cache.put_obj(i, "233" * i, expires=1)
            self.cache.put_obj(i + 100, "ZJU")
        sleep(1.6)
        self.cache.check_all_expire()
        for i in range(1, 10):
            self.assertIs(None, self.cache.get_obj(i))
            self.assertEqual("ZJU", self.cache.get_obj(i + 100))
        self.cache.check_all_expire(force_flush_all=True)
        for i in range(1, 10):
            self.assertIs(None, self.cache.get_info(i + 100))
