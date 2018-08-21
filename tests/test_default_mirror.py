# coding=utf-8
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import *


class TestDefaultMirror(ZmirrorTestBase):
    def test_kernel_pages(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        self.reload_zmirror({"developer_string_trace": "/"})
        # https://www.kernel.org/
        self.rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        assert isinstance(self.rv, Response)
        self.assertIn(b'The Linux Kernel Archives', self.rv.data, msg=self.dump())  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', self.rv.data, msg=self.dump())  # some rewrite

        # 下面这句话没有任何作用, 只是为了cover到一行没什么用的代码
        str(self.zmirror)

    def test_kernel_pages_compressed(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        # https://www.kernel.org/
        self.rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'},
                                  headers={"accept-encoding": "gzip, deflate, br"}
                                  )
        assert isinstance(self.rv, Response)
        self.assertIn(b'The Linux Kernel Archives', self.rv.data, msg=self.dump())  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', self.rv.data, msg=self.dump())  # some rewrite

    def test_kernel_img_get(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        self.rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(self.rv.mimetype, 'image/png', msg=self.dump())
        self.assertGreater(len(self.rv.data), 2000, msg=self.dump())  # > 2KB

    def test_kernel_img_get_cache(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        self.rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(self.rv.mimetype, 'image/png', msg=self.dump())
        self.assertGreater(len(self.rv.data), 2000, msg=self.dump())  # > 2KB
        print("test_kernel_img_get_cache", self.rv.headers)

    def test_kernel_css_get(self):
        # https://www.kernel.org/theme/css/main.css
        self.rv = self.client.get('/theme/css/main.css', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn('text/css', self.rv.mimetype, msg=self.dump())
        self.assertIn(b'@import "normalize.css"', self.rv.data, msg=self.dump())

    def test_crossdomain_and_status(self):
        self.rv = self.client.get('/crossdomain.xml', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'cross-domain-policy', self.rv.data, msg=self.dump())

        self.rv = self.client.get('/zmirror_stat', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'extract_real_url_from_embedded_url', self.rv.data, msg=self.dump())

    def test_ssrf_prevention(self):
        # example.com, should not allowed
        self.rv = self.client.get('/extdomains/example.com/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn(b'SSRF Prevention', self.rv.data, msg=self.dump())

    def test_spider_deny(self):
        self.rv = self.client.get('/', headers={'user-agent': 'spider'}, environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(self.rv.status_code, 403, msg=self.dump())
        self.assertIn(b'Spiders Are Not Allowed To This Site', self.rv.data, msg=self.dump())

    def test_about_zmirror(self):
        self.rv = self.client.get('/about_zmirror', headers=headers(), environ_base=env())
        self.assertIn(b"Love Luciaz Forever", self.rv.data, msg=self.dump())

    def test__domains_alias_to_target_domain(self):
        self.reload_zmirror({"domains_alias_to_target_domain": ["example.com"]})
        self.rv = self.client.get("http://example.com/")
        self.assertIn(b"The Linux Kernel Archives", self.rv.data, msg=self.dump())
