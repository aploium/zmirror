# coding=utf-8
from flask import Response

from .base_class import ZmirrorTestBase


class TestDefaultMirror(ZmirrorTestBase):
    def test_kernel_pages(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        # https://www.kernel.org/
        rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        assert isinstance(rv, Response)
        self.assertIn(b'The Linux Kernel Archives', rv.data)  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', rv.data)  # some rewrite

    def test_kernel_pages_compressed(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        # https://www.kernel.org/
        rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'},
                             headers={"accept-encoding": "gzip, deflate, br"}
                             )
        assert isinstance(rv, Response)
        self.assertIn(b'The Linux Kernel Archives', rv.data)  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', rv.data)  # some rewrite

    def test_kernel_img_get(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.mimetype, 'image/png')
        self.assertGreater(len(rv.data), 2000)  # > 2KB

    def test_kernel_img_get_cache(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        rv = self.client.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.mimetype, 'image/png')
        self.assertGreater(len(rv.data), 2000)  # > 2KB
        print("test_kernel_img_get_cache", rv.headers)

    def test_kernel_css_get(self):
        # https://www.kernel.org/theme/css/main.css
        rv = self.client.get('/theme/css/main.css', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn('text/css', rv.mimetype)
        self.assertIn(b'@import "normalize.css"', rv.data)

    def test_crossdomain_and_status(self):
        rv = self.client.get('/crossdomain.xml', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'cross-domain-policy', rv.data)

        rv = self.client.get('/zmirror_stat', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'extract_real_url_from_embedded_url', rv.data)

    def test_ssrf_prevention(self):
        # example.com, should not allowed
        rv = self.client.get('/extdomains/example.com/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn(b'SSRF Prevention', rv.data)

    def test_spider_deny(self):
        rv = self.client.get('/', headers={'user-agent': 'spider'}, environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.status_code, 403)
        self.assertIn(b'Spiders Are Not Allowed To This Site', rv.data)

    # def test_verification(self):
    #     zmirror.human_ip_verification_enabled = True
    #
    #     rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
    #     self.assertIn(b'ip_ban_verify_page', rv.data)
    #
    #     rv = self.client.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'}, follow_redirects=True)
    #     print(rv.data)
    #     rv = self.client.post('/ip_ban_verify_page', data={"0": "CorrectAnswer",
    #                                                     "student_id": "2333",
    #                                                     "password": "123456",
    #                                                     "origin": "aHR0cDovL2xvY2FsaG9zdC8="},
    #                        environ_base={'REMOTE_ADDR': '1.2.3.4'}, follow_redirects=True
    #                        )
    #     print(rv.data)
