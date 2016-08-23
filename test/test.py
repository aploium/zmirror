# coding=utf-8
import sys
import os
import unittest
import shutil
import importlib
from time import sleep
from flask import Response

basedir = os.path.dirname(os.path.abspath(__file__))
zmirror_dir = os.path.join(basedir, '..')
sys.path.insert(0, zmirror_dir)


def zmirror_file(filename):
    return os.path.join(zmirror_dir, filename)


class ZmirrorTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(zmirror_file('config.py')):
            print('[Waring] the config.py already exists, it would be temporary renamed to config.py._unittest_raw')
            shutil.move(zmirror_file('config.py'), zmirror_file('config.py._unittest_raw'))

        if os.path.exists(zmirror_file('custom_func.py')):
            print('[Waring] the custom_func.py already exists, it would be temporary renamed to custom_func.py._unittest_raw')
            shutil.move(zmirror_file('custom_func.py'), zmirror_file('custom_func.py._unittest_raw'))

        shutil.copy(zmirror_file('config_default.py'), zmirror_file('config.py'))
        shutil.copy(zmirror_file('custom_func.sample.py'), zmirror_file('custom_func.py'))

        import config
        config.cron_tasks_list.append(
            dict(name='test_task', priority=42, interval=1, target='cache_clean', kwargs={'is_force_flush': True})
        )
        config.custom_text_rewriter_enable = True
        config.human_ip_verification_enabled = True
        config.CDN_domains = ('127.0.0.1',)
        config.verbose_level = 2

        import zmirror
        zmirror.human_ip_verification_enabled = False
        self.app = zmirror.app.test_client()

    def tearDown(self):
        os.remove(zmirror_file('config.py'))
        os.remove(zmirror_file('custom_func.py'))
        if os.path.exists(zmirror_file('config.py._unittest_raw')):
            shutil.move(zmirror_file('config.py._unittest_raw'), zmirror_file('config.py'))
        if os.path.exists(zmirror_file('custom_func.py._unittest_raw')):
            shutil.move(zmirror_file('custom_func.py._unittest_raw'), zmirror_file('custom_func.py'))

    def test_kernel_pages(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        # https://www.kernel.org/
        rv = self.app.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        assert isinstance(rv, Response)
        self.assertIn(b'The Linux Kernel Archives', rv.data)  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', rv.data)  # some rewrite

    def test_kernel_pages_compressed(self):
        """
        default config is a mirror of https://www.kernel.org/
        """
        # https://www.kernel.org/
        rv = self.app.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'},
                          headers={"accept-encoding": "gzip, deflate, br"}
                          )
        assert isinstance(rv, Response)
        self.assertIn(b'The Linux Kernel Archives', rv.data)  # title
        self.assertIn(b'/extdomains/www.wiki.kernel.org/', rv.data)  # some rewrite

    def test_kernel_img_get(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        rv = self.app.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.mimetype, 'image/png')
        self.assertGreater(len(rv.data), 2000)  # > 2KB

    def test_kernel_img_get_cache(self):
        # https://www.kernel.org/theme/images/logos/osl.png

        rv = self.app.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        rv = self.app.get('/theme/images/logos/osl.png', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.mimetype, 'image/png')
        self.assertGreater(len(rv.data), 2000)  # > 2KB
        print("test_kernel_img_get_cache", rv.headers)

    def test_kernel_css_get(self):
        # https://www.kernel.org/theme/css/main.css
        rv = self.app.get('/theme/css/main.css', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn('text/css', rv.mimetype)
        self.assertIn(b'@import "normalize.css"', rv.data)

    def test_crossdomain_and_status(self):
        rv = self.app.get('/crossdomain.xml', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'cross-domain-policy', rv.data)

        rv = self.app.get('/zmirror_stat', environ_base={'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn(b'extract_real_url_from_embedded_url', rv.data)

    def test_ssrf_prevention(self):
        # example.com, should not allowed
        rv = self.app.get('/extdomains/example.com/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn(b'SSRF Prevention', rv.data)

    def test_spider_deny(self):
        rv = self.app.get('/', headers={'user-agent': 'spider'}, environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertEqual(rv.status_code, 403)
        self.assertIn(b'Spiders Are Not Allowed To This Site', rv.data)

    def test_cache_clean(self):
        import zmirror
        zmirror.cache_clean(is_force_flush=False)
        zmirror.cache_clean(is_force_flush=True)
        print('enable_static_resource_CDN', zmirror.enable_static_resource_CDN)

    def test_mirror_url(self):
        import zmirror
        print(zmirror.decode_mirror_url(zmirror.encode_mirror_url("/theme/css/main.css")))

    def test_cdn_query_string_embed(self):
        import zmirror
        raw = "https://www.kernel.org/theme/images/logos/osl.png?a=b&c=d"
        emb = zmirror.embed_real_url_to_embedded_url(raw, 'image/png')
        dec = zmirror.extract_real_url_from_embedded_url(emb)
        print(emb, dec)

    def run_basic_tests(self):
        self.test_cache_clean()
        self.test_kernel_pages()
        self.test_kernel_pages_compressed()
        self.test_kernel_img_get()
        self.test_kernel_img_get_cache()
        self.test_kernel_css_get()
        self.test_crossdomain_and_status()
        self.test_ssrf_prevention()
        self.test_spider_deny()
        self.test_mirror_url()
        self.test_cdn_query_string_embed()

    def test_url_custom_redirect(self):
        import zmirror
        zmirror.url_custom_redirect_enable = True
        zmirror.url_custom_redirect_list = {'/css': '/theme/css/main.css'}
        zmirror.url_custom_redirect_regex = (('/css1/.*', '/theme/css/main.css'),)
        zmirror.shadow_url_redirect_regex = (('/css2/.*', '/theme/css/main.css'),)
        zmirror.plain_replace_domain_alias = (('www.twitter.com', 'twitter.your-website-mirror.com'),)

        self.run_basic_tests()

        rv = self.app.get('/css', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        print(rv.headers)
        rv = self.app.get('/css1/233', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        print(rv.headers)
        rv = self.app.get('/css2/233', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        print(rv.headers)

    def test_verification(self):
        import zmirror
        zmirror.human_ip_verification_enabled = True

        rv = self.app.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'})
        self.assertIn(b'ip_ban_verify_page', rv.data)

        rv = self.app.get('/', environ_base={'REMOTE_ADDR': '1.2.3.4'}, follow_redirects=True)
        print(rv.data)
        rv = self.app.post('/ip_ban_verify_page', data={"0": "CorrectAnswer",
                                                        "student_id": "2333",
                                                        "password": "123456",
                                                        "origin": "aHR0cDovL2xvY2FsaG9zdC8="},
                           environ_base={'REMOTE_ADDR': '1.2.3.4'}, follow_redirects=True
                           )
        print(rv.data)


if __name__ == '__main__':
    unittest.main()
