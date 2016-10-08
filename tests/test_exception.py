# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *


class TestException(ZmirrorTestBase):
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

    def test_import_error_config(self):
        restore_config_file()
        try:
            self.reload_zmirror()
        except:
            import traceback
            traceback.print_exc()
            pass
        copy_default_config_file()

    def test_import_error_custom_func(self):
        restore_config_file()
        try:
            shutil.copy(zmirror_file('config_default.py'), zmirror_file('config.py'))
            try:
                self.reload_zmirror({"custom_text_rewriter_enable": True,
                                     "enable_custom_access_cookie_generate_and_verify": True,
                                     "identity_verify_required": True,
                                     })
            except:
                import traceback
                traceback.print_exc()
            os.remove(zmirror_file('config.py'))
        except:
            pass
        copy_default_config_file()
