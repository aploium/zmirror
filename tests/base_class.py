# coding=utf-8
import sys
import importlib
import unittest
import random
from urllib.parse import urljoin

from flask import Flask
from flask.testing import FlaskClient

from .utils import copy_default_config_file, restore_config_file

import cache_system


# config.enable_cron_tasks = False  # 为了避免多余的线程, 需要先关闭 cron_task
# import zmirror


class ZmirrorTestBase(unittest.TestCase):
    class C:
        verbose_level = 2
        unittest_mode = True
        enable_cron_tasks = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        copy_default_config_file()

    @classmethod
    def tearDownClass(cls):
        restore_config_file()

        super().tearDownClass()

    def reload_zmirror(self, configs_dict=None):
        self.tearDown()

        import config
        importlib.reload(config)

        test_config_names = (name for name in dir(self.C) if name[:2] != '__' and name[-2:] != '__')
        for config_name in test_config_names:
            config_value = getattr(self.C, config_name)
            setattr(config, config_name, config_value)

        if configs_dict is not None:
            for config_name, config_value in configs_dict.items():
                setattr(config, config_name, config_value)

        importlib.reload(cache_system)
        import zmirror
        importlib.reload(zmirror)
        zmirror.app.config['TESTING'] = True

        self.client = zmirror.app.test_client()  # type: FlaskClient
        self.app = zmirror.app  # type: Flask
        self.zmirror = zmirror

    def setUp(self):
        self.reload_zmirror()

    def tearDown(self):
        try:
            del self.client
        except:
            pass
        try:
            del self.app
        except:
            pass
        try:
            del self.zmirror
        except:
            pass

    def url(self, path):
        domain = getattr(self.C, "my_host_name", "127.0.0.1")
        scheme = getattr(self.C, "my_host_scheme", "http://")
        return urljoin(scheme + domain, path)
