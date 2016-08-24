# coding=utf-8
import sys
import importlib
import unittest
import random

from flask.testing import FlaskClient

from .utils import copy_default_config_file, restore_config_file

import cache_system


# config.enable_cron_tasks = False  # 为了避免多余的线程, 需要先关闭 cron_task
# import zmirror


class ZmirrorTestBase(unittest.TestCase):
    class ZmirrorInitConfig:
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
        try:
            del self.app
            del self.zmirror
            importlib.reload(cache_system)
        except:
            pass

        import config
        importlib.reload(config)

        test_config_names = (name for name in dir(self.ZmirrorInitConfig) if name[:2] != '__' and name[-2:] != '__')
        for config_name in test_config_names:
            config_value = getattr(self.ZmirrorInitConfig, config_name)
            setattr(config, config_name, config_value)

        if configs_dict is not None:
            for config_name, config_value in configs_dict.items():
                setattr(config, config_name, config_value)

        import zmirror
        importlib.reload(zmirror)
        zmirror.app.config['TESTING'] = True

        self.app = zmirror.app.test_client()  # type: FlaskClient
        self.zmirror = zmirror

    def setUp(self):
        self.reload_zmirror()

    def tearDown(self):
        try:
            del self.app
            del self.zmirror
            importlib.reload(cache_system)
        except:
            pass
