# coding=utf-8
import importlib
import unittest
import config
from .utils import copy_default_config_file, restore_config_file

config.enable_cron_tasks = False  # 为了避免多余的线程, 需要先关闭 cron_task
import zmirror


class ZmirrorTestBase(unittest.TestCase):
    class ZmirrorInitConfig:
        pass

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        copy_default_config_file()

    @classmethod
    def tearDownClass(cls):
        restore_config_file()
        super().tearDownClass()

    def setUp(self):
        importlib.reload(config)

        config.enable_cron_tasks = False  # 为了避免多余的线程, 需要先关闭 cron_task

        test_config_names = (name for name in dir(self.ZmirrorInitConfig) if name[:2] != '__' and name[-2:] != '__')
        for config_name in test_config_names:
            config_value = getattr(self.ZmirrorInitConfig, config_name)
            setattr(config, config_name, config_value)

        importlib.reload(zmirror)

        self.app = zmirror.app.test_client()
