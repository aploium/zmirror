# coding=utf-8
import sys
import importlib
import unittest
import random
from urllib.parse import urljoin

from flask import Flask, Response
from flask.testing import FlaskClient

from .utils import copy_default_config_file, restore_config_file, attributes

try:
    from typing import Union
except:
    pass


class LazyDump:
    def __init__(self, dumper, msg=None):
        self._dumper = dumper
        self._msg = msg

    def __str__(self):
        return self._dumper() + (("\n------extra msg------\n" + self._msg) if self._msg else "")

    def __repr__(self):
        return str(self)


class ZmirrorTestBase(unittest.TestCase):
    class C:
        verbose_level = 2
        unittest_mode = True
        enable_cron_tasks = False
        # developer_enable_experimental_feature = True
        requests_proxies = dict(
            http='http://127.0.0.1:8123',
            https='https://127.0.0.1:8123',
        )

    class CaseCfg:
        pass

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        copy_default_config_file()

    @classmethod
    def tearDownClass(cls):
        restore_config_file()

        super().tearDownClass()

    def reload_zmirror(self, configs_dict=None):
        self.del_temp_var()

        import config
        importlib.reload(config)

        test_config_names = (name for name in dir(self.C) if name[:2] != '__' and name[-2:] != '__')
        for config_name in test_config_names:
            config_value = getattr(self.C, config_name)
            setattr(config, config_name, config_value)

        if configs_dict is not None:
            for config_name, config_value in configs_dict.items():
                setattr(config, config_name, config_value)

        import zmirror.cache_system as cache_system
        import zmirror.zmirror as zmirror
        importlib.reload(cache_system)
        importlib.reload(zmirror)

        zmirror.app.config['TESTING'] = True

        # 处理有端口号的测试, 在 del_temp_var() 中回滚
        if hasattr(self.C, "my_host_port"):
            port = getattr(self.C, "my_host_port", None)
            my_host_name = getattr(self.C, "my_host_name", "127.0.0.1")
            if port is not None:
                self.C.my_host_name_no_port = my_host_name
                self.C.my_host_name = self.C.my_host_name_no_port + ":" + str(port)
            else:
                self.C.my_host_name_no_port = my_host_name
        elif hasattr(self.C, "my_host_name"):
            self.C.my_host_name_no_port = self.C.my_host_name

        self.client = zmirror.app.test_client()  # type: FlaskClient
        self.app = zmirror.app  # type: Flask
        self.zmirror = zmirror

    def setUp(self):
        self.reload_zmirror()
        self.rv = None
        self.rv2 = None
        self.rv3 = None

    def del_temp_var(self):
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
        try:
            del self.rv
        except:
            pass
        try:
            del self.rv2
        except:
            pass
        try:
            del self.rv3
        except:
            pass

        if hasattr(self.C, "my_host_name_no_port"):
            self.C.my_host_name = getattr(self.C, "my_host_name_no_port")
            delattr(self.C, "my_host_name_no_port")

    def tearDown(self):
        self.del_temp_var()

    def url(self, path):
        domain = getattr(self.C, "my_host_name", "127.0.0.1")
        scheme = getattr(self.C, "my_host_scheme", "http://")
        return urljoin(scheme + domain, path)

    def _dump(self, select='all'):
        """
        :type select: Union[int, str]
        :rtype: str
        """
        from pprint import pformat

        select = {
            "all": "all",
            1: "rv",
            2: "rv2",
            3: "rv3",
        }[select]
        dump = "\n------------- begin dump -------------"

        dump += "\n------------- zmirror parse -------------\n"
        dump += attributes(self.zmirror.parse)
        if self.zmirror.parse.remote_response is not None:
            dump += "\n------------- zmirror remote request -------------\n"
            dump += attributes(self.zmirror.parse.remote_response.request)
            dump += "\n------------- zmirror remote response -------------\n"
            dump += attributes(self.zmirror.parse.remote_response)

        for rv_name in ([select] if select != "all" else ["rv", "rv2", "rv3"]):
            if not hasattr(self, rv_name):
                continue

            rv = getattr(self, rv_name)  # type: Response

            if not isinstance(rv, Response):
                continue

            dump += "\n------------- {} -------------\n".format(rv_name)
            dump += attributes(rv)
            dump += "\n------------- {}.headers -------------\n".format(rv_name)
            dump += pformat(list(rv.headers.items()))

        dump += "\n------------- end dump -------------\n"

        return dump

    def dump(self, msg=None):
        """
        :type msg: str
        :rtype: LazyDump
        """
        return LazyDump(self._dump, msg=msg)
        # return self._dump()
