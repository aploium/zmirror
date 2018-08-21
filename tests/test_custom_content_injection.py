# coding=utf-8
from flask import Response

from .base_class import ZmirrorTestBase
from .utils import *


class TestContentInjection(ZmirrorTestBase):
    """testing using https://bugzilla.kernel.org"""

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'www.kernel.org'
        target_scheme = 'https://'

        force_https_domains = ('bugzilla.kernel.org',)

        enable_automatic_domains_whitelist = True
        domains_whitelist_auto_add_glob_list = ('*.kernel.org',)
        # verbose_level = 4

        # developer_do_not_verify_ssl = True
        # is_use_proxy = True
        # requests_proxies = dict(
        #     http='http://127.0.0.1:8882',
        #     https='https://127.0.0.1:8882',
        # )

    def test_head_first_injection_with_script_in_head(self):
        """https://bugzilla.kernel.org/"""

        self.reload_zmirror(configs_dict={
            "custom_inject_content": {
                "head_first": [
                    {
                        "content": r'''Love''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Luciaz''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Forever''',
                        # 测试没有 url_regex 字段
                    },
                    {
                        "content": r'''!''',
                        "url_regex": r"^bugzilla\.kernel\.org/?",  # 一个匹配的正则
                    },
                    {
                        "content": r'''ThisShouldNotBeInjected''',
                        "url_regex": r"wtf_regex",  # 一个不匹配的正则
                    },
                ]
            }
        }
        )

        self.rv = self.client.get(
            self.url("/extdomains/bugzilla.kernel.org/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        text = self.rv.data.decode(encoding="utf-8")
        self.assertIn('LoveLuciazForever!', text, msg=self.dump())
        self.assertNotIn('ThisShouldNotBeInjected', text, msg=self.dump())

        self.assertLess(text.find("LoveLuciazForever!"), text.find("<script"))
        self.assertLess(text.find("LoveLuciazForever!"), text.find("</head"))

    def test_head_first_injection_without_script_in_head(self):
        """https://www.kernel.org/pub/"""

        self.reload_zmirror(configs_dict={
            "custom_inject_content": {
                "head_first": [
                    {
                        "content": r'''Love''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Luciaz''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Forever''',
                        # 测试没有 url_regex 字段
                    },
                    {
                        "content": r'''!''',
                        "url_regex": r"^www\.kernel\.org/pub/?",  # 一个匹配的正则
                    },
                    {
                        "content": r'''ThisShouldNotBeInjected''',
                        "url_regex": r"wtf_regex",  # 一个不匹配的正则
                    },
                ]
            }
        }
        )

        self.rv = self.client.get(
            self.url("/pub/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        text = self.rv.data.decode(encoding="utf-8")
        self.assertIn('LoveLuciazForever!', text, msg=self.dump())
        self.assertNotIn('ThisShouldNotBeInjected', text, msg=self.dump())

        self.assertLess(text.find("LoveLuciazForever!"), text.find("</head"))

    def test_head_last_injection_with_script_in_head(self):
        """https://bugzilla.kernel.org/"""

        self.reload_zmirror(configs_dict={
            "custom_inject_content": {
                "head_last": [
                    {
                        "content": r'''Love''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Luciaz''',
                        "url_regex": None,
                    },
                    {
                        "content": r'''Forever''',
                        # 测试没有 url_regex 字段
                    },
                    {
                        "content": r'''!''',
                        "url_regex": r"^bugzilla\.kernel\.org/?",  # 一个匹配的正则
                    },
                    {
                        "content": r'''ThisShouldNotBeInjected''',
                        "url_regex": r"wtf_regex",  # 一个不匹配的正则
                    },
                ]
            }
        }
        )

        self.rv = self.client.get(
            self.url("/extdomains/bugzilla.kernel.org/"),
            environ_base=env(),
            headers=headers(),
        )  # type: Response
        text = self.rv.data.decode(encoding="utf-8")
        self.assertIn('LoveLuciazForever!', text, msg=self.dump())
        self.assertNotIn('ThisShouldNotBeInjected', text, msg=self.dump())

        self.assertGreater(text.find("LoveLuciazForever!"), text.find("<script"))
        self.assertLess(text.find("LoveLuciazForever!"), text.find("</head"))
