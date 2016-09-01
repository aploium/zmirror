# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .base_class import ZmirrorTestBase
from .utils import *

import re
from time import time


class TestRegex(ZmirrorTestBase):
    REGEX_POSSIBLE_SLASH = [
        "/",
        r"\/", r"\\/", r"\\\/", r"\\\\/",
        "%2f", "%2F",
        "%5C%2F", "%5c%2f",
        "%5C%5C%2F", "%5c%5c%2f",
        "%5C%5C%5C%2F", "%5c%5c%5c%2f",
        "%5C%5C%5C%5C%2F", "%5c%5c%5c%5c%2f",
        "%252F", "%252f",
        "%255C%252F", "%255c%252f",
        "%255C%255C%252F", "%255c%255c%252f",
        "%255C%255C%255C%252F", "%255c%255c%255c%252f",
        r"\x2F", r"\x2f",
    ]

    REGEX_POSSIBLE_COLON = [
        ":",
        "%3A", "%3a",
        "%253A", "%253a",
    ]

    REGEX_POSSIBLE_QUOTE = [
        "'", '"',
        r"\'", '\"',
        r"\\'", '\\"',
        r"\\\'", '\\\"',
        "%22", "%27",
        "%5C%22", "%5C%27", "%5c%22", "%5c%27",
        "%5C%5C%22", "%5C%5C%27", "%5c%5c%22", "%5c%5c%27",
        "%5C%5C%5C%22", "%5C%5C%5C%27", "%5c%5c%5c%22", "%5c%5c%5c%27",
        "%2522", "%2527",
        "%255C%2522", "%255C%2527", "%255c%2522", "%255c%2527",
        "%255C%255C%2522", "%255C%255C%2527", "%255c%255c%2522", "%255c%255c%2527",
        "&quot;",
    ]

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('eu.httpbin.org', "w.ww.httpbin.org", "fo.bar")
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        # verbose_level = 4
        possible_charsets = None

    def test__regex_request_rewriter_extdomains(self):
        from zmirror.external_pkgs.ColorfulPyPrint import errprint
        g = self.zmirror.get_group
        reg = self.zmirror.regex_request_rewriter_extdomains

        def match_test_1(slash, target_scheme_prefix, my_domain, real_domain, test_str):
            try:
                m = reg.fullmatch(test_str)
                self.assertIn("extdomains" + slash + target_scheme_prefix, m.group())
                self.assertEqual(real_domain, g("real_domain", m))
                self.assertEqual("", g("scheme", m))
                if my_domain:
                    self.assertEqual(slash, g("slash2", m))

            except:
                errprint(
                    "slash", slash, "target_scheme_prefix", target_scheme_prefix,
                    "real_domain", real_domain, "test_str", test_str)
                raise

        def match_test_2(scheme, slash, target_scheme_prefix, real_domain, test_str):
            try:
                m = reg.fullmatch(test_str)
                self.assertIn("extdomains" + slash + target_scheme_prefix, m.group())
                self.assertEqual(scheme, g("scheme", m))
                self.assertEqual(slash, g("scheme_slash", m))
                self.assertEqual(slash, g("slash2", m))
                self.assertEqual(real_domain, g("real_domain", m))
            except:
                errprint(
                    "scheme", scheme, "target_scheme_prefix", target_scheme_prefix,
                    "slash", slash,
                    "real_domain", real_domain, "test_str", test_str)
                raise

        count = 0
        _start = time()
        all_cases = ""
        for slash in self.REGEX_POSSIBLE_SLASH:
            for target_scheme_prefix in ["https-", ""]:
                for real_domain in [self.C.target_domain] + list(self.C.external_domains):
                    suffix = "extdomains/" + target_scheme_prefix + real_domain
                    for explicit_scheme in ["http://", "https://", "//", ""]:
                        #
                        if explicit_scheme == "":
                            # [www.mydomain.com/]extdomains/(https-)target.com
                            for my_domain in [self.C.my_host_name + "/", ""]:
                                buff = my_domain + suffix
                                buff = buff.replace("/", slash)
                                match_test_1(slash, target_scheme_prefix, my_domain, real_domain, buff)

                                all_cases += buff + "\n"
                                count += 1

                        elif ":" in explicit_scheme:
                            my_domain = self.C.my_host_name + "/"
                            for colon in self.REGEX_POSSIBLE_COLON:
                                buff = explicit_scheme + my_domain + suffix
                                buff = buff.replace("/", slash).replace(":", colon)
                                match_test_2(
                                    explicit_scheme.replace("/", slash).replace(":", colon),
                                    slash,
                                    target_scheme_prefix,
                                    real_domain,
                                    buff
                                )

                                all_cases += buff + "\n"
                                count += 1
                        #
                        else:  # //
                            my_domain = self.C.my_host_name + "/"
                            buff = explicit_scheme + my_domain + suffix
                            buff = buff.replace("/", slash)
                            match_test_2(
                                explicit_scheme.replace("/", slash),
                                slash,
                                target_scheme_prefix,
                                real_domain,
                                buff
                            )

                            all_cases += buff + "\n"
                            count += 1
        print("test__regex_request_rewriter_extdomains Total Count:", count, "Time:", time() - _start)
        # 最后再总的测试一下
        self.assertEqual(count, len(reg.findall(all_cases)))

    def test__regex_basic_mirrorlization(self):
        """
        测试正则 regex_basic_mirrorlization

        因为是草稿里直接复制过来的, 代码很乱
        """
        from zmirror.external_pkgs.ColorfulPyPrint import errprint

        reg = self.zmirror.regex_basic_mirrorlization
        # 下面这一堆嵌套的 for, 好吧我也无能为力
        # 因为需要穷举所有的可能(几千种), 来测试这个正则
        for domain in list(self.C.external_domains) + [self.C.target_domain]:
            assert re.fullmatch(self.zmirror.regex_all_remote_domains, domain) is not None, domain
            for slash in self.REGEX_POSSIBLE_SLASH:
                for suffix_slash in [True, False]:
                    for explicit_scheme in ["http://", "https://", "//", ""]:
                        if explicit_scheme == "":
                            for quote in self.REGEX_POSSIBLE_QUOTE:
                                buff = quote + domain + (slash if suffix_slash else "") + quote  # type: str
                                try:
                                    m = reg.fullmatch(buff)
                                    assert m.group("quote") == quote
                                    assert m.group("domain") == domain
                                    assert m.groupdict()["suffix_slash"] == (slash if suffix_slash else None)
                                except:
                                    errprint("slash", slash, "suffix_slash", suffix_slash,
                                             "quote", quote, "buff", buff)
                                    raise

                        elif ":" in explicit_scheme:
                            for colon in self.REGEX_POSSIBLE_COLON:
                                _explicit_scheme = explicit_scheme.replace("/", slash).replace(":", colon)
                                buff = _explicit_scheme + domain + (slash if suffix_slash else "")  # type: str
                                try:
                                    m = reg.fullmatch(buff)
                                    assert m.group("scheme_slash") == slash
                                    assert m.group("domain") == domain
                                    assert m.group("colon") == colon
                                    assert m.groupdict()["suffix_slash"] == (slash if suffix_slash else None)
                                except:
                                    errprint("slash", slash, "suffix_slash", suffix_slash,
                                             "explicit_scheme", explicit_scheme,
                                             "colon", colon, "buff", buff)
                                    raise
                        else:
                            _explicit_scheme = explicit_scheme.replace("/", slash)
                            buff = _explicit_scheme + domain + (slash if suffix_slash else "")  # type: str
                            try:
                                m = reg.fullmatch(buff)
                                # print(buff)

                                assert m.group("scheme_slash") == slash
                                assert m.group("domain") == domain
                                assert m.groupdict()["suffix_slash"] == (slash if suffix_slash else None)
                            except:
                                errprint("slash", slash, "suffix_slash", suffix_slash, "explicit_scheme", explicit_scheme,
                                         "buff", buff)
                                raise
