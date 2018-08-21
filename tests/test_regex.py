# coding=utf-8
import json
import copy
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
        # 斜线(/) 所有可能的值
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
        r"\\x2F", r"\\x2f",
        r"\\\x2F", r"\\\x2f",
        r"\\\\x2F", r"\\\\x2f",
    ]

    REGEX_POSSIBLE_COLON = [
        # 冒号(:) 所有可能的值
        ":",
        "%3A", "%3a",
        "%253A", "%253a",
    ]

    REGEX_POSSIBLE_QUOTE = [
        # 引号('") 所有可能的值
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

    def _url_format(self, url):
        """
        :type url: str
        :rtype: str
        """
        path = os.path.dirname(self.zmirror.parse.remote_path)
        if path == "/":
            path = ""

        path_up = os.path.dirname(path.rstrip("/"))
        if path_up == "/":
            path_up = ""
        return (
            url.replace("{ext_domain}", self.zmirror.parse.remote_domain)
                .replace("{path}", path)
                .replace("{path_up}", path_up)

                .replace("{our_scheme_esc}", slash_esc(self.zmirror.my_host_scheme))
                .replace("{our_scheme}", self.zmirror.my_host_scheme)
                .replace("{our_domain}", self.zmirror.my_host_name)

        )

    def test__regex_adv_url_rewriter__and__regex_url_reassemble(self):
        test_cases = (
            dict(
                raw='background: url(../images/boardsearch/mso-hd.gif);',
                main='background: url({path_up}/images/boardsearch/mso-hd.gif);',
                ext='background: url(/extdomains/{ext_domain}{path_up}/images/boardsearch/mso-hd.gif);',
            ),
            dict(
                raw='background: url(http://www.google.com/images/boardsearch/mso-hd.gif););',
                main='background: url({our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif););',
                ext='background: url({our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif););'
            ),
            dict(
                raw=": url('http://www.google.com/images/boardsearch/mso-hd.gif');",
                main=": url('{our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif');",
                ext=": url('{our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif');",
            ),
            dict(
                raw='background: url("//www.google.com/images/boardsearch/mso-hd.gif");',
                main='background: url("//{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif");',
                ext='background: url("//{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif");',
            ),
            dict(
                raw=r"""background: url ( "//www.google.com/images/boardsearch/mso-hd.gif" );""",
                main=r"""background: url ( "//{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif" );""",
                ext=r"""background: url ( "//{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif" );""",
            ),
            dict(
                raw=r""" src="https://ssl.gstatic.com/233.jpg" """,
                main=r""" src="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg" """,
                ext=r""" src="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg" """,
            ),
            dict(
                raw=r""" src="/233.jpg" """,
                main=r""" src="/233.jpg" """,
                ext=r""" src="/extdomains/{ext_domain}/233.jpg" """,
            ),
            dict(
                raw=r"""href="http://ssl.gstatic.com/233.jpg" """,
                main=r"""href="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg" """,
                ext=r"""href="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg" """,
            ),
            dict(
                raw=r"""background: url("//ssl.gstatic.com/images/boardsearch/mso-hd.gif"); """,
                main=r"""background: url("//{our_domain}/extdomains/ssl.gstatic.com/images/boardsearch/mso-hd.gif"); """,
                ext=r"""background: url("//{our_domain}/extdomains/ssl.gstatic.com/images/boardsearch/mso-hd.gif"); """,
            ),
            dict(
                raw=r"""background: url ( "//ssl.gstatic.com/images/boardsearch/mso-hd.gif" ); """,
                main=r"""background: url ( "//{our_domain}/extdomains/ssl.gstatic.com/images/boardsearch/mso-hd.gif" ); """,
                ext=r"""background: url ( "//{our_domain}/extdomains/ssl.gstatic.com/images/boardsearch/mso-hd.gif" ); """,
            ),
            dict(
                raw=r"""src="http://www.google.com/233.jpg" """,
                main=r"""src="{our_scheme}{our_domain}/extdomains/www.google.com/233.jpg" """,
                ext=r"""src="{our_scheme}{our_domain}/extdomains/www.google.com/233.jpg" """,
            ),
            dict(
                raw=r"""href="http://www.google.com/233.jpg" """,
                main=r"""href="{our_scheme}{our_domain}/extdomains/www.google.com/233.jpg" """,
                ext=r"""href="{our_scheme}{our_domain}/extdomains/www.google.com/233.jpg" """,
            ),
            dict(
                raw=r"""href="https://www.foo.com/233.jpg" """,
                main=r"""href="https://www.foo.com/233.jpg" """,
                ext=r"""href="https://www.foo.com/233.jpg" """,
            ),
            dict(
                raw=r"""xhref="http://www.google.com/233.jpg" """,
                main=r"""xhref="http://www.google.com/233.jpg" """,
                ext=r"""xhref="http://www.google.com/233.jpg" """,
            ),
            dict(
                raw=r"""s.href="http://www.google.com/path/233.jpg" """,
                main=r"""s.href="{our_scheme}{our_domain}/extdomains/www.google.com/path/233.jpg" """,
                ext=r"""s.href="{our_scheme}{our_domain}/extdomains/www.google.com/path/233.jpg" """,
            ),
            dict(
                raw=r"""background: url(../images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
                main=r"""background: url({path_up}/images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
                ext=r"""background: url(/extdomains/{ext_domain}{path_up}/images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
            ),
            dict(
                raw=r"""background: url(http://www.google.com/images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
                main=r"""background: url({our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
                ext=r"""background: url({our_scheme}{our_domain}/extdomains/www.google.com/images/boardsearch/mso-hd.gif?a=x&bb=fr%34fd);""",
            ),
            dict(
                raw=r"""src="http://ssl.gstatic.com/233.jpg?a=x&bb=fr%34fd" """,
                main=r"""src="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg?a=x&bb=fr%34fd" """,
                ext=r"""src="{our_scheme}{our_domain}/extdomains/ssl.gstatic.com/233.jpg?a=x&bb=fr%34fd" """,
            ),
            dict(
                raw=r"""href="index.php/img/233.jx" """,
                main=r"""href="{path}/index.php/img/233.jx" """,
                ext=r"""href="/extdomains/{ext_domain}{path}/index.php/img/233.jx" """,
            ),
            dict(
                raw=r"""href="/img/233.jss" """,
                main=r"""href="/img/233.jss" """,
                ext=r"""href="/extdomains/{ext_domain}/img/233.jss" """,
            ),
            dict(
                raw=r"""href="img/233.jpg" """,
                main=r"""href="{path}/img/233.jpg" """,
                ext=r"""href="/extdomains/{ext_domain}{path}/img/233.jpg" """,
            ),
            dict(
                raw=r"""nd-image:url(/static/images/project-logos/zhwiki.png)}@media""",
                main=r"""nd-image:url(/static/images/project-logos/zhwiki.png)}@media""",
                ext=r"""nd-image:url(/extdomains/{ext_domain}/static/images/project-logos/zhwiki.png)}@media""",
            ),
            dict(
                raw=r"""nd-image:url(static/images/project-logos/zhwiki.png)}@media""",
                main=r"""nd-image:url({path}/static/images/project-logos/zhwiki.png)}@media""",
                ext=r"""nd-image:url(/extdomains/{ext_domain}{path}/static/images/project-logos/zhwiki.png)}@media""",
            ),
            dict(
                raw=r"""@import "/wikipedia/zh/w/index.php?title=MediaWiki:Gadget-fontsize.css&action=raw&ctype=text/css";""",
                main=r"""@import "/wikipedia/zh/w/index.php?title=MediaWiki:Gadget-fontsize.css&action=raw&ctype=text/css";""",
                ext=r"""@import "/wikipedia/zh/w/index.php?title=MediaWiki:Gadget-fontsize.css&action=raw&ctype=text/css";""",
            ),
            dict(
                raw=r"""(window['gbar']=window['gbar']||{})._CONFIG=[[[0,"www.gstatic.com","og.og2.en_US.8UP-Hyjzcx8.O","com","zh-CN","1",0,[3,2,".40.64.","","1300102,3700275,3700388","1461637855","0"],"40400","LJ8qV4WxEI_QjwOio6SoDw",0,0,"og.og2.w5jrmmcgm1gp.L.F4.O","AA2YrTt48BbbcLnincZsbUECyYqIio-xhw","AA2YrTu9IQdyFrx2T9b82QPSt9PVPEWOIw","",2,0,200,"USA"],null,0,["m;/_/scs/abc-static/_/js/k=gapi.gapi.en.CqFrPIKIxF4.O/m=__features__/rt=j/d=1/rs=AHpOoo_SqGYjlKSpzsbc2UGyTC5n3Z0ZtQ","https://apis.google.com","","","","",null,1,"es_plusone_gc_20160421.0_p0","zh-CN"],["1","gci_91f30755d6a6b787dcc2a4062e6e9824.js","googleapis.client:plusone:gapi.iframes","","zh-CN"],null,null,null,[0.009999999776482582,"com","1",[null,"","w",null,1,5184000,1,0,""],null,[["","","",0,0,-1]],[null,0,0],0,null,null,["5061451","google\\.(com|ru|ca|by|kz|com\\.mx|com\\.tr)$",1]],null,[0,0,0,null,"","","",""],[1,0.001000000047497451,1],[1,0.1000000014901161,2,1],[0,"",null,"",0,"加载您的 Marketplace 应用时出错。","您没有任何 Marketplace 应用。",0,[1,"https://www.google.com/webhp?tab=ww","搜索","","0 -276px",null,0],null,null,1,0],[1],[0,1,["lg"],1,["lat"]],[["","","","","","","","","","","","","","","","","","","","def","","","","","",""],[""]],null,null,null,[30,127,1,0,60],null,null,null,null,null,[1,1]]];(window['gbar']=window['gbar']||{})._LDD=["in","fot"];this.gbar_=this.gbar_||{};(function(_){var window=this;""",
                main=r"""(window['gbar']=window['gbar']||{})._CONFIG=[[[0,"www.gstatic.com","og.og2.en_US.8UP-Hyjzcx8.O","com","zh-CN","1",0,[3,2,".40.64.","","1300102,3700275,3700388","1461637855","0"],"40400","LJ8qV4WxEI_QjwOio6SoDw",0,0,"og.og2.w5jrmmcgm1gp.L.F4.O","AA2YrTt48BbbcLnincZsbUECyYqIio-xhw","AA2YrTu9IQdyFrx2T9b82QPSt9PVPEWOIw","",2,0,200,"USA"],null,0,["m;/_/scs/abc-static/_/js/k=gapi.gapi.en.CqFrPIKIxF4.O/m=__features__/rt=j/d=1/rs=AHpOoo_SqGYjlKSpzsbc2UGyTC5n3Z0ZtQ","https://apis.google.com","","","","",null,1,"es_plusone_gc_20160421.0_p0","zh-CN"],["1","gci_91f30755d6a6b787dcc2a4062e6e9824.js","googleapis.client:plusone:gapi.iframes","","zh-CN"],null,null,null,[0.009999999776482582,"com","1",[null,"","w",null,1,5184000,1,0,""],null,[["","","",0,0,-1]],[null,0,0],0,null,null,["5061451","google\\.(com|ru|ca|by|kz|com\\.mx|com\\.tr)$",1]],null,[0,0,0,null,"","","",""],[1,0.001000000047497451,1],[1,0.1000000014901161,2,1],[0,"",null,"",0,"加载您的 Marketplace 应用时出错。","您没有任何 Marketplace 应用。",0,[1,"https://www.google.com/webhp?tab=ww","搜索","","0 -276px",null,0],null,null,1,0],[1],[0,1,["lg"],1,["lat"]],[["","","","","","","","","","","","","","","","","","","","def","","","","","",""],[""]],null,null,null,[30,127,1,0,60],null,null,null,null,null,[1,1]]];(window['gbar']=window['gbar']||{})._LDD=["in","fot"];this.gbar_=this.gbar_||{};(function(_){var window=this;""",
                ext=r"""(window['gbar']=window['gbar']||{})._CONFIG=[[[0,"www.gstatic.com","og.og2.en_US.8UP-Hyjzcx8.O","com","zh-CN","1",0,[3,2,".40.64.","","1300102,3700275,3700388","1461637855","0"],"40400","LJ8qV4WxEI_QjwOio6SoDw",0,0,"og.og2.w5jrmmcgm1gp.L.F4.O","AA2YrTt48BbbcLnincZsbUECyYqIio-xhw","AA2YrTu9IQdyFrx2T9b82QPSt9PVPEWOIw","",2,0,200,"USA"],null,0,["m;/_/scs/abc-static/_/js/k=gapi.gapi.en.CqFrPIKIxF4.O/m=__features__/rt=j/d=1/rs=AHpOoo_SqGYjlKSpzsbc2UGyTC5n3Z0ZtQ","https://apis.google.com","","","","",null,1,"es_plusone_gc_20160421.0_p0","zh-CN"],["1","gci_91f30755d6a6b787dcc2a4062e6e9824.js","googleapis.client:plusone:gapi.iframes","","zh-CN"],null,null,null,[0.009999999776482582,"com","1",[null,"","w",null,1,5184000,1,0,""],null,[["","","",0,0,-1]],[null,0,0],0,null,null,["5061451","google\\.(com|ru|ca|by|kz|com\\.mx|com\\.tr)$",1]],null,[0,0,0,null,"","","",""],[1,0.001000000047497451,1],[1,0.1000000014901161,2,1],[0,"",null,"",0,"加载您的 Marketplace 应用时出错。","您没有任何 Marketplace 应用。",0,[1,"https://www.google.com/webhp?tab=ww","搜索","","0 -276px",null,0],null,null,1,0],[1],[0,1,["lg"],1,["lat"]],[["","","","","","","","","","","","","","","","","","","","def","","","","","",""],[""]],null,null,null,[30,127,1,0,60],null,null,null,null,null,[1,1]]];(window['gbar']=window['gbar']||{})._LDD=["in","fot"];this.gbar_=this.gbar_||{};(function(_){var window=this;""",
            ),
            dict(
                raw=r""" src="" """,
                main=r""" src="" """,
                ext=r""" src="" """,
            ),
            dict(
                raw=r""" this.src=c; """,
                main=r""" this.src=c; """,
                ext=r""" this.src=c; """,
            ),
            dict(
                raw=r""" href="http://www.google.com/" """,
                main=r""" href="{our_scheme}{our_domain}/extdomains/www.google.com/" """,
                ext=r""" href="{our_scheme}{our_domain}/extdomains/www.google.com/" """,
            ),
            dict(
                raw=r"""_.Gd=function(a){if(_.na(a)||!a||a.Gb)return!1;var c=a.src;if(_.nd(c))return c.uc(a);var d=a.type,e=a.b;c.removeEventListener?c.removeEventListener(d,e,a.fc):c.detachEvent&&c.detachEvent(Cd(d),e);xd--;(d=_.Ad(c))?(td(d,a),0==d.o&&(d.src=null,c[vd]=null)):qd(a);return!0};Cd=function(a){return a in wd?wd[a]:wd[a]="on"+a};Id=function(a,c,d,e){var f=!0;if(a=_.Ad(a))if(c=a.b[c.toString()])for(c=c.concat(),a=0;a<c.length;a++){var g=c[a];g&&g.fc==d&&!g.Gb&&(g=Hd(g,e),f=f&&!1!==g)}return f};""",
                main=r"""_.Gd=function(a){if(_.na(a)||!a||a.Gb)return!1;var c=a.src;if(_.nd(c))return c.uc(a);var d=a.type,e=a.b;c.removeEventListener?c.removeEventListener(d,e,a.fc):c.detachEvent&&c.detachEvent(Cd(d),e);xd--;(d=_.Ad(c))?(td(d,a),0==d.o&&(d.src=null,c[vd]=null)):qd(a);return!0};Cd=function(a){return a in wd?wd[a]:wd[a]="on"+a};Id=function(a,c,d,e){var f=!0;if(a=_.Ad(a))if(c=a.b[c.toString()])for(c=c.concat(),a=0;a<c.length;a++){var g=c[a];g&&g.fc==d&&!g.Gb&&(g=Hd(g,e),f=f&&!1!==g)}return f};""",
                ext=r"""_.Gd=function(a){if(_.na(a)||!a||a.Gb)return!1;var c=a.src;if(_.nd(c))return c.uc(a);var d=a.type,e=a.b;c.removeEventListener?c.removeEventListener(d,e,a.fc):c.detachEvent&&c.detachEvent(Cd(d),e);xd--;(d=_.Ad(c))?(td(d,a),0==d.o&&(d.src=null,c[vd]=null)):qd(a);return!0};Cd=function(a){return a in wd?wd[a]:wd[a]="on"+a};Id=function(a,c,d,e){var f=!0;if(a=_.Ad(a))if(c=a.b[c.toString()])for(c=c.concat(),a=0;a<c.length;a++){var g=c[a];g&&g.fc==d&&!g.Gb&&(g=Hd(g,e),f=f&&!1!==g)}return f};""",
            ),
            dict(
                raw=r"""<script>(function(){window.google={kEI:'wZ4qV6KnMtjwjwOztI2ABQ',kEXPI:'10201868',authuser:0,j:{en:1,bv:24,u:'e4f4906d',qbp:0},kscs:'e4f4906d_24'};google.kHL='zh-CN';})();(function(){google.lc=[];google.li=0;google.getEI=function(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||google.kEI};google.getLEI=function(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b};google.https=function(){return"https:"==window.location.protocol};google.ml=function(){return null};google.wl=function(a,b){try{google.ml(Error(a),!1,b)}catch(c){}};google.time=function(){return(new Date).getTime()};google.log=function(a,b,c,e,g){a=google.logUrl(a,b,c,e,g);if(""!=a){b=new Image;var d=google.lc,f=google.li;d[f]=b;b.onerror=b.onload=b.onabort=function(){delete d[f]};window.google&&window.google.vel&&window.google.vel.lu&&window.google.vel.lu(a);b.src=a;google.li=f+1}};google.logUrl=function(a,b,c,e,g){var d="",f=google.ls||"";if(!c&&-1==b.search("&ei=")){var h=google.getEI(e),d="&ei="+h;-1==b.search("&lei=")&&((e=google.getLEI(e))?d+="&lei="+e:h!=google.kEI&&(d+="&lei="+google.kEI))}a=c||"/"+(g||"gen_204")+"?atyp=i&ct="+a+"&cad="+b+d+f+"&zx="+google.time();/^http:/i.test(a)&&google.https()&&(google.ml(Error("a"),!1,{src:a,glmm:1}),a="");return a};google.y={};google.x=function(a,b){google.y[a.id]=[a,b];return!1};google.load=function(a,b,c){google.x({id:a+k++},function(){google.load(a,b,c)})};var k=0;})();""",
                main=r"""<script>(function(){window.google={kEI:'wZ4qV6KnMtjwjwOztI2ABQ',kEXPI:'10201868',authuser:0,j:{en:1,bv:24,u:'e4f4906d',qbp:0},kscs:'e4f4906d_24'};google.kHL='zh-CN';})();(function(){google.lc=[];google.li=0;google.getEI=function(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||google.kEI};google.getLEI=function(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b};google.https=function(){return"https:"==window.location.protocol};google.ml=function(){return null};google.wl=function(a,b){try{google.ml(Error(a),!1,b)}catch(c){}};google.time=function(){return(new Date).getTime()};google.log=function(a,b,c,e,g){a=google.logUrl(a,b,c,e,g);if(""!=a){b=new Image;var d=google.lc,f=google.li;d[f]=b;b.onerror=b.onload=b.onabort=function(){delete d[f]};window.google&&window.google.vel&&window.google.vel.lu&&window.google.vel.lu(a);b.src=a;google.li=f+1}};google.logUrl=function(a,b,c,e,g){var d="",f=google.ls||"";if(!c&&-1==b.search("&ei=")){var h=google.getEI(e),d="&ei="+h;-1==b.search("&lei=")&&((e=google.getLEI(e))?d+="&lei="+e:h!=google.kEI&&(d+="&lei="+google.kEI))}a=c||"/"+(g||"gen_204")+"?atyp=i&ct="+a+"&cad="+b+d+f+"&zx="+google.time();/^http:/i.test(a)&&google.https()&&(google.ml(Error("a"),!1,{src:a,glmm:1}),a="");return a};google.y={};google.x=function(a,b){google.y[a.id]=[a,b];return!1};google.load=function(a,b,c){google.x({id:a+k++},function(){google.load(a,b,c)})};var k=0;})();""",
                ext=r"""<script>(function(){window.google={kEI:'wZ4qV6KnMtjwjwOztI2ABQ',kEXPI:'10201868',authuser:0,j:{en:1,bv:24,u:'e4f4906d',qbp:0},kscs:'e4f4906d_24'};google.kHL='zh-CN';})();(function(){google.lc=[];google.li=0;google.getEI=function(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||google.kEI};google.getLEI=function(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b};google.https=function(){return"https:"==window.location.protocol};google.ml=function(){return null};google.wl=function(a,b){try{google.ml(Error(a),!1,b)}catch(c){}};google.time=function(){return(new Date).getTime()};google.log=function(a,b,c,e,g){a=google.logUrl(a,b,c,e,g);if(""!=a){b=new Image;var d=google.lc,f=google.li;d[f]=b;b.onerror=b.onload=b.onabort=function(){delete d[f]};window.google&&window.google.vel&&window.google.vel.lu&&window.google.vel.lu(a);b.src=a;google.li=f+1}};google.logUrl=function(a,b,c,e,g){var d="",f=google.ls||"";if(!c&&-1==b.search("&ei=")){var h=google.getEI(e),d="&ei="+h;-1==b.search("&lei=")&&((e=google.getLEI(e))?d+="&lei="+e:h!=google.kEI&&(d+="&lei="+google.kEI))}a=c||"/"+(g||"gen_204")+"?atyp=i&ct="+a+"&cad="+b+d+f+"&zx="+google.time();/^http:/i.test(a)&&google.https()&&(google.ml(Error("a"),!1,{src:a,glmm:1}),a="");return a};google.y={};google.x=function(a,b){google.y[a.id]=[a,b];return!1};google.load=function(a,b,c){google.x({id:a+k++},function(){google.load(a,b,c)})};var k=0;})();""",
            ),
            dict(
                raw=r"""background-image: url("../skin/default/tabs_m_tile.gif");""",
                main=r"""background-image: url("{path_up}/skin/default/tabs_m_tile.gif");""",
                ext=r"""background-image: url("/extdomains/{ext_domain}{path_up}/skin/default/tabs_m_tile.gif");""",
            ),
            dict(
                raw=r"""background-image: url("xx/skin/default/tabs_m_tile.gif");""",
                main=r"""background-image: url("{path}/xx/skin/default/tabs_m_tile.gif");""",
                ext=r"""background-image: url("/extdomains/{ext_domain}{path}/xx/skin/default/tabs_m_tile.gif");""",
            ),
            dict(
                raw=r"""background-image: url('xx/skin/default/tabs_m_tile.gif");""",
                main=r"""background-image: url('xx/skin/default/tabs_m_tile.gif");""",
                ext=r"""background-image: url('xx/skin/default/tabs_m_tile.gif");""",
            ),
            dict(
                raw=r"""} else 2 == e ? this.Ea ? this.Ea.style.display = "" : (e = QS_XA("sbsb_j " + this.$.ef), f = QS_WA("a"), f.id = "sbsb_f", f.href = "http://www.google.com/support/websearch/bin/answer.py?hl=" + this.$.Xe + "&answer=106230", f.innerHTML = this.$.$k, e.appendChild(f), e.onmousedown = QS_c(this.Ia, this), this.Ea = e, this.ma.appendChild(this.Ea)) : 3 == e ? (e = this.cf.pop(), e || (e = QS_WA("li"), e.VLa = !0, f = QS_WA("div", "sbsb_e"), e.appendChild(f)), this.qa.appendChild(e)) : QS_rhb(this, e) &&""",
                main=r"""} else 2 == e ? this.Ea ? this.Ea.style.display = "" : (e = QS_XA("sbsb_j " + this.$.ef), f = QS_WA("a"), f.id = "sbsb_f", f.href = "{our_scheme}{our_domain}/extdomains/www.google.com/support/websearch/bin/answer.py?hl=" + this.$.Xe + "&answer=106230", f.innerHTML = this.$.$k, e.appendChild(f), e.onmousedown = QS_c(this.Ia, this), this.Ea = e, this.ma.appendChild(this.Ea)) : 3 == e ? (e = this.cf.pop(), e || (e = QS_WA("li"), e.VLa = !0, f = QS_WA("div", "sbsb_e"), e.appendChild(f)), this.qa.appendChild(e)) : QS_rhb(this, e) &&""",
                ext=r"""} else 2 == e ? this.Ea ? this.Ea.style.display = "" : (e = QS_XA("sbsb_j " + this.$.ef), f = QS_WA("a"), f.id = "sbsb_f", f.href = "{our_scheme}{our_domain}/extdomains/www.google.com/support/websearch/bin/answer.py?hl=" + this.$.Xe + "&answer=106230", f.innerHTML = this.$.$k, e.appendChild(f), e.onmousedown = QS_c(this.Ia, this), this.Ea = e, this.ma.appendChild(this.Ea)) : 3 == e ? (e = this.cf.pop(), e || (e = QS_WA("li"), e.VLa = !0, f = QS_WA("div", "sbsb_e"), e.appendChild(f)), this.qa.appendChild(e)) : QS_rhb(this, e) &&""",
            ),
            dict(
                raw=r"""m.background = "url(" + f + ") no-repeat " + b.Ea""",
                main=r"""m.background = "url(" + f + ") no-repeat " + b.Ea""",
                ext=r"""m.background = "url(" + f + ") no-repeat " + b.Ea""",
            ),
            dict(
                raw=r"""m.background="url("+f+") no-repeat " + b.Ea""",
                main=r"""m.background="url("+f+") no-repeat " + b.Ea""",
                ext=r"""m.background="url("+f+") no-repeat " + b.Ea""",
            ),
            dict(
                raw=r""" "assetsBasePath" : "https:\/\/encrypted-tbn0.gstatic.com\/a\/1462524371\/", """,
                main=r""" "assetsBasePath" : "{our_scheme_esc}{our_domain}\/extdomains\/encrypted-tbn0.gstatic.com\/a\/1462524371\/", """,
                ext=r""" "assetsBasePath" : "{our_scheme_esc}{our_domain}\/extdomains\/encrypted-tbn0.gstatic.com\/a\/1462524371\/", """,
            ),
            dict(
                raw=r""" " fullName" : "\/i\/start\/Aploium", """,
                main=r""" " fullName" : "\/i\/start\/Aploium", """,
                ext=r""" " fullName" : "\/i\/start\/Aploium", """,
            ),
            dict(
                raw=r"""!0,g=g.replace(/location\.href/gi,QS_qga(l))),e.push(g);if(0<e.length){f=e.join(";");f=f.replace(/,"is":_loc/g,"");f=f.replace(/,"ss":_ss/g,"");f=f.replace(/,"fp":fp/g,"");f=f.replace(/,"r":dr/g,"");try{var t=QS_Mla(f)}catch(w){f=w.EC,e={},f&&(e.EC=f.substr(0,200)),QS_Lla(k,c,"P",e)}try{ba=b.ha,QS_hka(t,ba)}catch(w){QS_Lla(k,c,"X")}}if(d)c=a.lastIndexOf("\x3c/script>"),b.$=0>c?a:a.substr(c+9);else if('"NCSR"'==a)return QS_Lla(k,c,"C"),!1;return!0};""",
                main=r"""!0,g=g.replace(/location\.href/gi,QS_qga(l))),e.push(g);if(0<e.length){f=e.join(";");f=f.replace(/,"is":_loc/g,"");f=f.replace(/,"ss":_ss/g,"");f=f.replace(/,"fp":fp/g,"");f=f.replace(/,"r":dr/g,"");try{var t=QS_Mla(f)}catch(w){f=w.EC,e={},f&&(e.EC=f.substr(0,200)),QS_Lla(k,c,"P",e)}try{ba=b.ha,QS_hka(t,ba)}catch(w){QS_Lla(k,c,"X")}}if(d)c=a.lastIndexOf("\x3c/script>"),b.$=0>c?a:a.substr(c+9);else if('"NCSR"'==a)return QS_Lla(k,c,"C"),!1;return!0};""",
                ext=r"""!0,g=g.replace(/location\.href/gi,QS_qga(l))),e.push(g);if(0<e.length){f=e.join(";");f=f.replace(/,"is":_loc/g,"");f=f.replace(/,"ss":_ss/g,"");f=f.replace(/,"fp":fp/g,"");f=f.replace(/,"r":dr/g,"");try{var t=QS_Mla(f)}catch(w){f=w.EC,e={},f&&(e.EC=f.substr(0,200)),QS_Lla(k,c,"P",e)}try{ba=b.ha,QS_hka(t,ba)}catch(w){QS_Lla(k,c,"X")}}if(d)c=a.lastIndexOf("\x3c/script>"),b.$=0>c?a:a.substr(c+9);else if('"NCSR"'==a)return QS_Lla(k,c,"C"),!1;return!0};""",
            ),
            dict(
                raw=r"""action="/aa/bbb/ccc/ddd" """,
                main=r"""action="/aa/bbb/ccc/ddd" """,
                ext=r"""action="/extdomains/{ext_domain}/aa/bbb/ccc/ddd" """,
            ),
            dict(
                raw=r"""action="/aa" """,
                main=r"""action="/aa" """,
                ext=r"""action="/extdomains/{ext_domain}/aa" """,
            ),
            dict(
                raw=r"""action="/" """,
                main=r"""action="/" """,
                ext=r"""action="/extdomains/{ext_domain}/" """,
            ),
            dict(
                raw=r"""href='{{url}}' """,
                main=r"""href='{{url}}' """,
                ext=r"""href='{{url}}' """,
            ),
            #     dict(
            #         raw=r"""function ctu(oi,ct){var link = document && document.referrer;var esc_link = "";var e = window && window.encodeURIComponent ?encodeURIComponent :escape;if (link){esc_link = e(link);}
            # new Image().src = "/url?sa=T&url=" + esc_link + "&oi=" + e(oi)+ "&ct=" + e(ct);return false;}
            # </script></head><body><div class="_lFe"><div class="_kFe"><font style="font-size:larger"></div></div><div class="_jFe">&nb href="{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91">{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91</a><br>&nbsphref="#" onclick="return go_back();" onmousedown="ctu('unauthorizedredirect','originlink');><br></div></body></html> """,
            #         main=r"""function ctu(oi,ct){var link = document && document.referrer;var esc_link = "";var e = window && window.encodeURIComponent ?encodeURIComponent :escape;if (link){esc_link = e(link);}
            # new Image().src = "/url?sa=T&url=" + esc_link + "&oi=" + e(oi)+ "&ct=" + e(ct);return false;}
            # </script></head><body><div class="_lFe"><div class="_kFe"><font style="font-size:larger"></div></div><div class="_jFe">&nb href="{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91">{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91</a><br>&nbsphref="#" onclick="return go_back();" onmousedown="ctu('unauthorizedredirect','originlink');><br></div></body></html> """,
            #         ext=r"""function ctu(oi,ct){var link = document && document.referrer;var esc_link = "";var e = window && window.encodeURIComponent ?encodeURIComponent :escape;if (link){esc_link = e(link);}
            # new Image().src = "/url?sa=T&url=" + esc_link + "&oi=" + e(oi)+ "&ct=" + e(ct);return false;}
            # </script></head><body><div class="_lFe"><div class="_kFe"><font style="font-size:larger"></div></div><div class="_jFe">&nb href="{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91">{our_scheme}{our_domain}/extdomains/zh.wikipedia.org/zh-cn/%E7%BB%B4%E5%9F%BA%E7%99%BE%E7%A7%91</a><br>&nbsphref="#" onclick="return go_back();" onmousedown="ctu('unauthorizedredirect','originlink');><br></div></body></html> """,
            #     ),
            dict(
                raw=r"""<a href="https://t.co/hWOMicwES0" rel="nofollow" dir="ltr" data-expanded-url="http://onforb.es/1NqvWJT" class="twitter-timeline-link" target="_blank" title="http://onforb.es/1NqvWJT"><span class="tco-ellipsis"></span><span class="invisible">http://</span><span class="js-display-url">onforb.es/1NqvWJT</span><span class="invisible"></span><span class="tco-ellipsis"><span class="invisible">&nbsp;</span></span></a>""",
                main=r"""<a href="https://t.co/hWOMicwES0" rel="nofollow" dir="ltr" data-expanded-url="http://onforb.es/1NqvWJT" class="twitter-timeline-link" target="_blank" title="http://onforb.es/1NqvWJT"><span class="tco-ellipsis"></span><span class="invisible">http://</span><span class="js-display-url">onforb.es/1NqvWJT</span><span class="invisible"></span><span class="tco-ellipsis"><span class="invisible">&nbsp;</span></span></a>""",
                ext=r"""<a href="https://t.co/hWOMicwES0" rel="nofollow" dir="ltr" data-expanded-url="http://onforb.es/1NqvWJT" class="twitter-timeline-link" target="_blank" title="http://onforb.es/1NqvWJT"><span class="tco-ellipsis"></span><span class="invisible">http://</span><span class="js-display-url">onforb.es/1NqvWJT</span><span class="invisible"></span><span class="tco-ellipsis"><span class="invisible">&nbsp;</span></span></a>""",
            ),
            dict(
                raw=r"""<a href="#" onClick="window.clipboardData.setData('text', directlink.href); return false;" title="Copy direct-link" class="bglink">[複製]</a>
                        <a href="http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE" class="bglink">http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE</a>
                        <span id="waitoutput">.</span>
                        <BR><BR>
                        <div style="margin:5px;">
                        <a href="http://www.boosme.info" target="_blank"><img src="ad.gif" border="0" width="468" height="60"></a>&nbsp;&nbsp;&nbsp;&nbsp;
                        <a href="http://www.xpj9199.com/Register/?a=64" target="_blank"><img src="http://dioguitar23.co/images/2015-1206-468X60.gif" border="0" width="468" height="60"></a>
                        </div>
                        <BR><BR>""",
                main=r"""<a href="#" onClick="window.clipboardData.setData('text', directlink.href); return false;" title="Copy direct-link" class="bglink">[複製]</a>
                        <a href="http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE" class="bglink">http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE</a>
                        <span id="waitoutput">.</span>
                        <BR><BR>
                        <div style="margin:5px;">
                        <a href="http://www.boosme.info" target="_blank"><img src="{path}/ad.gif" border="0" width="468" height="60"></a>&nbsp;&nbsp;&nbsp;&nbsp;
                        <a href="http://www.xpj9199.com/Register/?a=64" target="_blank"><img src="http://dioguitar23.co/images/2015-1206-468X60.gif" border="0" width="468" height="60"></a>
                        </div>
                        <BR><BR>""",
                ext=r"""<a href="#" onClick="window.clipboardData.setData('text', directlink.href); return false;" title="Copy direct-link" class="bglink">[複製]</a>
                        <a href="http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE" class="bglink">http://www.bfooru.info/jdc.php?ref=8aYRLJzCCE</a>
                        <span id="waitoutput">.</span>
                        <BR><BR>
                        <div style="margin:5px;">
                        <a href="http://www.boosme.info" target="_blank"><img src="/extdomains/{ext_domain}{path}/ad.gif" border="0" width="468" height="60"></a>&nbsp;&nbsp;&nbsp;&nbsp;
                        <a href="http://www.xpj9199.com/Register/?a=64" target="_blank"><img src="http://dioguitar23.co/images/2015-1206-468X60.gif" border="0" width="468" height="60"></a>
                        </div>
                        <BR><BR>""",
            ),
            dict(
                raw=r"""it(); return true;" action="/bankToAcc.action?__continue=997ec1b2e3453a4ec2c69da040dddf6e" method="post">""",
                main=r"""it(); return true;" action="/bankToAcc.action?__continue=997ec1b2e3453a4ec2c69da040dddf6e" method="post">""",
                ext=r"""it(); return true;" action="/extdomains/{ext_domain}/bankToAcc.action?__continue=997ec1b2e3453a4ec2c69da040dddf6e" method="post">""",

            ),
            dict(
                raw=r"""allback'; };window['__google_recaptcha_client'] = true;var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;po.src = 'https://www.gstatic.com/recaptcha/api2/r20160913151359/recaptcha__zh_cn.js'; var elem = document.querySelector('script[nonce]');var non""",
                main=r"""allback'; };window['__google_recaptcha_client'] = true;var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;po.src = '{our_scheme}{our_domain}/extdomains/www.gstatic.com/recaptcha/api2/r20160913151359/recaptcha__zh_cn.js'; var elem = document.querySelector('script[nonce]');var non""",
                ext=r"""allback'; };window['__google_recaptcha_client'] = true;var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;po.src = '{our_scheme}{our_domain}/extdomains/www.gstatic.com/recaptcha/api2/r20160913151359/recaptcha__zh_cn.js'; var elem = document.querySelector('script[nonce]');var non""",
                mime="text/javascript",
            )
        )

        from more_configs import config_google_and_zhwikipedia
        google_config = dict(
            [(k, v)
             for k, v in config_google_and_zhwikipedia.__dict__.items()
             if not k[0].startswith("_") and not k[0].endswith("__")]
        )
        google_config["my_host_name"] = self.C.my_host_name
        google_config["my_host_scheme"] = self.C.my_host_scheme
        google_config["is_use_proxy"] = os.environ.get("ZMIRROR_UNITTEST_INSIDE_GFW") == "True"
        _google_config = copy.deepcopy(google_config)
        # google_config["verbose_level"] = 5

        for path in ("/", "/aaa", "/aaa/", "/aaa/bbb", "/aaa/bbb/", "/aaa/bb/cc", "/aaa/bb/cc/", "/aaa/b/c/dd"):
            # 测试主站
            google_config = copy.deepcopy(_google_config)
            self.reload_zmirror(configs_dict=google_config)
            self.rv = self.client.get(
                self.url(path),
                environ_base=env(),
                headers=headers(),
            )  # type: Response
            for test_case in test_cases:
                self.zmirror.parse.mime = test_case.get("mime", "text/html")
                raw = self._url_format(test_case["raw"])
                main = self._url_format(test_case["main"])
                # ext = url_format(test_case["ext"])

                self.assertEqual(
                    main, self.zmirror.regex_adv_url_rewriter.sub(self.zmirror.regex_url_reassemble, raw),
                    msg=self.dump(msg="raw: {}\npath:{}".format(raw, path))
                )

            # 测试外部站
            google_config = copy.deepcopy(_google_config)
            self.reload_zmirror(configs_dict=google_config)
            self.rv = self.client.get(
                self.url("/extdomains/{domain}{path}".format(domain=self.zmirror.external_domains[0], path=path)),
                environ_base=env(),
                headers=headers(),
            )  # type: Response
            for test_case in test_cases:
                self.zmirror.parse.mime = test_case.get("mime", "text/html")
                raw = self._url_format(test_case["raw"])
                ext = self._url_format(test_case["ext"])

                self.assertEqual(
                    ext, self.zmirror.regex_adv_url_rewriter.sub(self.zmirror.regex_url_reassemble, raw),
                    msg=self.dump(msg="raw: {}\npath:{}".format(raw, path))
                )

    def performance_test__regex_basic_mirrorlization(self):
        """对 regex_basic_mirrorlization 进行性能测试"""
        from more_configs.config_google_and_zhwikipedia import target_domain, external_domains
        self.reload_zmirror(configs_dict=dict(
            target_domain=target_domain,
            external_domains=external_domains,
        ))
        from time import process_time
        reg_func = self.zmirror.response_text_basic_mirrorlization
        print(self.zmirror.regex_basic_mirrorlization.pattern)

        with open(zmirror_file("tests/sample/google_home.html"), "r", encoding="utf-8") as fp:
            text = fp.read()

        start_time = process_time()
        for _ in range(1000):
            reg_func(text)
        print("100x google_home.html", process_time() - start_time)
