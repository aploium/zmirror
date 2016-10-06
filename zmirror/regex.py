# coding=utf-8
import re
from zmirror import cfg

# ########### PreCompile Regex ###############

# 冒号(colon :)可能的值为:
#    : %3A %253A  完整列表见 tests.TestRegex.REGEX_POSSIBLE_COLON
REGEX_COLON = r"""(?::|%(?:25)?3[Aa])"""
# 斜线(slash /)可能的值为(包括大小写):
# 完整列表见 tests.TestRegex.REGEX_POSSIBLE_COLON
#    / \/ \\/ \\\(N个反斜线)/ %2F %5C%2F %5C%5C(N个5C)%2F %255C%252F %255C%255C%252F \x2F
REGEX_SLASH = r"""(?:\\*(?:/|x2[Ff])|%(?:(?:25)?5[Cc]%)*(?:25)?2[Ff])"""
# 引号 可能值的完整列表见 tests.TestRegex.REGEX_POSSIBLE_QUOTE
# " ' \\(可能有N个反斜线)' \\(可能有N个反斜线)"
# %22 %27 %5C(可能N个5C)%22 %5C(可能N个5C)%27
# %2522 %2527 %255C%2522 %255C%2527
# &quot;
REGEX_QUOTE = r"""(?:\\*["']|%(?:(?:25)?5[Cc]%)*2(?:52)?[27]|&quot;)"""

# 代表本镜像域名的正则
if cfg.my_host_port is not None:
    REGEX_MY_HOST_NAME = r'(?:' + re.escape(cfg.my_host_name_no_port) + REGEX_COLON + re.escape(str(cfg.my_host_port)) \
                         + r'|' + re.escape(cfg.my_host_name_no_port) + r')'
else:
    REGEX_MY_HOST_NAME = re.escape(cfg.my_host_name)

# Advanced url rewriter, see function response_text_rewrite()
# #### 这个正则表达式是整个程序的最核心的部分, 它的作用是从 html/css/js 中提取出长得类似于url的东西 ####
# 如果需要阅读这个表达式, 请一定要在IDE(如PyCharm)的正则高亮下阅读
# 这个正则并不保证匹配到的东西一定是url, 在 regex_url_reassemble() 中会进行进一步验证是否是url
regex_adv_url_rewriter = re.compile(
    # 前缀, 必须有  'action='(表单) 'href='(链接) 'src=' 'url('(css) '@import'(css) '":'(js/json, "key":"value")
    # \s 表示空白字符,如空格tab
    r"""(?P<prefix>\b(?:(?:src|href|action)\s*=|url\s*\(|@import\s*|"\s*:)\s*)""" +  # prefix, eg: src=
    # 左边引号, 可选 (因为url()允许没有引号). 如果是url以外的, 必须有引号且左右相等(在重写函数中判断, 写在正则里可读性太差)
    r"""(?P<quote_left>["'])?""" +  # quote  "'
    # 域名和协议头, 可选. http:// https:// // http:\/\/ (json) https:\/\/ (json) \/\/ (json)
    r"""(?P<domain_and_scheme>(?P<scheme>(?:https?:)?\\?/\\?/)(?P<domain>(?:[-a-z0-9]+\.)+[a-z]+(?P<port>:\d{1,5})?))?""" +
    # url路径, 含参数 可选
    r"""(?P<path>[^\s;+$?#'"\{}]*?""" +  # full path(with query string)  /foo/bar.js?love=luciaZ
    # 查询字符串, 可选
    r"""(?P<query_string>\?[^\s?#'"]*?)?)""" +  # query string  ?love=luciaZ
    # 右引号(可以是右括弧), 必须
    r"""(?P<quote_right>["')])(?P<right_suffix>\W)""",  # right quote  "'
    flags=re.IGNORECASE
)

# Response Cookies Rewriter, see response_cookie_rewrite()
regex_cookie_rewriter = re.compile(r'\bdomain=(\.?([\w-]+\.)+\w+)\b', flags=re.IGNORECASE)
regex_cookie_path_rewriter = re.compile(r'(?P<prefix>[pP]ath)=(?P<path>[\w\._/-]+?;)')

# Request Domains Rewriter, see client_requests_text_rewrite()
# 该正则用于匹配类似于下面的东西
#   [[[http(s):]//]www.mydomain.com/]extdomains/(https-)target.com
# 兼容各种urlencode/escape
#
# 注意, 若想阅读下面的正则表达式, 请一定要在 Pycharm 的正则高亮下进行
# 否则不对可能的头晕/恶心负责
# 下面那个正则, 在组装以后的样子大概是这样的(已大幅简化):
# 假设b.test.com是本机域名
#   ((https?:/{2})?b\.test\.com/)?extdomains/(https-)?((?:[\w-]+\.)+\w+)\b
#
# 对应的 unittest 见 TestRegex.test__regex_request_rewriter_extdomains()
regex_request_rewriter_extdomains = re.compile(
    r"""(?P<domain_prefix>""" +
    (  # [[[http(s):]//]www.mydomain.com/]
        r"""(?P<scheme>""" +
        (  # [[http(s):]//]
            (  # [http(s):]
                r"""(?:https?(?P<colon>{REGEX_COLON}))?""".format(REGEX_COLON=REGEX_COLON)  # https?:
            ) +
            r"""(?P<scheme_slash>%s)(?P=scheme_slash)""" % REGEX_SLASH  # //
        ) +
        r""")?""" +
        REGEX_MY_HOST_NAME +  # www.mydomain.com[:port] 本部分的正则在上面单独组装
        r"""(?P<slash2>(?(scheme_slash)(?P=scheme_slash)|{REGEX_SLASH}))""".format(REGEX_SLASH=REGEX_SLASH)  # # /
    ) +
    r""")?""" +

    r"""extdomains(?(slash2)(?P=slash2)|{REGEX_SLASH})(?P<is_https>https-)?""".format(
        REGEX_SLASH=REGEX_SLASH) +  # extdomains/(https-)
    r"""(?P<real_domain>(?:[\w-]+\.)+\w+)\b""",  # target.com
    flags=re.IGNORECASE,
)
regex_request_rewriter_main_domain = re.compile(REGEX_MY_HOST_NAME)


# 以下正则为*实验性*的 response_text_basic_rewrite() 的替代品
# 用于函数 response_text_basic_mirrorlization()
# 理论上, 在大量域名的情况下, 会比现有的暴力字符串替换要快, 并且未来可以更强大的域名通配符
# v0.28.0加入, v0.28.3后默认启用
def regex_generate__basic_mirrorlization():
    """产生 regex_basic_mirrorlization
    用一个函数包裹起来是因为在 try_match_and_add_domain_to_rewrite_white_list()
    中需要动态修改 external_domains, 修改以后可能需要随之生成新的正则, 包裹一下比较容易调用
    """
    from collections import Counter

    # 统计各个后缀出现的频率, 并且按照出现频率降序排列, 有助于提升正则效率
    c = Counter(re.escape(x.split(".")[-1]) for x in cfg.allowed_domains_set)
    regex_all_remote_tld = sorted(list(c.keys()), key=lambda x: c[x], reverse=True)

    regex_all_remote_tld = "(?:" + "|".join(regex_all_remote_tld) + ")"
    return re.compile(
        r"""(?:""" +
        (  # [[http(s):]//] or [\?["']] or %27 %22 or &quot;
            r"""(?P<scheme>""" +
            (  # [[http(s):]//]
                (  # [http(s):]
                    r"""(?:https?(?P<colon>{REGEX_COLON}))?""".format(REGEX_COLON=REGEX_COLON)  # https?:
                ) +
                r"""(?P<scheme_slash>%s)(?P=scheme_slash)""" % REGEX_SLASH  # //
            ) +
            r""")""" +
            r"""|""" +
            # [\?["']] or %27 %22 or &quot
            r"""(?P<quote>{REGEX_QUOTE})""".format(REGEX_QUOTE=REGEX_QUOTE)
        ) +
        r""")""" +
        # End prefix.
        # Begin domain
        r"""(?P<domain>([a-zA-Z0-9-]+\.){1,5}%s)\b""" % regex_all_remote_tld +
        # Optional suffix slash
        r"""(?P<suffix_slash>(?(scheme_slash)(?P=scheme_slash)|{SLASH}))?""".format(SLASH=REGEX_SLASH) +

        # right quote (if we have left quote)
        r"""(?(quote)(?P=quote))"""
    )


regex_basic_mirrorlization = regex_generate__basic_mirrorlization()

# 用于移除掉cookie中类似于 zmirror_verify=75bf23086a541e1f; 的部分
regex_remove__zmirror_verify__header = re.compile(
    r"""zmirror_verify=[a-zA-Z0-9]+\b;? ?"""
)


