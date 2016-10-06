# coding=utf-8
import os
import re
import zlib
import base64
from html import escape as html_escape
from urllib.parse import urljoin, urlsplit, urlunsplit, quote_plus
from flask import make_response, Response

try:
    from typing import Union, Tuple  # for python 3.5+ type hint
except:
    pass

try:  # lru_cache的c语言实现, 比Python内置lru_cache更快
    from fastcache import lru_cache  # lru_cache用于缓存函数的执行结果
except:
    from functools import lru_cache

from . import CONSTS


def zmirror_root(filename):
    return os.path.join(CONSTS.ZMIRROR_ROOT, filename)


@lru_cache(maxsize=1024)
def s_esc(s):
    """
    equivalent to s.replace("/",r"\/")
    :type s: str
    :rtype: str
    """
    return s.replace("/", r"\/")


def extract_root_domain(domain):
    """
    提取出一个域名的根域名
    支持二级顶级域名, 允许包含端口(端口会被舍去)

    :param domain: eg: dwn.cdn.google.co.jp[:233]
    :type domain: str
    :return: root_domain, sub_domain
    :rtype: Tuple[str, str]
    """
    domain = domain.rstrip("0123456789").rstrip(":").strip(".")
    temp = domain.split('.')

    # 粗略判断是否是二级顶级域名
    is_level2_tld = len(temp[-1]) <= 3 and temp[-2] in ('com', 'net', 'org', 'co', 'edu', 'mil', 'gov', 'ac')

    if len(temp) <= 2 or len(temp) == 3 and is_level2_tld:
        # 它本身就是一个根域名
        return domain, ""
    elif is_level2_tld:
        return ".".join(temp[-3:]), ".".join(temp[:-3])
    else:
        return '.'.join(temp[-2:]), ".".join(temp[:-2])


# noinspection PyShadowingNames
def calc_domain_replace_prefix(_domain):
    """生成各种形式的scheme变体
    :type _domain: str
    :rtype: bool
    """
    return dict(
        # normal
        slash='//' + _domain,
        http='http://' + _domain,
        https='https://' + _domain,
        double_quoted='"%s"' % _domain,
        single_quoted="'%s'" % _domain,
        # hex
        hex_lower=('//' + _domain).replace('/', r'\x2f'),
        hex_upper=('//' + _domain).replace('/', r'\x2F'),
        # escape slash
        slash_esc=s_esc('//' + _domain),
        http_esc=s_esc('http://' + _domain),
        https_esc=s_esc('https://' + _domain),
        double_quoted_esc=r'\"%s\"' % _domain,
        single_quoted_esc=r"\'%s\'" % _domain,
        # double escape slash
        slash_double_esc=('//' + _domain).replace('/', r'\\/'),
        http_double_esc=('http://' + _domain).replace('/', r'\\/'),
        https_double_esc=('https://' + _domain).replace('/', r'\\/'),
        # triple escape slash
        slash_triple_esc=('//' + _domain).replace('/', r'\\\/'),
        http_triple_esc=('http://' + _domain).replace('/', r'\\\/'),
        https_triple_esc=('https://' + _domain).replace('/', r'\\\/'),
        # urlencoded
        slash_ue=quote_plus('//' + _domain),
        http_ue=quote_plus('http://' + _domain),
        https_ue=quote_plus('https://' + _domain),
        double_quoted_ue=quote_plus('"%s"' % _domain),
        single_quoted_ue=quote_plus("'%s'" % _domain),
        # escaped and urlencoded
        slash_esc_ue=quote_plus(s_esc('//' + _domain)),
        http_esc_ue=quote_plus(s_esc('http://' + _domain)),
        https_esc_ue=quote_plus(s_esc('https://' + _domain)),
    )


def current_line_number():
    """Returns the current line number in our program.
    :return: current line number
    :rtype: int
    """
    import inspect
    return inspect.currentframe().f_back.f_lineno


def generate_simple_resp_page(errormsg=b'We Got An Unknown Error', error_code=500):
    """

    :type errormsg: bytes
    :type error_code: int
    :rtype: Response
    """
    return make_response(errormsg, error_code)


@lru_cache(maxsize=128)
def extract_mime_from_content_type(_content_type):
    """从content-type中提取出mime, 如 'text/html; encoding=utf-8' --> 'text/html'
    :rtype: str
    """
    c = _content_type.find(';')
    if c == -1:
        return _content_type.lower()
    else:
        return _content_type[:c].lower()


def get_group(name, match_obj):
    """return a blank string if the match group is None"""
    try:
        obj = match_obj.group(name)
    except:
        return ''
    else:
        if obj is not None:
            return obj
        else:
            return ''


def get_ext_domain_inurl_scheme_prefix(ext_domain, force_https=None):
    """旧版本遗留函数, 已经不再需要, 永远返回空字符串"""
    return ''


def strx(*args):
    """
    :return: str
    """
    output = ''
    for arg in args:
        output += str(arg) + ' '
    output.rstrip(' ')
    return output


def generate_html_redirect_page(target_url, msg='', delay_sec=1):
    """生成一个HTML重定向页面
    某些浏览器在301/302页面不接受cookies, 所以需要用html重定向页面来传cookie
    :type target_url: str
    :type msg: str
    :type delay_sec: int
    :rtype: Response
    """
    resp_content = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>重定向 (Page Redirect)</title>
<meta http-equiv="refresh" content="%d; url=%s">
<script>setTimeout(function(){location.href="%s"} , %d000);</script>
</head>
<body>
<pre>%s</pre>
<hr />
You are now redirecting to <a href="%s">%s</a>, if it didn't redirect automatically, please click that link.
</body>
</html>""" % (
        delay_sec, html_escape(target_url), html_escape(target_url), delay_sec + 1,
        html_escape(msg), html_escape(target_url), html_escape(target_url)
    )
    resp_content = resp_content.encode('utf-8')
    return Response(response=resp_content)



@lru_cache(maxsize=64)
def guess_colon_from_slash(slash):
    """根据 slash(/) 的格式, 猜测最有可能与之搭配的 colon(:) 格式"""
    if "%" not in slash:
        return ":"  # slash没有转义, 直接原文
    elif "%25" in slash:
        # %252F %252f
        if "F" in slash:
            return "%253A"
        else:
            return "%253a"
    else:
        # %2F %2f
        if "F" in slash:
            return "%3A"
        else:
            return "%3a"


def attributes(var, to_dict=False, max_len=1024):
    output = {} if to_dict else ""
    for name in dir(var):
        if name[0] != '_' and name[-2:] != '__':
            value = str(getattr(var, name))

            if max_len:
                length = len(value)
                if length > max_len:
                    value = value[:max_len] + "....(total:{})".format(length)

            if to_dict:
                output[name] = value
            else:
                output += strx(name, ":", value, "\n")
    return output


def inject_content(position, html, content):
    """
    将文本内容注入到html中
    详见 default_config.py 的 `Custom Content Injection` 部分
    :param position: 插入位置
    :type position: str
    :param html: 原始html
    :type html: str
    :param content: 等待插入的自定义文本内容
    :type content: str
    :return: 处理后的html
    :rtype: str
    """
    if position == "head_first":
        return inject_content_head_first(html, content)
    elif position == "head_last":
        return inject_content_head_last(html, content)
    else:  # coverage: exclude
        raise ValueError("Unknown Injection Position: {}".format(position))


def inject_content_head_first(html, content):
    """
    将文本内容插入到head中第一个现有<script>之前
    如果head中不存在<script>, 则加在</head>标签之前

    :type html: str
    :type content: str
    :rtype: str
    """
    head_end_pos = html.find("</head")  # 找到 </head> 标签结束的位置
    script_begin_pos = html.find("<script")  # 找到第一个 <script> 开始的地方

    if head_end_pos == -1:  # coverage: exclude
        # 如果没有 </head> 就不进行插入
        return html

    if script_begin_pos != -1 and script_begin_pos < head_end_pos:
        # 如果<head>中存在<script>标签, 则插入到第一个 <script> 标签之前
        return html[:script_begin_pos] + content + html[script_begin_pos:]

    else:
        # 如果<head>中 *不* 存在<script>标签, 则插入到 </head> 之前
        return html[:head_end_pos] + content + html[head_end_pos:]


def inject_content_head_last(html, content):
    """
    将文本内容插入到head的尾部

    :type html: str
    :type content: str
    :rtype: str
    """
    head_end_pos = html.find("</head")  # 找到 </head> 标签结束的位置

    if head_end_pos == -1:
        # 如果没有 </head> 就不进行插入
        return html

    return html[:head_end_pos] + content + html[head_end_pos:]
