# coding=utf-8
import os
import re
import zlib
import base64
from fnmatch import fnmatch
from html import escape as html_escape
from urllib.parse import urljoin, urlsplit, urlunsplit, quote_plus
from flask import make_response, Response

try:  # lru_cache的c语言实现, 比Python内置lru_cache更快
    from fastcache import lru_cache  # lru_cache用于缓存函数的执行结果
except:
    from functools import lru_cache

from . import CONSTS

import config as cfg


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
def is_mime_represents_text(input_mime):
    """
    Determine whether an mime is text (eg: text/html: True, image/png: False)
    :param input_mime: str
    :return: bool
    """
    input_mime_l = input_mime.lower()
    for text_word in cfg.text_like_mime_keywords:
        if text_word in input_mime_l:
            return True
    return False


@lru_cache(maxsize=128)
def extract_mime_from_content_type(_content_type):
    """从content-type中提取出mime, 如 'text/html; encoding=utf-8' --> 'text/html'
    :rtype: str
    """
    c = _content_type.find(';')
    if c == -1:
        return _content_type
    else:
        return _content_type[:c]


@lru_cache(maxsize=128)
def is_content_type_using_cdn(_content_type):
    """根据content-type确定该资源是否使用CDN"""
    _mime = extract_mime_from_content_type(_content_type)
    if _mime in cfg.mime_to_use_cdn:
        # dbgprint(content_type, 'Should Use CDN')
        return _mime
    else:
        # dbgprint(content_type, 'Should NOT CDN')
        return False


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


@lru_cache(maxsize=1024)
def check_global_ua_pass(ua_str):
    """该user-agent是否满足全局白名单"""
    if ua_str is None or not cfg.global_ua_white_name:
        return False
    ua_str = ua_str.lower()
    if cfg.global_ua_white_name in ua_str:
        return True
    else:
        return False


@lru_cache(maxsize=1024)
def is_domain_match_glob_whitelist(domain):
    """
    域名是否匹配 `domains_whitelist_auto_add_glob_list` 中设置的通配符
    :type domain: str
    :rtype: bool
    """
    for domain_glob in cfg.domains_whitelist_auto_add_glob_list:
        if fnmatch(domain, domain_glob):
            return True
    return False


@lru_cache(maxsize=128)
def is_content_type_streamed(_content_type):
    """
    根据content-type判断是否应该用stream模式传输(服务器下载的同时发送给用户)
     视频/音频/图片等二进制内容默认用stream模式传输
     :param _content_type: content_type, eg: "plain/text; encoding=utf-8"
     :type _content_type: str
     :rtype: bool
    """
    for streamed_keyword in cfg.steamed_mime_keywords:
        if streamed_keyword in _content_type:
            return True
    return False

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

# 在 cdn_redirect_encode_query_str_into_url 中用于标示编码进url的分隔串
cdn_url_query_encode_salt = 'zm26'
_url_salt = re.escape(cdn_url_query_encode_salt)

regex_extract_base64_from_embedded_url = re.compile(
    r'_' + _url_salt + r'(?P<gzip>z?)_\.(?P<b64>[a-zA-Z0-9-_]+=*)\._' + _url_salt + r'_\.[a-zA-Z\d]+\b')


@lru_cache(maxsize=1024)
def extract_real_url_from_embedded_url(embedded_url):
    """
    将 embed_real_url_to_embedded_url() 编码后的url转换为原来的带有参数的url
    `cdn_redirect_encode_query_str_into_url`设置依赖于本函数, 详细说明请看配置文件中这个参数的部分

    eg: https://cdn.domain.com/a.php_zm24_.cT1zb21ldGhpbmc=._zm24_.css
        ---> https://foo.com/a.php?q=something (assume it returns an css) (base64 only)
    eg2: https://cdn.domain.com/a/b/_zm24_.bG92ZT1saXZl._zm24_.jpg
        ---> https://foo.com/a/b/?love=live (assume it returns an jpg) (base64 only)
    eg3: https://cdn.domain.com/a/b/_zm24z_.[some long long base64 encoded string]._zm24_.jpg
        ---> https://foo.com/a/b/?love=live[and a long long query string] (assume it returns an jpg) (gzip + base64)
    eg4:https://cdn.domain.com/a  (no change)
        ---> (no query string): https://foo.com/a (assume it returns an png) (no change)
    :param embedded_url: 可能被编码的URL
    :return: 如果传入的是编码后的URL, 则返回解码后的URL, 否则返回None
    :type embedded_url: str
    :rtype: Union[str, None]
    """
    if '._' + cdn_url_query_encode_salt + '_.' not in embedded_url[-15:]:  # check url mark
        return None
    m = regex_extract_base64_from_embedded_url.search(embedded_url)
    b64 = get_group('b64', m)
    if not b64:
        return None

    # 'https://cdn.domain.com/a.php_zm24_.cT1zb21ldGhpbmc=._zm24_.css'
    # real_request_url_no_query ---> 'https://cdn.domain.com/a.php'
    real_request_url_no_query = embedded_url[:m.span()[0]]

    query_string_byte = base64.urlsafe_b64decode(b64)
    is_gzipped = get_group('gzip', m)
    if is_gzipped:
        query_string_byte = zlib.decompress(query_string_byte)
    query_string = query_string_byte.decode(encoding='utf-8')

    result = urljoin(real_request_url_no_query, '?' + query_string)
    # dbgprint('extract:', embedded_url, 'to', result)
    return result


@lru_cache(maxsize=1024)
def embed_real_url_to_embedded_url(real_url_raw, url_mime, escape_slash=False):
    """
    将url的参数(?q=some&foo=bar)编码到url路径中, 并在url末添加一个文件扩展名
    在某些对url参数支持不好的CDN中, 可以减少错误
    `cdn_redirect_encode_query_str_into_url`设置依赖于本函数, 详细说明可以看配置文件中的对应部分
    解码由 extract_real_url_from_embedded_url() 函数进行, 对应的例子也请看这个函数
    :rtype: str
    """
    # dbgprint(real_url_raw, url_mime, escape_slash)
    if escape_slash:
        real_url = real_url_raw.replace(r'\/', '/')
    else:
        real_url = real_url_raw
    url_sp = urlsplit(real_url)
    if not url_sp.query:  # no query, needn't rewrite
        return real_url_raw

    byte_query = url_sp.query.encode()
    if len(byte_query) > 128:  # 当查询参数太长时, 进行gzip压缩
        gzip_label = 'z'  # 进行压缩后的参数, 会在标识区中添加一个z
        byte_query = zlib.compress(byte_query)
    else:
        gzip_label = ''

    b64_query = base64.urlsafe_b64encode(byte_query).decode()
    # dbgprint(url_mime)
    mixed_path = url_sp.path + '_' + _url_salt + gzip_label + '_.' \
                 + b64_query \
                 + '._' + _url_salt + '_.' + cfg.mime_to_use_cdn[url_mime]
    result = urlunsplit((url_sp.scheme, url_sp.netloc, mixed_path, '', ''))

    if escape_slash:
        result = s_esc(result)
        # dbgprint('embed:', real_url_raw, 'to:', result)
    return result
