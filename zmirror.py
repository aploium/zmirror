#!/usr/bin/env python3
# coding=utf-8
import os
# noinspection PyUnresolvedReferences
from itertools import count

if os.path.dirname(__file__) != '':
    os.chdir(os.path.dirname(__file__))
import traceback
import pickle
from datetime import datetime, timedelta
import re
import base64
import zlib
import random
import sched
import copy
from time import time, sleep
import queue
from fnmatch import fnmatch
from html import escape as html_escape
from urllib.parse import urljoin, urlsplit, urlunsplit, quote_plus

try:
    from typing import Union, List, Any, Tuple  # for python 3.5+ Type Hint
except:
    pass

import requests
from flask import Flask, request, make_response, Response, redirect
from ColorfulPyPrint import *  # TODO: Migrate logging tools to the stdlib

__VERSION__ = '0.24.1'
__AUTHOR__ = 'Aploium <i@z.codes>'
__GITHUB_URL__ = 'https://github.com/aploium/zmirror'

infoprint('zmirror version: {version} author: {author}'.format(version=__VERSION__, author=__AUTHOR__))
infoprint('Github: {site_url}'.format(site_url=__GITHUB_URL__))

try:
    import threading
except ImportError:  # 在某些罕见的系统环境下,threading包可能失效,用dummy代替
    import dummy_threading as threading

try:  # 用于检测html的文本编码, cchardet是chardet的c语言实现, 非常快
    from cchardet import detect as c_chardet
except:
    cchardet_available = False
else:
    cchardet_available = True

try:  # lru_cache的c语言实现, 比Python内置lru_cache更快
    from fastcache import lru_cache  # lru_cache用于缓存函数的执行结果
except:
    from functools import lru_cache

    warnprint('package fastcache not found, fallback to stdlib lru_cache, no FUNCTION is effected, only maybe a bit slower. '
              'Considering install it using "pip3 install fastcache"')
else:
    infoprint('lru_cache loaded successfully from fastcache')

try:  # 加载默认设置
    from config_default import *
except:
    traceback.print_exc()
    errprint('the config_default.py is missing, this program may not works normally\n'
             'config_default.py 文件丢失, 这会导致配置文件不向后兼容, 请重新下载一份 config_default.py')
    raise  # v0.23.1+ 当 config_default.py 不存在时, 程序会终止运行

try:  # 加载用户自定义配置文件, 覆盖掉默认配置的同名项
    from config import *
except:
    traceback.print_exc()
    errprint(
        'the config_default.py is missing, fallback to default configs(if we can), '
        'please COPY the config_default.py to config.py, and change it\'s content, '
        'or use the configs in the more_configs folder\n'
        '自定义配置文件 config.py 丢失或存在错误, 将使用默认设置, 请将 config_default.py 复制一份为 config.py, '
        '并根据自己的需求修改里面的设置'
        '(或者使用 more_configs 中的配置文件)'
    )
    raise  # v0.23.1+ 当config文件存在错误或不存在时, 程序会终止运行
else:
    infoprint('config file found')

if local_cache_enable:
    try:
        from cache_system import FileCache, get_expire_from_mime

        cache = FileCache()
    except Exception as e:
        traceback.print_exc()
        errprint('Can Not Create Local File Cache: ', e, ' local file cache is disabled automatically.')
        local_cache_enable = False
    else:
        infoprint('Local file cache enabled')

# ########## Basic Init #############
# 开始从配置文件加载配置, 在读代码时可以先跳过这部分, 从 main_function() 开始看
ColorfulPyPrint_set_verbose_level(verbose_level)
my_host_name_no_port = my_host_name  # 不带有端口号的本机域名

if my_host_port is not None:
    my_host_name += ':' + str(my_host_port)  # 带有端口号的本机域名, 如果为标准端口则不带显式端口号
    my_host_name_urlencoded = quote_plus(my_host_name)  # url编码后的
else:
    my_host_name_urlencoded = my_host_name
static_file_extensions_list = set(static_file_extensions_list)
external_domains_set = set(external_domains or [])
allowed_domains_set = external_domains_set.copy()
allowed_domains_set.add(target_domain)
for _domain in external_domains:  # for support domain with port
    allowed_domains_set.add(urlsplit('http://' + _domain).hostname)

domain_alias_to_target_set = set()  # 那些被视为主域名的域名, 如 www.google.com和google.com可以都被视为主域名
domain_alias_to_target_set.add(target_domain)
domains_alias_to_target_domain = list(domains_alias_to_target_domain)
if domains_alias_to_target_domain:
    for _domain in domains_alias_to_target_domain:
        allowed_domains_set.add(_domain)
        domain_alias_to_target_set.add(_domain)
    domains_alias_to_target_domain.append(target_domain)
else:
    domains_alias_to_target_domain = [target_domain]
my_host_scheme_escaped = my_host_scheme.replace('/', r'\/')
myurl_prefix = my_host_scheme + my_host_name  # http(s)://www.my-mirror-site.com  末尾没有反斜线
myurl_prefix_escaped = myurl_prefix.replace('/', r'\/')
cdn_domains_number = len(CDN_domains)
allowed_remote_response_headers = {
    'content-type', 'date', 'expires', 'cache-control', 'last-modified', 'server', 'location',
    'accept-ranges',
    'access-control-allow-origin', 'access-control-allow-headers', 'access-control-allow-methods',
    'access-control-expose-headers', 'access-control-max-age', 'access-control-allow-credentials',
    'timing-allow-origin',
}
allowed_remote_response_headers.update(custom_allowed_remote_headers)
# ## Get Target Domain and MyHostName's Root Domain ##
# 解析目标域名和本机域名的根域名, 如 www.foobar.com 的根域名为 foobar.com
# 但是 www.aaa.foobar.com 的根域名会被认为是 aaa.foobar.com
# 支持二级顶级域名, 如 www.white.ac.cn
temp = target_domain.split('.')
if len(temp) <= 2 or len(temp) == 3 and temp[1] in ('com', 'net', 'org', 'co', 'edu', 'mil', 'gov', 'ac'):
    target_domain_root = target_domain
else:
    target_domain_root = '.'.join(temp[1:])
temp = my_host_name.split('.')
if len(temp) <= 2 or len(temp) == 3 and temp[1] in ('com', 'net', 'org', 'co', 'edu', 'mil', 'gov', 'ac'):
    my_host_name_root = target_domain
else:
    my_host_name_root = '.'.join(temp[1:])

# keep-alive的连接池, 每个域名保持一个keep-alive连接
# 借用requests在同一session中, 自动保持keep-alive的特性
connection_pool_per_domain = {}
if enable_keep_alive_per_domain:
    for _domain in allowed_domains_set:
        connection_pool_per_domain[_domain] = {'session': requests.Session(),}

# 在 cdn_redirect_encode_query_str_into_url 中用于标示编码进url的分隔串
cdn_url_query_encode_salt = 'zm24'
_url_salt = re.escape(cdn_url_query_encode_salt)
if cdn_redirect_encode_query_str_into_url:
    # 两个选项冲突. 当本选项开启时, 会清空掉 `target_static_domains`
    target_static_domains = set()

# ## thread local var ##
# 与flask的request变量功能类似, 存储了一些解析后的请求信息, 在程序中会经常被调用
this_request = threading.local()
this_request.start_time = None  # 处理请求开始的时间, unix
this_request.content_type = ''  # 远程服务器响应头中的content_type
this_request.mime = ''  # 远程服务器响应的MIME
this_request.cache_control = ''  # 远程服务器响应的cache_control内容
this_request.temporary_domain_alias = None  # 用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项
this_request.remote_domain = ''  # 当前请求对应的远程域名
this_request.is_https = ''  # 是否需要用https来请求远程域名
this_request.remote_url = ''  # 远程服务器的url
# this_request.url_no_scheme = ''  # 没有 http(s):// 前缀的url
this_request.remote_path = ''  # 对应的远程path
this_request.remote_path_query = ''  # 对应的远程path+query string
this_request.remote_response = None  # 远程服务器的响应, requests.Response

# task_scheduler
task_scheduler = sched.scheduler(time, sleep)
# ########## Handle dependencies #############
if not enable_static_resource_CDN:
    mime_based_static_resource_CDN = False
    disable_legacy_file_recognize_method = True
if not mime_based_static_resource_CDN:
    cdn_redirect_code_if_cannot_hard_rewrite = 0  # record incoming urls if we should use cdn on it

# 记录一个URL的一些信息, 以及是否应该使用CDN
# 结构例子见下
url_to_use_cdn = {
    "www.fake-domain.com/folder/foo/bar.png":
        [True,  # Should this url use CDN
         "image/png",  # MIME
         17031,  # size, if size too small, will not redirect to cdn
         ]
}

if not isinstance(target_static_domains, set):
    target_static_domains = set()
if not enable_stream_content_transfer:
    steamed_mime_keywords = ()

if not url_custom_redirect_enable:
    url_custom_redirect_list = {}
    url_custom_redirect_regex = ()
    shadow_url_redirect_regex = ()
    plain_replace_domain_alias = ()

if not enable_stream_content_transfer:
    enable_stream_transfer_async_preload = False

if not enable_automatic_domains_whitelist:
    domains_whitelist_auto_add_glob_list = tuple()

if not enable_individual_sites_isolation:
    isolated_domains = set()
else:
    for isolated_domain in isolated_domains:
        if isolated_domain not in external_domains_set:
            warnprint('An isolated domain:', isolated_domain,
                      'would not have effect because it did not appears in the `external_domains` list')

if enable_custom_access_cookie_generate_and_verify:
    human_ip_verification_whitelist_from_cookies = False

if not is_use_proxy:
    requests_proxies = None
if human_ip_verification_enabled:
    import ipaddress

    buff = []
    for network in human_ip_verification_default_whitelist_networks:
        buff.append(ipaddress.ip_network(network, strict=False))
    human_ip_verification_default_whitelist_networks = tuple(buff)
    for question in human_ip_verification_questions:
        human_ip_verification_answers_hash_str += question[1]
else:
    identity_verify_required = False
    human_ip_verification_whitelist_from_cookies = False
    must_verify_cookies = False
if not human_ip_verification_whitelist_from_cookies and not enable_custom_access_cookie_generate_and_verify:
    must_verify_cookies = False

url_rewrite_cache = {}  # an VERY Stupid and VERY Experimental Cache
url_rewrite_cache_hit_count = 0
url_rewrite_cache_miss_count = 0

# ########### PreCompile Regex ###############
# Advanced url rewriter, see function response_text_rewrite()
# #### 这个正则表达式是整个程序的最核心的部分, 它的作用是从 html/css/js 中提取出长得类似于url的东西 ####
# 如果需要阅读这个表达式, 请一定要在IDE(如PyCharm)的正则高亮下阅读
# 这个正则并不保证匹配到的东西一定是url, 在 regex_url_reassemble() 中会进行进一步验证是否是url
regex_adv_url_rewriter = re.compile(
    # 前缀, 必须有  'action='(表单) 'href='(链接) 'src=' 'url('(css) '@import'(css) '":'(js/json, "key":"value")
    # \s 表示空白字符,如空格tab
    r"""(?P<prefix>\b((action|href|src)\s*=|url\s*\(|@import\s*|"\s*:)\s*)""" +  # prefix, eg: src=
    # 左边引号, 可选 (因为url()允许没有引号). 如果是url以外的, 必须有引号且左右相等(在重写函数中判断, 写在正则里可读性太差)
    r"""(?P<quote_left>["'])?""" +  # quote  "'
    # 域名和协议头, 可选. http:// https:// // http:\/\/ (json) https:\/\/ (json) \/\/ (json)
    r"""(?P<domain_and_scheme>(?P<scheme>(https?:)?\\?/\\?/)(?P<domain>([-a-z0-9]+\.)+[a-z]+(?P<port>:\d{1,5})?))?""" +
    # url路径, 含参数 可选
    r"""(?P<path>[^\s;+$?#'"\{}]*?""" +  # full path(with query string)  /foo/bar.js?love=luciaZ
    # url中的扩展名, 仅在启用传统的根据扩展名匹配静态文件时打开
    (r"""(\.(?P<ext>[-_a-z0-9]+?))?""" if not disable_legacy_file_recognize_method else '') +  # file ext
    # 查询字符串, 可选
    r"""(?P<query_string>\?[^\s?#'"]*?)?)""" +  # query string  ?love=luciaZ
    # 右引号(可以是右括弧), 必须
    r"""(?P<quote_right>["'\)])(?P<right_suffix>\W)""",  # right quote  "'
    flags=re.IGNORECASE
)

regex_extract_base64_from_embedded_url = re.compile(
    r'_' + _url_salt + r'(?P<gzip>z?)_\.(?P<b64>[a-zA-Z0-9-_]+=*)\._' + _url_salt + r'_\.[a-zA-Z\d]+\b')

# Response Cookies Rewriter, see response_cookie_rewrite()
regex_cookie_rewriter = re.compile(r'\bdomain=(\.?([\w-]+\.)+\w+)\b', flags=re.IGNORECASE)
regex_cookie_path_rewriter = re.compile(r'(?P<prefix>[pP]ath)=(?P<path>[\w\._/-]+?;)')
# Request Domains Rewriter, see client_requests_text_rewrite()
if my_host_port is not None:
    temp = r'(' + re.escape(my_host_name) + r'|' + re.escape(my_host_name_no_port) + r')'
else:
    temp = re.escape(my_host_name)
regex_request_rewriter = re.compile(
    temp + r'(/|(%2F))extdomains(/|(%2F))(https-)?(?P<origin_domain>\.?([\w-]+\.)+\w+)\b',
    flags=re.IGNORECASE)

# Flask main app
app = Flask(__name__)


# ########## Begin Utils #############

def cache_clean(is_force_flush=False):
    """
    清理程序运行中产生的垃圾, 在程序运行期间会被自动定期调用
    包括各种重写缓存, 文件缓存等
    默认仅清理过期的
    :param is_force_flush: 是否无视有效期, 清理所有缓存
    :type is_force_flush: bool
    """
    global url_rewrite_cache, cache, url_to_use_cdn, connection_pool_per_domain
    if len(url_rewrite_cache) > 16384:
        url_rewrite_cache.clear()
    if len(url_to_use_cdn) > 40960:
        url_to_use_cdn.clear()

    if enable_keep_alive_per_domain:
        connection_pool_per_domain.clear()

    try:
        if local_cache_enable:
            cache.check_all_expire(force_flush_all=is_force_flush)
    except:
        errprint('ErrorWhenCleaningLocalCache, is_force_flush=', is_force_flush)
        traceback.print_exc()

    if is_force_flush:
        try:
            is_domain_match_glob_whitelist.cache_clear()
            is_content_type_streamed.cache_clear()
            extract_real_url_from_embedded_url.cache_clear()
            embed_real_url_to_embedded_url.cache_clear()
            check_global_ua_pass.cache_clear()
            is_mime_represents_text.cache_clear()
            extract_mime_from_content_type.cache_clear()
            is_content_type_using_cdn.cache_clear()
            is_ua_in_whitelist.cache_clear()
            verify_ip_hash_cookie.cache_clear()
            is_denied_because_of_spider.cache_clear()
            is_ip_not_in_allow_range.cache_clear()
            # client_requests_text_rewrite.cache_clear()
            # extract_url_path_and_query.cache_clear()
        except:
            errprint('ErrorWhenCleaningFunctionLruCache')
            traceback.print_exc()


def cron_task_container(task_dict, add_task_only=False):
    """
    定时任务容器. 调用目标函数, 并在运行结束后创建下一次定时

    :param task_dict: 定时任务的相关参数, dict
      { "target":目标函数(可调用的函数对象,不是函数名字符串) 必须,
        "iterval":任务延时(秒) 可选,
        "priority":优先级 可选,
        "name":定时任务别名 可选
        "args":位置型参数 (arg1,arg2) 可选,
        "kwargs":键值型参数 {key:value,} 可选,
      }
    :param add_task_only: 是否只添加定时任务而不执行
    """
    global task_scheduler
    if not add_task_only:
        # 执行任务
        try:
            infoprint('CronTask:', task_dict.get('name', str(task_dict['target'])), 'Target:', str(task_dict['target']))

            target_func = task_dict.get('target')
            if target_func is None:
                raise ValueError("target is not given in " + str(task_dict))
            target_func(
                *(task_dict.get('args', ())),  # 解开参数以后传递
                **(task_dict.get('kwargs', {}))
            )
        except:
            errprint('ErrorWhenProcessingCronTasks', task_dict)
            traceback.print_exc()

    # 添加下一次定时任务
    task_scheduler.enter(
        task_dict.get('interval', 300),
        task_dict.get('priority', 999),
        cron_task_container,
        (task_dict,)
    )


def cron_task_host():
    """定时任务宿主, 每分钟检查一次列表, 运行时间到了的定时任务"""
    while True:
        sleep(60)
        try:
            task_scheduler.run()
        except:
            errprint('ErrorDuringExecutingCronTasks')
            traceback.print_exc()


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
        slash_esc=('//' + _domain).replace('/', r'\/'),
        http_esc=('http://' + _domain).replace('/', r'\/'),
        https_esc=('https://' + _domain).replace('/', r'\/'),
        double_quoted_esc='\\"%s\\"' % _domain,
        single_quoted_esc="\\'%s\\'" % _domain,
        # double escape slash
        slash_double_esc=('//' + _domain).replace('/', r'\\\/'),
        http_double_esc=('http://' + _domain).replace('/', r'\\\/'),
        https_double_esc=('https://' + _domain).replace('/', r'\\\/'),
        # urlencoded
        slash_ue=quote_plus('//' + _domain),
        http_ue=quote_plus('http://' + _domain),
        https_ue=quote_plus('https://' + _domain),
        double_quoted_ue=quote_plus('"%s"' % _domain),
        single_quoted_ue=quote_plus("'%s'" % _domain),
        # escaped and urlencoded
        slash_esc_ue=quote_plus(('//' + _domain).replace('/', r'\/')),
        http_esc_ue=quote_plus(('http://' + _domain).replace('/', r'\/')),
        https_esc_ue=quote_plus(('https://' + _domain).replace('/', r'\/')),
    )


def add_temporary_domain_alias(source_domain, replaced_to_domain):
    """
    添加临时域名替换列表
    用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项
    :param source_domain: 被替换的域名
    :param replaced_to_domain: 替换成这个域名
    :type source_domain: str
    :type replaced_to_domain: str
    """
    if this_request.temporary_domain_alias is None:
        this_request.temporary_domain_alias = []
    else:
        this_request.temporary_domain_alias = list(this_request.temporary_domain_alias)

    this_request.temporary_domain_alias.append((source_domain, replaced_to_domain))
    this_request.temporary_domain_alias = tuple(this_request.temporary_domain_alias)
    dbgprint('A domain', source_domain, 'to', replaced_to_domain, 'added to temporary_domain_alias',
             this_request.temporary_domain_alias)


@lru_cache(maxsize=1024)
def is_domain_match_glob_whitelist(domain):
    """
    域名是否匹配 `domains_whitelist_auto_add_glob_list` 中设置的通配符
    :type domain: str
    :rtype: bool
    """
    for domain_glob in domains_whitelist_auto_add_glob_list:
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
    for streamed_keyword in steamed_mime_keywords:
        if streamed_keyword in _content_type:
            return True
    return False


# noinspection PyGlobalUndefined
def try_match_and_add_domain_to_rewrite_white_list(domain, force_add=False):
    """
    若域名与`domains_whitelist_auto_add_glob_list`中的通配符匹配, 则加入 external_domains 列表
    被加入 external_domains 列表的域名, 会被应用重写机制
    用于在程序运行过程中动态添加域名到external_domains中
    也可在外部函数(custom_func.py)中使用
    关于 external_domains 更详细的说明, 请看 default_config.py 中对应的文档
    :type domain: str
    :type force_add: bool
    :rtype: bool
    """
    global external_domains, external_domains_set, allowed_domains_set, prefix_buff

    if domain is None or not domain:
        return False
    if domain in allowed_domains_set:
        return True
    if not force_add and not is_domain_match_glob_whitelist(domain):
        return False
    else:
        infoprint('A domain:', domain, 'was added to external_domains list')

        _buff = list(external_domains)  # external_domains是tuple类型, 添加前需要先转换
        _buff.append(domain)
        external_domains = tuple(_buff)  # 转换回tuple, tuple有一些性能优势
        external_domains_set.add(domain)
        allowed_domains_set.add(domain)

        prefix_buff[domain] = calc_domain_replace_prefix(domain)

        # write log
        try:
            with open('automatic_domains_whitelist.log', 'a', encoding='utf-8') as fp:
                fp.write(domain + '\n')
        except:
            traceback.print_exc()

        return True


def current_line_number():
    """Returns the current line number in our program.
    :return: current line number
    :rtype: int
    """
    import inspect
    return inspect.currentframe().f_back.f_lineno


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

    try:
        query_string_byte = base64.urlsafe_b64decode(b64)
        is_gzipped = get_group('gzip', m)
        if is_gzipped:
            query_string_byte = zlib.decompress(query_string_byte)
        query_string = query_string_byte.decode(encoding='utf-8')
    except:
        traceback.print_exc()
        raise
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
    try:
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
                     + '._' + _url_salt + '_.' + mime_to_use_cdn[url_mime]
        result = urlunsplit((url_sp.scheme, url_sp.netloc, mixed_path, '', ''))
    except:
        traceback.print_exc()
        raise
    else:
        if escape_slash:
            result = result.replace('/', r'\/')
        # dbgprint('embed:', real_url_raw, 'to:', result)
        return result


def decode_mirror_url(mirror_url=None):
    """
    解析镜像url(可能含有extdomains), 并提取出原始url信息
    可以不是完整的url, 只需要有 path 部分即可(query_string也可以有)
    若参数留空, 则使用当前用户正在请求的url
    支持json (处理 \/ 和 \. 的转义)

    :rtype: dict[str, Union[str, bool]]
    :return: {'domain':str, 'is_https':bool, 'path':str, 'path_query':str}
    """
    _is_escaped_dot = False
    _is_escaped_slash = False
    result = {}

    if mirror_url is None:
        input_path_query = extract_url_path_and_query()
    else:
        if r'\/' in mirror_url:  # 如果 \/ 在url中, 先反转义, 处理完后再转义回来
            _is_escaped_slash = True
            mirror_url = mirror_url.replace(r'\/', '/')

        if r'\.' in mirror_url:  # 如果 \. 在url中, 先反转义, 处理完后再转义回来
            _is_escaped_dot = True
            mirror_url = mirror_url.replace(r'\.', '.')

        input_path_query = extract_url_path_and_query(mirror_url)

    if input_path_query[:12] == '/extdomains/':
        # 12 == len('/extdomains/')
        domain_end_pos = input_path_query.find('/', 12)
        real_domain = input_path_query[12:domain_end_pos]
        real_path_query = input_path_query[domain_end_pos:]

        if real_domain[:6] == 'https-':
            # 如果显式指定了 /extdomains/https-域名 形式(为了兼容老版本)的, 那么使用https
            real_domain = real_domain[6:]
            _is_https = True
        else:
            # 如果是 /extdomains/域名 形式, 没有 "https-" 那么根据域名判断是否使用HTTPS
            _is_https = is_target_domain_use_https(real_domain)

        real_path_query = client_requests_text_rewrite(real_path_query)

        if _is_escaped_dot: real_path_query = real_path_query.replace('.', r'\.')
        if _is_escaped_slash: real_path_query = real_path_query.replace('/', r'\/')
        result['domain'] = real_domain
        result['is_https'] = _is_https
        result['path_query'] = real_path_query
        result['path'] = urlsplit(result['path_query']).path
        return result

    input_path_query = client_requests_text_rewrite(input_path_query)

    if _is_escaped_dot: input_path_query = input_path_query.replace('.', r'\.')
    if _is_escaped_slash: input_path_query = input_path_query.replace('/', r'\/')
    result['domain'] = target_domain
    result['is_https'] = (target_scheme == 'https://')
    result['path_query'] = input_path_query
    result['path'] = urlsplit(result['path_query']).path
    return result


# 函数别名, 为了兼容早期版本的配置文件
extract_from_url_may_have_extdomains = decode_mirror_url


# noinspection PyShadowingNames
def encode_mirror_url(raw_url_or_path, remote_domain=None, is_scheme=None, is_escape=False):
    """convert url from remote to mirror url
    :type raw_url_or_path: str
    :type remote_domain: str
    :type is_scheme: bool
    :type is_escape: bool
    :rtype: str
    """

    if is_escape:
        _raw_url_or_path = raw_url_or_path.replace('r\/', r'/')
    else:
        _raw_url_or_path = raw_url_or_path
    sp = urlsplit(_raw_url_or_path)
    if '/extdomains/' == sp.path[:12]:
        return raw_url_or_path
    domain = remote_domain or sp.netloc or this_request.remote_domain or target_domain
    if domain not in allowed_domains_set:
        return raw_url_or_path

    if is_scheme or ((sp.scheme or _raw_url_or_path[:2] == '//') and is_scheme is not False):
        our_prefix = myurl_prefix
    else:
        our_prefix = ''

    if domain not in domain_alias_to_target_set:
        middle_part = '/extdomains/' + domain
    else:
        middle_part = ''

    result = urljoin(our_prefix + middle_part + '/',
                     extract_url_path_and_query(_raw_url_or_path).lstrip('/'))
    if is_escape:
        result = result.replace('/', r'\/')

    return response_text_rewrite(result)


# 函数别名, 为了兼容早期版本的配置文件
convert_to_mirror_url = encode_mirror_url


def is_target_domain_use_https(target_domain):
    """请求目标域名时是否使用https"""
    if force_https_domains == 'NONE':
        return False
    if force_https_domains == 'ALL':
        return True
    if target_domain in force_https_domains:
        return True
    else:
        return False


def get_ext_domain_inurl_scheme_prefix(ext_domain, force_https=None):
    """旧版本遗留函数, 已经不再需要, 永远返回空字符串"""
    return ''


def add_ssrf_allowed_domain(domain):
    """添加域名到ssrf白名单, 不支持通配符
    :type domain: str
    """
    global allowed_domains_set
    allowed_domains_set.add(domain)


# noinspection PyGlobalUndefined
def set_request_for_debug(dummy_request):
    global request
    request = dummy_request


def strx(*args, sep=' '):
    """
    :return: str
    """
    output = ''
    for arg in args:
        output += str(arg) + sep
    output.rstrip(sep)
    return output


@lru_cache(maxsize=1024)
def check_global_ua_pass(ua_str):
    """该user-agent是否满足全局白名单"""
    if ua_str is None or not global_ua_white_name:
        return False
    ua_str = ua_str.lower()
    if global_ua_white_name in ua_str:
        return True
    else:
        return False


@lru_cache(maxsize=128)
def is_mime_represents_text(input_mime):
    """
    Determine whether an mime is text (eg: text/html: True, image/png: False)
    :param input_mime: str
    :return: bool
    """
    input_mime_l = input_mime.lower()
    for text_word in text_like_mime_keywords:
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
    if _mime in mime_to_use_cdn:
        # dbgprint(content_type, 'Should Use CDN')
        return _mime
    else:
        # dbgprint(content_type, 'Should NOT CDN')
        return False


def generate_simple_resp_page(errormsg=b'We Got An Unknown Error', error_code=500):
    """

    :type errormsg: bytes
    :type error_code: int
    :rtype: Response
    """
    return make_response(errormsg, error_code)


def generate_error_page(errormsg='Unknown Error', error_code=500, is_traceback=False, content_only=False):
    """

    :type errormsg: Union(str, bytes)
    :type error_code: int
    :type is_traceback: bool
    :rtype: Union[Response, str]
    """
    if isinstance(errormsg, bytes):
        errormsg = errormsg.decode()

    request_detail = ""
    for attrib in filter(lambda x: x[:2] != '__' and x[-2:] != '__', dir(this_request)):
        request_detail += "<tr><td>{attrib}</td><td>{value}</td></tr>" \
            .format(attrib=attrib, value=html_escape(str(this_request.__getattribute__(attrib))))

    error_page = """<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8">
<title>zmirror internal error</title>
<style>code{{background-color: #cccaca;}}</style>
</head>
<body>
<h1>zmirror internal error</h1>
An fatal error occurs. 服务器中运行的zmirror出现一个内部错误.<br>

<hr>
<h2>If you are visitor 如果你是访客</h2>
This site is temporary unavailable because some internal error<br>
Please contact your site admin. <br>
该镜像站暂时出现了临时的内部故障, 请联系网站管理员<br>

<hr>
<h2>If you are admin</h2>
You can find full detail log in your server's log.<br>
For apache, typically at <code>/var/log/apache2/YOUR_SITE_NAME_error.log</code><br>
tips: you can use <code>tail -n 100 -f YOUR_SITE_NAME_error.log</code> to view real-time log<br>
<br>
If you can't solve it by your self, here are some ways may help:<br>
<ul>
    <li>contact the developer by email: <a href="mailto:i@z.codes" target="_blank">aploium &lt;i@z.codes&gt;</a></li>
    <li>seeking for help in zmirror's <a href="https://gitter.im/zmirror/zmirror" target="_blank">online chat room</a></li>
    <li>open an <a href="https://github.com/aploium/zmirror/issues" target="_blank">issue</a> (as an bug report) in github</li>
</ul>
<h3>Detail</h3>
<table border="1"><tr><th>Attrib</th><th>Value</th></tr>
{request_detail}
</table>
<h3>Additional information</h3>
<pre>{errormsg}</pre>
<h3>Traceback</h3>
<pre>{traceback_str}</pre>
<hr>
<div style="font-size: smaller">Powered by <em>zmirror {version}</em><br>
<a href="{official_site}" target="_blank">{official_site}</a></div>
</body></html>""".format(errormsg=errormsg, request_detail=request_detail,
                         traceback_str=html_escape(traceback.format_exc()) if is_traceback else 'None or not displayed',
                         version=__VERSION__, official_site=__GITHUB_URL__
                         )

    if not content_only:
        return make_response(error_page.encode(), error_code)
    else:
        return error_page


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


def generate_304_response(_content_type=None):
    """:rtype Response"""
    r = Response(content_type=_content_type, status=304)
    r.headers.add('X-Cache', 'FileHit-304')
    return r


def generate_ip_verify_hash(input_dict):
    """
    生成一个标示用户身份的hash
    在 human_ip_verification 功能中使用
    hash一共14位
    hash(前7位+salt) = 后7位 以此来进行验证
    :rtype str
    """
    strbuff = human_ip_verification_answers_hash_str
    for key in input_dict:
        strbuff += key + input_dict[key] + str(random.randint(0, 9000000))
    input_key_hash = hex(zlib.adler32(strbuff.encode(encoding='utf-8')))[2:]
    while len(input_key_hash) < 7:
        input_key_hash += '0'
    output_hash = hex(zlib.adler32((input_key_hash + human_ip_verification_answers_hash_str).encode(encoding='utf-8')))[2:]
    while len(output_hash) < 7:
        output_hash += '0'
    return input_key_hash + output_hash


@lru_cache(maxsize=1024)
def verify_ip_hash_cookie(hash_cookie_value):
    """
    根据cookie中的hash判断是否允许用户访问
    在 human_ip_verification 功能中使用
    hash一共14位
    hash(前7位+salt) = 后7位 以此来进行验证
    :type hash_cookie_value: str
    :rtype: bool
    """
    try:
        input_key_hash = hash_cookie_value[:8]
        output_hash = hash_cookie_value[8:]
        calculated_hash = hex(zlib.adler32(
            (input_key_hash + human_ip_verification_answers_hash_str).encode(encoding='utf-8')
        ))[2:]
        if output_hash == calculated_hash:
            return True
        else:
            return False
    except:
        return False


def update_content_in_local_cache(url, content, method='GET'):
    """更新 local_cache 中缓存的资源, 追加content
    在stream模式中使用"""
    if local_cache_enable and method == 'GET' and cache.is_cached(url):
        info_dict = cache.get_info(url)
        resp = cache.get_obj(url)
        resp.set_data(content)

        # 当存储的资源没有完整的content时, without_content 被设置为true
        # 此时该缓存不会生效, 只有当content被添加后, 缓存才会实际生效
        # 在stream模式中, 因为是先接收http头, 然后再接收内容, 所以会出现只有头而没有内容的情况
        # 此时程序会先将只有头部的响应添加到本地缓存, 在内容实际接收完成后再追加内容
        info_dict['without_content'] = False

        if verbose_level >= 4: dbgprint('LocalCache_UpdateCache', url, content[:30], len(content))
        cache.put_obj(
            url,
            resp,
            obj_size=len(content),
            expires=get_expire_from_mime(this_request.mime),
            last_modified=info_dict.get('last_modified'),
            info_dict=info_dict,
        )


def put_response_to_local_cache(url, _our_resp, without_content=False):
    """
    put our response object(headers included) to local cache
    :param without_content: for stream mode use
    :param url: client request url
    :param _our_resp: our response(flask response object) to client, would be storge
    """
    # Only cache GET method, and only when remote returns 200(OK) status
    if local_cache_enable and request.method == 'GET' and this_request.remote_response.status_code == 200:
        if without_content:
            our_resp = copy.copy(_our_resp)
            our_resp.response = None  # delete iterator
        else:
            our_resp = _our_resp
        # the header's character cases are different in flask/apache(win)/apache(linux)
        last_modified = this_request.remote_response.headers.get('last-modified', None) \
                        or this_request.remote_response.headers.get('Last-Modified', None)
        dbgprint('PuttingCache:', url)
        cache.put_obj(
            url,
            our_resp,
            expires=get_expire_from_mime(this_request.mime),
            obj_size=0 if without_content else len(this_request.remote_response.content),
            last_modified=last_modified,
            info_dict={'without_content': without_content,
                       'last_modified': last_modified,
                       },
        )


def try_get_cached_response(url, client_header=None):
    """
    尝试从本地缓存中取出响应
    :param url: real url with query string
    :type client_header: dict
    :rtype: Union[Response, None]
    """
    # Only use cache when client use GET
    if local_cache_enable and request.method == 'GET' and cache.is_cached(url):
        if client_header is not None and 'if-modified-since' in client_header and \
                cache.is_unchanged(url, client_header.get('if-modified-since', None)):
            dbgprint('FileCacheHit-304', url)
            return generate_304_response()
        else:
            cached_info = cache.get_info(url)
            if cached_info.get('without_content', False):
                # 关于 without_content 的解释, 请看update_content_in_local_cache()函数
                return None
            # dbgprint('FileCacheHit-200')
            resp = cache.get_obj(url)
            assert isinstance(resp, Response)
            resp.headers.set('x-zmirror-cache', 'FileHit')
            return resp
    else:
        return None


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


def regex_url_reassemble(match_obj):
    """
    Reassemble url parts split by the regex.
    :param match_obj: match object of stdlib re
    :return: re assembled url string (included prefix(url= etc..) and suffix.)
    :rtype: str
    """

    if match_obj.group() in url_rewrite_cache:  # Read Cache
        global url_rewrite_cache_hit_count
        url_rewrite_cache_hit_count += 1
        return url_rewrite_cache[match_obj.group()]
    else:
        global url_rewrite_cache_miss_count

    prefix = get_group('prefix', match_obj)
    quote_left = get_group('quote_left', match_obj)
    quote_right = get_group('quote_right', match_obj)
    path = get_group('path', match_obj)
    match_domain = get_group('domain', match_obj)
    scheme = get_group('scheme', match_obj)

    whole_match_string = match_obj.group()
    # dbgprint('prefix', prefix, 'quote_left', quote_left, 'quote_right', quote_right,
    #          'path', path, 'match_domain', match_domain, 'scheme', scheme, 'whole', whole_match_string)
    if r"\/" in path or r"\/" in scheme:
        require_slash_escape = True
        path = path.replace(r"\/", "/")
        # domain_and_scheme = domain_and_scheme.replace(r"\/", "/")
    else:
        require_slash_escape = False
    # path must be not blank
    if (not path  # path is blank
        # only url(something) and @import are allowed to be unquoted
        or ('url' not in prefix and 'import' not in prefix) and (not quote_left or quote_right == ')')
        # for "key":"value" type replace, we must have at least one '/' in url path (for the value to be regard as url)
        or (':' in prefix and '/' not in path)
        # if we have quote_left, it must equals to the right
        or (quote_left and quote_left != quote_right)
        # in javascript, those 'path' contains one or only two slash, should not be rewrited (for potential error)
        # or (this_request.mime == 'application/javascript' and path.count('/') < 2)
        # in javascript, we only rewrite those with explicit scheme ones.
        # v0.21.10+ in "key":"value" format, we should ignore those path without scheme
        or (not scheme and ('javascript' in this_request.mime or '"' in prefix))
        ):
        # dbgprint('returned_un_touch', whole_match_string)
        return whole_match_string

    # v0.19.0+ Automatic Domains Whitelist (Experimental)
    if enable_automatic_domains_whitelist:
        try_match_and_add_domain_to_rewrite_white_list(match_domain)

    # dbgprint('remote_path:', remote_path, 'remote_domain:', remote_domain, 'match_domain', match_domain, v=5)
    # dbgprint(match_obj.groups(), v=5)
    # dbgprint('remote_path:', remote_path, 'remote_domain:', remote_domain, 'match_domain', match_domain, v=5)

    domain = match_domain or this_request.remote_domain
    # dbgprint('rewrite match_obj:', match_obj, 'domain:', domain, v=5)
    # skip if the domain are not in our proxy list
    if domain not in allowed_domains_set:
        # dbgprint('return untouched because domain not match', domain, whole_match_string)
        return match_obj.group()  # return raw, do not change

    # this resource's absolute url path to the domain root.
    # dbgprint('match path', path, v=5)
    path = urljoin(this_request.remote_path, path)
    # dbgprint('middle path', path, v=5)
    if ':' not in this_request.remote_domain:  # the python's builtin urljoin has a bug, cannot join domain with port correctly
        url_no_scheme = urljoin(domain + '/', path.lstrip('/'))
    else:
        url_no_scheme = domain + '/' + path.lstrip('/')

    # dbgprint('url_no_scheme', url_no_scheme)
    # add extdomains prefix in path if need
    if domain in external_domains_set:
        path = '/extdomains/' + url_no_scheme

    # dbgprint('final_path', path, v=5)
    if mime_based_static_resource_CDN and url_no_scheme in url_to_use_cdn:
        # dbgprint('We Know:', url_no_scheme,v=5)
        _we_knew_this_url = True
        _this_url_mime_cdn = url_to_use_cdn[url_no_scheme][0]
    else:
        # dbgprint('We Don\'t know:', url_no_scheme,v=5)
        _we_knew_this_url = False
        _this_url_mime_cdn = False

    # Apply CDN domain
    if _this_url_mime_cdn \
            or (not disable_legacy_file_recognize_method and get_group('ext', match_obj) in static_file_extensions_list):
        # pick an cdn domain due to the length of url path
        # an advantage of choose like this (not randomly), is this can make higher CDN cache hit rate.

        # CDN rewrite, rewrite static resources to cdn domains.
        # A lot of cases included, the followings are just the most typical examples.
        # http(s)://target.com/img/love_lucia.jpg --> http(s)://your.cdn.domains.com/img/love_lucia.jpg
        # http://external.com/css/main.css --> http(s)://your.cdn.domains.com/extdomains/external.com/css/main.css
        # http://external.pw/css/main.css --> http(s)://your.cdn.domains.com/extdomains/external.pw/css/main.css
        replace_to_scheme_domain = my_host_scheme + CDN_domains[zlib.adler32(path.encode()) % cdn_domains_number]

    # else:  # this_request.mime == 'application/javascript':
    #     replace_to_scheme_domain = ''  # Do not use explicit url prefix in js, to prevent potential error
    elif not scheme:
        replace_to_scheme_domain = ''
    else:
        replace_to_scheme_domain = myurl_prefix

    reassembled_url = urljoin(replace_to_scheme_domain, path)
    if _this_url_mime_cdn and cdn_redirect_encode_query_str_into_url:
        reassembled_url = embed_real_url_to_embedded_url(
            reassembled_url,
            url_mime=url_to_use_cdn[url_no_scheme][1],
            escape_slash=require_slash_escape
        )

    if require_slash_escape:
        reassembled_url = reassembled_url.replace("/", r"\/")

    # reassemble!
    # prefix: src=  quote_left: "
    # path: /extdomains/target.com/foo/bar.js?love=luciaZ
    reassembled = prefix + quote_left + reassembled_url + quote_right + get_group('right_suffix', match_obj)

    # write the adv rewrite cache only if we disable CDN or we known whether this url is CDN-able
    if not mime_based_static_resource_CDN or _we_knew_this_url:
        url_rewrite_cache[match_obj.group()] = reassembled  # write cache
        url_rewrite_cache_miss_count += 1
    # dbgprint('---------------------', v=5)
    return reassembled


@lru_cache(maxsize=256)
def is_ua_in_whitelist(ua_str):
    """
    当机器人或蜘蛛的请求被ban时, 检查它是否处在允许的白名单内
    被 is_denied_because_of_spider() 调用
    :type ua_str: str
    """
    ua_str = ua_str.lower()
    if global_ua_white_name in ua_str:
        return True
    for allowed_ua in spider_ua_white_list:
        if allowed_ua in ua_str:
            return True
    return False


@lru_cache(maxsize=256)
def is_denied_because_of_spider(ua_str):
    """检查user-agent是否因为是蜘蛛或机器人而需要ban掉"""
    ua_str = ua_str.lower()
    if 'spider' in ua_str or 'bot' in ua_str:
        if is_ua_in_whitelist(ua_str):
            infoprint("A Spider/Bot's access was granted", ua_str)
            return False
        infoprint('A Spider/Bot was denied, UA is:', ua_str)
        return True
    else:
        return False


def load_ip_whitelist_file():
    """从文件加载ip白名单"""
    set_buff = set()
    if os.path.exists(human_ip_verification_whitelist_file_path):
        with open(human_ip_verification_whitelist_file_path, 'r', encoding='utf-8') as fp:
            set_buff.add(fp.readline().strip())
    return set_buff


def append_ip_whitelist_file(ip_to_allow):
    """写入ip白名单到文件"""
    try:
        with open(human_ip_verification_whitelist_file_path, 'a', encoding='utf-8') as fp:
            fp.write(ip_to_allow + '\n')
    except:
        errprint('Unable to write whitelist file')
        traceback.print_exc()


def ip_whitelist_add(ip_to_allow, info_record_dict=None):
    """添加ip到白名单, 并写入文件"""
    if ip_to_allow in single_ip_allowed_set:
        return
    dbgprint('ip white added', ip_to_allow, 'info:', info_record_dict)
    single_ip_allowed_set.add(ip_to_allow)
    is_ip_not_in_allow_range.cache_clear()
    append_ip_whitelist_file(ip_to_allow)
    # dbgprint(single_ip_allowed_set)
    try:
        with open(human_ip_verification_whitelist_log, 'a', encoding='utf-8') as fp:
            fp.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " " + ip_to_allow
                     + " " + str(request.user_agent)
                     + " " + repr(info_record_dict) + "\n")
    except:
        errprint('Unable to write log file', os.path.abspath(human_ip_verification_whitelist_log))
        traceback.print_exc()


@lru_cache(maxsize=256)
def is_ip_not_in_allow_range(ip_address):
    """判断ip是否在白名单中"""
    if ip_address in single_ip_allowed_set:
        return False
    ip_address_obj = ipaddress.ip_address(ip_address)
    for allowed_network in human_ip_verification_default_whitelist_networks:
        if ip_address_obj in allowed_network:
            return False
    return True


# ########## End utils ###############


# ################# Begin Server Response Handler #################
def preload_streamed_response_content_async(requests_response_obj, buffer_queue):
    """
    stream模式下, 预读远程响应的content
    :param requests_response_obj:
    :type buffer_queue: queue.Queue
    """
    for particle_content in requests_response_obj.iter_content(stream_transfer_buffer_size):
        try:
            buffer_queue.put(particle_content, timeout=10)
        except queue.Full:
            traceback.print_exc()
            buffer_queue = None  # 这样把它free掉, 会不会减少内存泄露? 我也不知道 (Ap)
            exit()
        if verbose_level >= 3: dbgprint('BufferSize', buffer_queue.qsize())
    buffer_queue.put(None, timeout=10)
    exit()


def iter_streamed_response_async():
    """异步, 一边读取远程响应, 一边发送给用户"""
    total_size = 0
    _start_time = time()

    _content_buffer = b''
    _disable_cache_temporary = False

    buffer_queue = queue.Queue(maxsize=stream_transfer_async_preload_max_packages_size)

    t = threading.Thread(
        target=preload_streamed_response_content_async,
        args=(this_request.remote_response, buffer_queue),
        daemon=True,
    )
    t.start()

    while True:
        try:
            particle_content = buffer_queue.get(timeout=15)
        except queue.Empty:
            warnprint('WeGotAnSteamTimeout')
            traceback.print_exc()
            try:
                # noinspection PyProtectedMember
                t._stop()
            except:
                pass
            return
        buffer_queue.task_done()

        if particle_content is not None:
            # 由于stream的特性, content会被消耗掉, 所以需要额外储存起来
            if local_cache_enable and not _disable_cache_temporary:
                if len(_content_buffer) > 8 * 1024 * 1024:  # 8MB
                    _disable_cache_temporary = True
                    _content_buffer = None
                else:
                    _content_buffer += particle_content

            yield particle_content
        else:
            if local_cache_enable and not _disable_cache_temporary:
                update_content_in_local_cache(this_request.remote_url, _content_buffer,
                                              method=this_request.remote_response.request.method)
            return

        if verbose_level >= 4:
            total_size += len(particle_content)
            dbgprint('total_size:', total_size, 'total_speed(KB/s):', total_size / 1024 / (time() - _start_time))


def iter_streamed_response():
    """非异步, 读取一小部分远程响应, 发送给用户, 再读取下一小部分. 已不推荐使用"""
    total_size = 0
    _start_time = time()

    _content_buffer = b''
    _disable_cache_temporary = False

    for particle_content in this_request.remote_response.iter_content(stream_transfer_buffer_size):
        if verbose_level >= 4:
            total_size += len(particle_content)
            dbgprint('total_size:', total_size, 'total_speed(KB/s):', total_size / 1024 / (time() - _start_time))

        if particle_content is not None:
            # 由于stream的特性, content会被消耗掉, 所以需要额外储存起来
            if local_cache_enable and not _disable_cache_temporary:
                if len(_content_buffer) > 8 * 1024 * 1024:  # 8MB
                    _disable_cache_temporary = True
                    _content_buffer = None
                else:
                    _content_buffer += particle_content

        yield particle_content

    if local_cache_enable and not _disable_cache_temporary:
        update_content_in_local_cache(this_request.remote_url, _content_buffer,
                                      method=this_request.remote_response.request.method)


def copy_response(content=None, is_streamed=False):
    """
    Copy and parse remote server's response headers, generate our flask response object

    :type content: str
    :type is_streamed: bool
    :param content: pre-rewrited response content, bytes
    :return: flask response object
    :rtype: Tuple[Response, float]
    """
    if content is None:
        if is_streamed:
            req_time_body = 0
            if not enable_stream_transfer_async_preload:
                dbgprint('TransferUsingStreamMode(basic):', this_request.remote_response.url, this_request.mime)
                content = iter_streamed_response()
            else:
                dbgprint('TransferUsingStreamMode(async):', this_request.remote_response.url, this_request.mime)
                content = iter_streamed_response_async()
        else:
            content, req_time_body = response_content_rewrite()
    else:
        req_time_body = 0

    if verbose_level >= 3: dbgprint('RemoteRespHeaders', this_request.remote_response.headers)
    resp = Response(content, status=this_request.remote_response.status_code)

    for header_key in this_request.remote_response.headers:
        header_key_lower = header_key.lower()
        # Add necessary response headers from the origin site, drop other headers
        if header_key_lower in allowed_remote_response_headers:
            if header_key_lower == 'location':
                _location = this_request.remote_response.headers[header_key]
                # try to apply custom rewrite function
                try:
                    if custom_text_rewriter_enable:
                        _loc_rewrite = custom_response_text_rewriter(_location, 'mwm/headers-location', this_request.remote_url)
                        if isinstance(_loc_rewrite, str):
                            _location = _loc_rewrite
                except Exception as _e:  # just print err and fallback to normal rewrite
                    errprint('(LOCATION) Custom Rewrite Function ERROR', _e)
                    traceback.print_exc()
                    return generate_error_page("(LOCATION) Custom Rewrite Function ERROR", is_traceback=True), 0
                resp.headers[header_key] = encode_mirror_url(_location)

            elif header_key_lower == 'content-type':
                # force add utf-8 to content-type if it is text
                if is_mime_represents_text(this_request.mime) and 'utf-8' not in this_request.content_type:
                    resp.headers[header_key] = this_request.mime + '; charset=utf-8'
                else:
                    resp.headers[header_key] = this_request.remote_response.headers[header_key]

            elif header_key_lower in ('access-control-allow-origin', 'timing-allow-origin'):
                if custom_allowed_origin is None:
                    resp.headers[header_key] = myurl_prefix
                elif custom_allowed_origin == '_*_':
                    _origin = request.headers.get('origin') or request.headers.get('Origin') or myurl_prefix
                    resp.headers[header_key] = _origin
                else:
                    resp.headers[header_key] = custom_allowed_origin

            else:
                resp.headers[header_key] = this_request.remote_response.headers[header_key]

        # If we have the Set-Cookie header, we should extract the raw ones
        #   and then change the cookie domain to our domain
        if header_key_lower == 'set-cookie':
            for cookie_string in response_cookies_deep_copy():
                try:
                    resp.headers.add('Set-Cookie', response_cookie_rewrite(cookie_string))
                except:
                    traceback.print_exc()
                    return generate_error_page(
                        "Error occurs when copying remote 'set-cookie' headers:" + str(cookie_string), is_traceback=True), 0

    if verbose_level >= 3: dbgprint('OurRespHeaders:\n', resp.headers)

    return resp, req_time_body


# noinspection PyProtectedMember
def response_cookies_deep_copy():
    """
    It's a BAD hack to get RAW cookies headers, but so far, we don't have better way.
    We'd go DEEP inside the urllib's private method to get raw headers

    raw_headers example:
    [('Cache-Control', 'private'),
    ('Content-Length', '48234'),
    ('Content-Type', 'text/html; Charset=utf-8'),
    ('Server', 'Microsoft-IIS/8.5'),
    ('Set-Cookie','BoardList=BoardID=Show; expires=Mon, 02-May-2016 16:00:00 GMT; path=/'),
    ('Set-Cookie','aspsky=abcefgh; expires=Sun, 24-Apr-2016 16:00:00 GMT; path=/; HttpOnly'),
    ('Set-Cookie', 'ASPSESSIONIDSCSSDSSQ=OGKMLAHDHBFDJCDMGBOAGOMJ; path=/'),
    ('X-Powered-By', 'ASP.NET'),
    ('Date', 'Tue, 26 Apr 2016 12:32:40 GMT')]

    """
    raw_headers = this_request.remote_response.raw._original_response.headers._headers
    header_cookies_string_list = []
    for name, value in raw_headers:
        if name.lower() == 'set-cookie':
            if my_host_scheme == 'http://':
                value = value.replace('Secure;', '')
                value = value.replace(';Secure', ';')
                value = value.replace('; Secure', ';')
            if 'httponly' in value.lower():
                if enable_aggressive_cookies_path_rewrite:
                    # 暴力cookie path重写, 把所有path都重写为 /
                    value = regex_cookie_path_rewriter.sub('path=/;', value)
                elif enable_aggressive_cookies_path_rewrite is not None:
                    # 重写HttpOnly Cookies的path到当前url下
                    # eg(/extdomains/a.foobar.com): path=/verify; -> path=/extdomains/a.foobar.com/verify

                    if this_request.remote_domain not in domain_alias_to_target_set:  # do not rewrite main domains
                        value = regex_cookie_path_rewriter.sub(
                            '\g<prefix>=/extdomains/' + this_request.remote_domain + '\g<path>', value)

            header_cookies_string_list.append(value)
    return header_cookies_string_list


def response_content_rewrite():
    """
    Rewrite requests response's content's url. Auto skip binary (based on MIME).
    :return: List[bytes, float]
    """

    _start_time = time()
    _content = this_request.remote_response.content
    req_time_body = time() - _start_time

    if this_request.mime and is_mime_represents_text(this_request.mime):
        # Do text rewrite if remote response is text-like (html, css, js, xml, etc..)
        if verbose_level >= 3: dbgprint('Text-like', this_request.content_type,
                                        this_request.remote_response.text[:15], _content[:15])

        if force_decode_remote_using_encode is not None:
            this_request.remote_response.encoding = force_decode_remote_using_encode
        elif possible_charsets:
            for charset in possible_charsets:
                try:
                    this_request.remote_response.content.decode(charset)
                except:
                    pass
                else:
                    this_request.remote_response.encoding = charset
                    break
        elif cchardet_available:  # detect the encoding using cchardet (if we have)
            this_request.remote_response.encoding = c_chardet(_content)

        # simply copy the raw text, for custom rewriter function first.
        resp_text = this_request.remote_response.text

        if developer_string_trace is not None and developer_string_trace in resp_text:
            infoprint('StringTrace: appears in the RAW remote response text, code line no. ', current_line_number())

        # try to apply custom rewrite function
        try:
            if custom_text_rewriter_enable:
                resp_text2 = custom_response_text_rewriter(resp_text, this_request.mime, this_request.remote_url)
                if isinstance(resp_text2, str):
                    resp_text = resp_text2
                elif isinstance(resp_text2, tuple) or isinstance(resp_text2, list):
                    resp_text, is_skip_builtin_rewrite = resp_text2
                    if is_skip_builtin_rewrite:
                        infoprint('Skip_builtin_rewrite', request.url)
                        return resp_text.encode(encoding='utf-8')
        except Exception as _e:  # just print err and fallback to normal rewrite
            errprint('Custom Rewrite Function "custom_response_text_rewriter(text)" in custom_func.py ERROR', _e)
            traceback.print_exc()
            return generate_error_page(
                'Error in custom response rewrite', is_traceback=True, content_only=True).encode(), req_time_body
        else:
            if developer_string_trace is not None and developer_string_trace in resp_text:
                infoprint('StringTrace: appears after custom text rewrite, code line no. ', current_line_number())

        # then do the normal rewrites
        try:
            resp_text = response_text_rewrite(resp_text)
        except:
            traceback.print_exc()
            return generate_error_page(
                'Error in builtin response rewrite', is_traceback=True, content_only=True).encode(), req_time_body
        else:
            if developer_string_trace is not None and developer_string_trace in resp_text:
                infoprint('StringTrace: appears after builtin rewrite, code line no. ', current_line_number())

        return resp_text.encode(encoding='utf-8'), req_time_body  # return bytes
    else:
        # simply don't touch binary response content
        dbgprint('Binary', this_request.content_type)
        return _content, req_time_body


def response_text_basic_rewrite(resp_text, domain, domain_id=None):
    """

    :type resp_text: str
    :type domain: str
    :type domain_id: int
    :rtype: str
    """
    if domain not in domains_alias_to_target_domain:
        domain_prefix = '/extdomains/' + domain
        domain_prefix_https_esc = r'\/extdomains\/' + domain
    else:
        domain_prefix = ''
        domain_prefix_https_esc = ''

    # Static resources domains hard rewrite
    if enable_static_resource_CDN and domain in target_static_domains:
        # dbgprint(domain, 'is static domains')
        cdn_id = domain_id if domain_id is not None else zlib.adler32(domain.encode())
        _my_host_name = CDN_domains[cdn_id % cdn_domains_number]
        _myurl_prefix = my_host_scheme + _my_host_name
        _myurl_prefix_escaped = _myurl_prefix.replace('/', r'\/')
    else:
        _my_host_name = my_host_name
        _myurl_prefix = myurl_prefix
        _myurl_prefix_escaped = myurl_prefix_escaped

    # load pre-generated replace prefix
    prefix = prefix_buff[domain]

    # Explicit HTTPS scheme must be kept
    resp_text = resp_text.replace(prefix['https_double_esc'], (_myurl_prefix + domain_prefix).replace('/', r'\\\/'))
    resp_text = resp_text.replace(prefix['https_esc'], _myurl_prefix_escaped + domain_prefix_https_esc)
    resp_text = resp_text.replace(prefix['https'], _myurl_prefix + domain_prefix)

    resp_text = resp_text.replace(prefix['https_esc_ue'], quote_plus(_myurl_prefix_escaped + domain_prefix_https_esc))
    resp_text = resp_text.replace(prefix['https_ue'], quote_plus(_myurl_prefix + domain_prefix))

    # Implicit schemes replace, will be replaced to the same as `my_host_scheme`, unless forced
    # _buff: my-domain.com/extdomains/remote.com or my-domain.com
    if domain not in domains_alias_to_target_domain:
        _buff = _my_host_name + domain_prefix
    else:
        _buff = _my_host_name
    _buff_esc = _buff.replace('/', r'\/')
    _buff_double_esc = _buff.replace('/', r'\\\/')

    resp_text = resp_text.replace(prefix['http_double_esc'], my_host_scheme_escaped + _buff_double_esc)
    resp_text = resp_text.replace(prefix['http_esc'], my_host_scheme_escaped + _buff_esc)
    resp_text = resp_text.replace(prefix['http'], my_host_scheme + _buff)
    resp_text = resp_text.replace(prefix['slash_double_esc'], r'\\\/\\\/' + _buff_double_esc)
    resp_text = resp_text.replace(prefix['slash_esc'], r'\/\/' + _buff_esc)
    resp_text = resp_text.replace(prefix['slash'], '//' + _buff)

    resp_text = resp_text.replace(prefix['http_esc_ue'], quote_plus(my_host_scheme_escaped + _buff_esc))
    resp_text = resp_text.replace(prefix['http_ue'], quote_plus(my_host_scheme + _buff))
    resp_text = resp_text.replace(prefix['slash_esc_ue'], quote_plus(r'\/\/' + _buff_esc))
    resp_text = resp_text.replace(prefix['slash_ue'], quote_plus('//' + _buff))

    resp_text = resp_text.replace(prefix['hex_lower'], ('//' + _my_host_name).replace('/', r'\x2f'))
    resp_text = resp_text.replace(prefix['hex_upper'], ('//' + _my_host_name).replace('/', r'\x2F'))

    # rewrite "foo.domain.tld" and 'foo.domain.tld'
    resp_text = resp_text.replace(prefix['double_quoted'], '"%s"' % _buff)
    resp_text = resp_text.replace(prefix['single_quoted'], "'%s'" % _buff)
    resp_text = resp_text.replace(prefix['double_quoted_esc'], '\\"%s\\"' % _buff)
    resp_text = resp_text.replace(prefix['single_quoted_esc'], "\\'%s\\'" % _buff)
    resp_text = resp_text.replace(prefix['double_quoted_ue'], quote_plus('"%s"' % _buff))
    resp_text = resp_text.replace(prefix['single_quoted_ue'], quote_plus("'%s'" % _buff))

    resp_text = resp_text.replace('&quot;' + domain + '&quot;', '&quot;' + _buff_esc + '&quot;')

    return resp_text


def response_text_rewrite(resp_text):
    """
    rewrite urls in text-like content (html,css,js)
    :type resp_text: str
    :rtype: str
    """
    # v0.20.6+ plain replace domain alias, support json/urlencoded/json-urlencoded/plain
    if url_custom_redirect_enable:
        for before_replace, after_replace in (plain_replace_domain_alias + this_request.temporary_domain_alias):
            # _before_e = before_replace.replace('/', r'\/')
            # _after_e = after_replace.replace('/', r'\/')
            # resp_text = resp_text.replace(quote_plus(_before_e), quote_plus(_after_e))
            # resp_text = resp_text.replace(_before_e, _after_e)
            # resp_text = resp_text.replace(quote_plus(before_replace), quote_plus(after_replace))
            dbgprint('plain_replace_domain_alias', before_replace, after_replace, v=4)
            resp_text = resp_text.replace(before_replace, after_replace)

    # v0.9.2+: advanced url rewrite engine
    resp_text = regex_adv_url_rewriter.sub(regex_url_reassemble, resp_text)

    if developer_string_trace is not None and developer_string_trace in resp_text:
        infoprint('StringTrace: appears after advanced rewrite, code line no. ', current_line_number())

    # basic url rewrite, rewrite the main site's url
    # http(s)://target.com/foo/bar --> http(s)://your-domain.com/foo/bar
    for _target_domain in domains_alias_to_target_domain:
        resp_text = response_text_basic_rewrite(resp_text, _target_domain)

    if developer_string_trace is not None and developer_string_trace in resp_text:
        infoprint('StringTrace: appears after basic rewrite(main site), code line no. ', current_line_number())

    # External Domains Rewrite
    # http://external.com/foo1/bar2 --> http(s)://your-domain.com/extdomains/external.com/foo1/bar2
    # https://external.com/foo1/bar2 --> http(s)://your-domain.com/extdomains/external.com/foo1/bar2
    for domain_id, domain in enumerate(external_domains):
        resp_text = response_text_basic_rewrite(resp_text, domain, domain_id)
        if developer_string_trace is not None and developer_string_trace in resp_text:
            infoprint('StringTrace: appears after basic ext domain rewrite:', domain, ', code line no. ', current_line_number())

    # for cookies set string (in js) replace
    # eg: ".twitter.com" --> "foo.com"
    resp_text = resp_text.replace('\".' + target_domain_root + '\"', '\"' + my_host_name_no_port + '\"')
    resp_text = resp_text.replace("\'." + target_domain_root + "\'", "\'" + my_host_name_no_port + "\'")
    resp_text = resp_text.replace("domain=." + target_domain_root, "domain=" + my_host_name_no_port)
    resp_text = resp_text.replace('\"' + target_domain_root + '\"', '\"' + my_host_name_no_port + '\"')
    resp_text = resp_text.replace("\'" + target_domain_root + "\'", "\'" + my_host_name_no_port + "\'")

    if developer_string_trace is not None and developer_string_trace in resp_text:
        infoprint('StringTrace: appears after js cookies string rewrite, code line no. ', current_line_number())

    # resp_text = resp_text.replace('lang="zh-Hans"', '', 1)
    return resp_text


def response_cookie_rewrite(cookie_string):
    """
    rewrite response cookie string's domain to `my_host_name`
    :type cookie_string: str
    """
    cookie_string = regex_cookie_rewriter.sub('domain=' + my_host_name_no_port, cookie_string)
    return cookie_string


# ################# End Server Response Handler #################


# ################# Begin Client Request Handler #################
def assemble_remote_url():
    """
    组装目标服务器URL, 即生成 this_request.remote_url 的值
    :rtype: str
    """
    if this_request.is_external_domain:
        # 请求的是外部域名 (external domains)
        scheme = 'https://' if this_request.is_https else 'http://'
        dbgprint('remote_url(ext):', this_request.remote_url)
        return urljoin(scheme + this_request.remote_domain, this_request.remote_path_query)
    else:
        # 请求的是主域名及可以被当做(alias)主域名的域名
        dbgprint('remote_url(main):', this_request.remote_url)
        return urljoin(target_scheme + target_domain, this_request.remote_path_query)


def ssrf_check_layer_1():
    """
    SSRF防护, 第一层, 在请求刚开始时被调用, 检查域名是否允许
    :return: 如果请求触发了SSRF防护, 则返回True
    :rtype: bool
    """
    # Only external in-zone domains are allowed (SSRF check layer 1)
    if this_request.remote_domain not in allowed_domains_set:
        if not try_match_and_add_domain_to_rewrite_white_list(this_request.remote_domain):  # 请求的域名是否满足通配符
            if developer_temporary_disable_ssrf_prevention:  # 是否在设置中临时关闭了SSRF防护
                add_ssrf_allowed_domain(this_request.remote_domain)
                return False
            else:
                return True
    return False


def extract_client_header():
    """
    Extract necessary client header, filter out some.
    :return: dict client request headers
    """
    outgoing_head = {}
    if verbose_level >= 3: dbgprint('ClientRequestHeaders:', request.headers)
    for head_name, head_value in request.headers:
        head_name_l = head_name.lower()
        if (head_name_l not in ('host', 'content-length', 'content-type')) \
                or (head_name_l == 'content-type' and head_value != ''):
            # For Firefox, they may send 'Accept-Encoding: gzip, deflate, br'
            #   however, this program cannot decode the br encode, so we have to remove it from the request header.
            if head_name_l == 'accept-encoding' and 'br' in head_value:
                _str_buff = ''
                if 'gzip' in head_value:
                    _str_buff += 'gzip, '
                if 'deflate' in head_value:
                    _str_buff += 'deflate'
                if _str_buff:
                    outgoing_head[head_name_l] = _str_buff
            else:
                outgoing_head[head_name_l] = client_requests_text_rewrite(head_value)

    if verbose_level >= 3: dbgprint('FilteredRequestHeaders:', outgoing_head)
    return outgoing_head


# noinspection SpellCheckingInspection
def client_requests_text_rewrite(raw_text):
    """
    Rewrite proxy domain to origin domain, extdomains supported.
    Also Support urlencoded url.
    This usually used in rewriting request params

    eg. http://foo.bar/extdomains/accounts.google.com to http://accounts.google.com
    eg2. foo.bar/foobar to www.google.com/foobar
    eg3. http%3a%2f%2fg.zju.tools%2fextdomains%2Faccounts.google.com%2f233
            to http%3a%2f%2faccounts.google.com%2f233
    """
    replaced = regex_request_rewriter.sub('\g<origin_domain>', raw_text)
    # replaced = replaced.replace(my_host_name_urlencoded, target_domain)
    # replaced = replaced.replace(my_host_name_no_port, target_domain)

    # dbgprint('after regex_request_rewriter', replaced)

    # 32MB == 33554432
    replaced = client_requests_bin_rewrite(replaced.encode(), max_len=33554432).decode()

    if verbose_level >= 3 and raw_text != replaced:
        dbgprint('ClientRequestedUrl: ', raw_text, '<- Has Been Rewrited To ->', replaced)
    return replaced


def client_requests_bin_rewrite(raw_bin, max_len=2097152):  # 2097152=2MB
    """

    :type max_len: int
    :type raw_bin: byte
    """
    if raw_bin is None or len(raw_bin) > max_len:
        return raw_bin
    else:
        _str_buff = my_host_name + '/extdomains'

        for _str_buff2 in (_str_buff + '/https-', _str_buff + '/', _str_buff):
            raw_bin = raw_bin.replace(quote_plus(_str_buff2.replace('/', r'\/')).encode(), b'')
            raw_bin = raw_bin.replace(quote_plus(_str_buff2.replace('/', r'\/')).lower().encode(), b'')

            raw_bin = raw_bin.replace(quote_plus(_str_buff2).encode(), b'')
            raw_bin = raw_bin.replace(quote_plus(_str_buff2).lower().encode(), b'')

            raw_bin = raw_bin.replace(_str_buff2.replace('/', r'\/').encode(), b'')
            raw_bin = raw_bin.replace(_str_buff2.replace('/', r'\/').lower().encode(), b'')

            raw_bin = raw_bin.replace(_str_buff2.encode(), b'')

        raw_bin = raw_bin.replace(quote_plus(my_host_name).encode(), quote_plus(target_domain).encode())
        raw_bin = raw_bin.replace(my_host_name.encode(), target_domain.encode())
        raw_bin = raw_bin.replace(my_host_name_no_port.encode(), target_domain.encode())

        raw_bin = raw_bin.replace(b'%5C%2Fextdomains%5C%2Fhttps-', b'')
        raw_bin = raw_bin.replace(b'%5c%2fextdomains%5c%2fhttps-', b'')
        raw_bin = raw_bin.replace(b'%2Fextdomains%2Fhttps-', b'')
        raw_bin = raw_bin.replace(b'%2fextdomains%2fhttps-', b'')
        raw_bin = raw_bin.replace(b'\\/extdomains\\/https-', b'')
        raw_bin = raw_bin.replace(b'/extdomains/https-', b'')

        raw_bin = raw_bin.replace(b'%2Fextdomains%2F', b'')
        raw_bin = raw_bin.replace(b'%2fextdomains%2f', b'')
        raw_bin = raw_bin.replace(b'%5C%2Fextdomains%5C%2F', b'')
        raw_bin = raw_bin.replace(b'%5c%2cextdomains%5c%2c', b'')
        raw_bin = raw_bin.replace(b'\\/extdomains\\/', b'')
        raw_bin = raw_bin.replace(b'/extdomains/', b'')

        return raw_bin


def extract_url_path_and_query(full_url=None, no_query=False):
    """
    Convert http://foo.bar.com/aaa/p.html?x=y to /aaa/p.html?x=y

    :param no_query:
    :type full_url: str
    :param full_url: full url
    :return: str
    """
    if full_url is None:
        full_url = request.url
    split = urlsplit(full_url)
    result = split.path
    if not no_query and split.query:
        result += '?' + split.query
    return result


# ################# End Client Request Handler #################


# ################# Begin Middle Functions #################
def send_request(url, method='GET', headers=None, param_get=None, data=None):
    """实际发送请求到目标服务器, 对于重定向, 原样返回给用户
    被request_remote_site_and_parse()调用"""
    final_hostname = urlsplit(url).netloc
    dbgprint('FinalRequestUrl', url, 'FinalHostname', final_hostname)
    # Only external in-zone domains are allowed (SSRF check layer 2)
    if final_hostname not in allowed_domains_set and not developer_temporary_disable_ssrf_prevention:
        raise ConnectionAbortedError('Trying to access an OUT-OF-ZONE domain(SSRF Layer 2):', final_hostname)

    # set zero data to None instead of b''
    if not data:
        data = None

    if enable_keep_alive_per_domain:
        if final_hostname not in connection_pool_per_domain:
            connection_pool_per_domain[final_hostname] = {'session': requests.Session()}
        _requester = connection_pool_per_domain[final_hostname]['session']
        _requester.cookies.clear()
    else:
        _requester = requests

    # Send real requests
    req_start_time = time()
    r = _requester.request(
        method, url,
        params=param_get, headers=headers, data=data,
        proxies=requests_proxies, allow_redirects=False,
        stream=enable_stream_content_transfer,
    )
    # remote request time
    req_time = time() - req_start_time
    dbgprint('RequestTime:', req_time, v=4)

    # Some debug output
    # print(r.request.headers, r.headers)
    if verbose_level >= 3:
        dbgprint(r.request.method, "FinalSentToRemoteRequestUrl:", r.url, "\nRem Resp Stat: ", r.status_code)
        dbgprint("RemoteRequestHeaders: ", r.request.headers)
        if data:
            dbgprint('RemoteRequestRawData: ', r.request.body)
        dbgprint("RemoteResponseHeaders: ", r.headers)

    return r, req_time


def request_remote_site_and_parse():
    try:  # send request to remote server
        data = client_requests_bin_rewrite(request.get_data())
        # server's request won't follow 301 or 302 redirection
        this_request.remote_response, req_time_headers = send_request(
            this_request.remote_url,
            method=request.method,
            headers=this_request.client_header,
            data=data,  # client_requests_bin_rewrite(request.get_data()),
        )
        if this_request.remote_response.url != this_request.remote_url:
            warnprint('requests\'s remote url' + this_request.remote_response.url
                      + 'does no equals our rewrited url' + this_request.remote_url)
    except Exception as _e:
        errprint(_e)  # ERROR :( so sad
        traceback.print_exc()
        return generate_error_page(errormsg="Error occurs when requesting remote server", is_traceback=True)

    # extract response's mime to thread local var
    this_request.content_type = this_request.remote_response.headers.get('Content-Type', '') \
                                or this_request.remote_response.headers.get('content-type', '')
    this_request.mime = extract_mime_from_content_type(this_request.content_type)

    # only_serve_static_resources
    if only_serve_static_resources and not is_content_type_using_cdn(this_request.content_type):
        return generate_simple_resp_page(b'This site is just for static resources.', error_code=403)

    # is streamed
    is_streamed = enable_stream_content_transfer and is_content_type_streamed(this_request.content_type)

    # extract cache control header, if not cache, we should disable local cache
    this_request.cache_control = this_request.remote_response.headers.get('Cache-Control', '') \
                                 or this_request.remote_response.headers.get('cache-control', '')
    _response_no_cache = 'no-store' in this_request.cache_control or 'must-revalidate' in this_request.cache_control

    if verbose_level >= 4:
        dbgprint('Response Content-Type:', this_request.content_type,
                 'IsStreamed:', is_streamed,
                 'is_no_cache:', _response_no_cache,
                 'Line', current_line_number(), v=4)

    # add url's MIME info to record, for MIME-based CDN rewrite,
    #   next time we access this url, we would know it's mime
    # Notice: mime_based_static_resource_CDN will be auto disabled above when global CDN option are False
    if mime_based_static_resource_CDN and not _response_no_cache \
            and this_request.remote_response.request.method == 'GET' and this_request.remote_response.status_code == 200:
        # we should only cache GET method, and response code is 200
        # noinspection PyUnboundLocalVariable
        if this_request.url_no_scheme not in url_to_use_cdn:
            # 记录本URL的信息
            url_to_use_cdn[this_request.url_no_scheme] = [False, this_request.mime, len(this_request.remote_response.content)]

            if is_content_type_using_cdn(this_request.mime):
                # mark it to use cdn, and record it's url without scheme.
                # eg: If SERVER's request url is http://example.com/2333?a=x, we record example.com/2333?a=x
                # because the same url for http and https SHOULD be the same, drop the scheme would increase performance
                url_to_use_cdn[this_request.url_no_scheme][0] = True  # 标记为使用CDN
                dbgprint('CDN enabled for:', this_request.url_no_scheme)
            else:
                dbgprint('CDN disabled for:', this_request.url_no_scheme)

    # copy and parse remote response
    resp, req_time_body = copy_response(is_streamed=is_streamed)

    # storge entire our server's response (headers included)
    if local_cache_enable and not _response_no_cache:
        put_response_to_local_cache(this_request.remote_url, resp, without_content=is_streamed)

    if this_request.start_time is not None and not is_streamed:
        # remote request time should be excluded when calculating total time
        resp.headers.add('X-Header-Req-Time', "%.4f" % req_time_headers)
        resp.headers.add('X-Body-Req-Time', "%.4f" % req_time_body)
        resp.headers.add('X-Compute-Time', "%.4f" % (time() - this_request.start_time - req_time_headers - req_time_body))

    resp.headers.add('X-Powered-By', 'zmirror/%s' % __VERSION__)

    if developer_dump_all_traffics and not is_streamed:
        if not os.path.exists('traffic'):
            os.mkdir('traffic')
        _time_str = datetime.now().strftime('traffic_%Y-%m-%d_%H-%M-%S')
        try:
            with open(os.path.join('traffic', _time_str + '.dump'), 'wb') as fp:
                pickle.dump(
                    (_time_str,
                     (repr(request.url), repr(request.headers), repr(request.get_data())),
                     this_request.remote_response, resp
                     ),
                    fp)
        except:
            traceback.print_exc()
            return generate_error_page(errormsg="Unable to dump traffic", is_traceback=True)

    return resp


def filter_client_request():
    """过滤用户请求, 视情况拒绝用户的访问
    :rtype: Union[Response, None]
    """
    dbgprint('Client Request Url: ', request.url)

    # crossdomain.xml
    if os.path.basename(request.path) == 'crossdomain.xml':
        dbgprint('crossdomain.xml hit from', request.url)
        return crossdomain_xml()

    # Global whitelist ua
    if check_global_ua_pass(str(request.user_agent)):
        return None

    if is_deny_spiders_by_403 and is_denied_because_of_spider(str(request.user_agent)):
        return generate_simple_resp_page(b'Spiders Are Not Allowed To This Site', 403)

    if human_ip_verification_enabled and (
                ((human_ip_verification_whitelist_from_cookies or enable_custom_access_cookie_generate_and_verify)
                 and must_verify_cookies)
            or is_ip_not_in_allow_range(request.remote_addr)
    ):
        dbgprint('ip', request.remote_addr, 'is verifying cookies')
        if 'zmirror_verify' in request.cookies and \
                ((human_ip_verification_whitelist_from_cookies and verify_ip_hash_cookie(request.cookies.get('zmirror_verify')))
                 or (enable_custom_access_cookie_generate_and_verify and custom_verify_access_cookie(
                        request.cookies.get('zmirror_verify'), request))):
            ip_whitelist_add(request.remote_addr, info_record_dict=request.cookies.get('zmirror_verify'))
            dbgprint('add to ip_whitelist because cookies:', request.remote_addr)
        else:
            return redirect(
                "/ip_ban_verify_page?origin=" + base64.urlsafe_b64encode(str(request.url).encode(encoding='utf-8')).decode(),
                code=302)

    return None


def prior_request_redirect():
    """对用户的请求进行按需重定向处理
    与 rewrite_client_request() 不同, 使用301/307等进行外部重定向, 不改变服务器内部数据
    遇到任意一个需要重定向的, 就跳出本函数

    这是第一阶段重定向

    第一阶段重定向, 是在 rewrite_client_request() 内部隐式重写 *之前* 的重定向
    第二阶段重定向, 是在 rewrite_client_request() 内部隐式重写 *之后* 的重定向

    :return: 如果不需要重定向, 则返回None, 否则返回重定向的 Response
    :rtype: Union[Response, None]
    """

    # hostname, extpath_query = _temp['domain'], _temp['path_query']
    if this_request.remote_domain in domain_alias_to_target_set and '/extdomains/' == request.path[:12]:
        dbgprint('Requesting main domain in extdomains, redirect back.')
        return redirect(this_request.remote_path_query, code=307)

    if enable_individual_sites_isolation and '/extdomains/' != request.path[:12] and request.headers.get('referer'):
        reference_domain = decode_mirror_url(request.headers.get('referer'))['domain']
        if reference_domain in isolated_domains:
            return redirect(encode_mirror_url(this_request.remote_path_query, reference_domain), code=307)

    if url_custom_redirect_enable:
        if request.path in url_custom_redirect_list:
            redirect_to = request.url.replace(request.path, url_custom_redirect_list[request.path], 1)
            if verbose_level >= 3: dbgprint('Redirect from', request.url, 'to', redirect_to)
            return redirect(redirect_to, code=307)

        for regex_match, regex_replace in url_custom_redirect_regex:
            if re.match(regex_match, extract_url_path_and_query(), flags=re.IGNORECASE) is not None:
                redirect_to = re.sub(regex_match, regex_replace, extract_url_path_and_query(), flags=re.IGNORECASE)
                if verbose_level >= 3: dbgprint('Redirect from', request.url, 'to', redirect_to)
                return redirect(redirect_to, code=307)


def posterior_request_redirect():
    """
    这是第二阶段重定向, 内部隐式重写 *之后* 的重定向
    第一阶段重定向, 是在 rewrite_client_request() 内部隐式重写 *之前* 的重定向
    第二阶段重定向, 是在 rewrite_client_request() 内部隐式重写 *之后* 的重定向

    遇到任意一个需要重定向的, 就跳出本函数

    :return: 如果不需要重定向, 则返回None, 否则返回重定向的 Response
    :rtype: Union[Response, None]
    """

    # CDN软重定向
    # 具体请看 config 中 cdn_redirect_code_if_cannot_hard_rewrite 选项的说明
    if mime_based_static_resource_CDN:  # CDN总开关
        if (cdn_redirect_code_if_cannot_hard_rewrite  # CDN软(301/307)重定向开关
            # 该URL所对应的资源已知, 即之前已经被成功请求过
            and this_request.url_no_scheme in url_to_use_cdn
            # 并且该资源已经被判断为可以应用CDN
            and url_to_use_cdn[this_request.url_no_scheme][0]
            # 只缓存 GET 方法的资源
            and request.method == 'GET'
            # 只有超过大小下限才会重定向
            and url_to_use_cdn[this_request.url_no_scheme][2] > cdn_soft_redirect_minimum_size
            # 请求者的UA符合CDN提供商的爬虫, 则返回实际的资源
            and not is_ua_in_whitelist(str(request.user_agent))
            ):
            # 下面这个urljoin, 是把形如 https://foo.com/a.png?q=233 的url转化为对应的CDN URL https://cdn.com/a.png?q=233
            redirect_to_url = urljoin(
                my_host_scheme
                # 根据url的crc32取余来选取一个CDN域名
                # 使用crc32, 而不是随机数, 是为了确保相同的URL每次都能应用相同的CDN域名
                # 以增加CDN和缓存命中率
                + CDN_domains[zlib.adler32(this_request.url_no_scheme.encode()) % cdn_domains_number],
                extract_url_path_and_query()  # 得到目标url的 /a.png?q=233 这么个部分
            )
            if cdn_redirect_encode_query_str_into_url:
                # 将 ?q=233 这种查询字串编码进path, 详情看config里的说明
                redirect_to_url = embed_real_url_to_embedded_url(
                    redirect_to_url, url_mime=url_to_use_cdn[this_request.url_no_scheme][1])

            return redirect(redirect_to_url, code=cdn_redirect_code_if_cannot_hard_rewrite)

    # 本地缓存若命中则直接返回
    if local_cache_enable:
        resp = try_get_cached_response(this_request.remote_url, this_request.client_header)
        if resp is not None:
            dbgprint('CacheHit,Return')
            if this_request.start_time is not None:
                resp.headers.set('X-Compute-Time', "%.4f" % (time() - this_request.start_time))
            return resp


def rewrite_client_request():
    """
    在这里的所有重写都只作用程序内部, 对请求者不可见
    与 prior_request_redirect() 的外部301/307重定向不同,
    本函数通过改变程序内部变量来起到重定向作用
    返回True表示进行了重定向, 需要重载某些设置, 返回False表示未重定向
    遇到重写后, 不会跳出本函数, 而是会继续下一项. 所以重写顺序很重要
    """
    has_been_rewrited = False

    # ------------- 请求重写代码开始 ----------------
    if cdn_redirect_encode_query_str_into_url:
        try:
            real_url = extract_real_url_from_embedded_url(request.url)
        except:
            traceback.print_exc()
            raise
        else:
            if real_url is not None:
                dbgprint("BeforeEmbeddedExtract:", request.url, " After:", real_url)
                request.url = real_url
                request.path = urlsplit(real_url).path
                has_been_rewrited = True

    if url_custom_redirect_enable and shadow_url_redirect_regex:
        _path_query = extract_url_path_and_query()
        _path_query_raw = _path_query

        for before, after in shadow_url_redirect_regex:
            _path_query = re.sub(before, after, _path_query)
            if _path_query != _path_query_raw:
                dbgprint('ShadowUrlRedirect:', _path_query_raw, 'to', _path_query)
                request.url = myurl_prefix + _path_query
                request.path = urlsplit(_path_query).path
                has_been_rewrited = True
                break
    # ------------- 请求重写代码结束 ----------------

    # 如果进行了重写, 那么 has_been_rewrited 为 True
    # 在 rewrite_client_request() 函数内部会更改 request.url
    # 所以此时需要重新解析一遍
    if has_been_rewrited:
        _temp = decode_mirror_url()
        this_request.remote_domain = _temp['domain']  # type: str
        this_request.is_https = _temp['is_https']  # type: bool
        this_request.remote_path = _temp['path']  # type: str
        this_request.remote_path_query = _temp['path_query']  # type: str
        this_request.is_external_domain = this_request.remote_domain not in domain_alias_to_target_set
        this_request.remote_url = assemble_remote_url()  # type: str
        this_request.url_no_scheme = this_request.remote_url[this_request.remote_url.find('//') + 2:]  # type: str

    return has_been_rewrited


# ################# End Middle Functions #################


# ################# Begin Flask #################
@app.route('/zmirror_stat')
def zmirror_status():
    """返回服务器的一些状态信息"""
    if request.remote_addr and request.remote_addr != '127.0.0.1':
        return generate_simple_resp_page(b'Only 127.0.0.1 are allowed', 403)
    output = ""
    output += strx('extract_real_url_from_embedded_url', extract_real_url_from_embedded_url.cache_info())
    output += strx('\nis_content_type_streamed', is_content_type_streamed.cache_info())
    output += strx('\nembed_real_url_to_embedded_url', embed_real_url_to_embedded_url.cache_info())
    output += strx('\ncheck_global_ua_pass', check_global_ua_pass.cache_info())
    output += strx('\nextract_mime_from_content_type', extract_mime_from_content_type.cache_info())
    output += strx('\nis_content_type_using_cdn', is_content_type_using_cdn.cache_info())
    output += strx('\nis_ua_in_whitelist', is_content_type_using_cdn.cache_info())
    output += strx('\nis_mime_represents_text', is_mime_represents_text.cache_info())
    output += strx('\nis_domain_match_glob_whitelist', is_domain_match_glob_whitelist.cache_info())
    output += strx('\nverify_ip_hash_cookie', verify_ip_hash_cookie.cache_info())
    output += strx('\nis_denied_because_of_spider', is_denied_because_of_spider.cache_info())
    output += strx('\nis_ip_not_in_allow_range', is_ip_not_in_allow_range.cache_info())
    output += strx('\n\ncurrent_threads_number', threading.active_count())
    # output += strx('\nclient_requests_text_rewrite', client_requests_text_rewrite.cache_info())
    # output += strx('\nextract_url_path_and_query', extract_url_path_and_query.cache_info())
    output += strx('\n\nurl_rewriter_cache len: ', len(url_rewrite_cache),
                   'Hits:', url_rewrite_cache_hit_count, 'Misses:', url_rewrite_cache_miss_count)

    output += strx('\n----------------\n')
    output += strx('\ndomain_alias_to_target_set', domain_alias_to_target_set)

    return "<pre>" + output + "</pre>\n"


@app.route('/ip_ban_verify_page', methods=['GET', 'POST'])
def ip_ban_verify_page():
    """生成一个身份验证页面"""
    if request.method == 'GET':
        dbgprint('Verifying IP:', request.remote_addr)
        form_body = ''
        for q_id, _question in enumerate(human_ip_verification_questions):
            form_body += r"""%s <input type="text" name="%d" placeholder="%s" style="width: 190px;" /><br/>""" \
                         % (_question[0], q_id, (html_escape(_question[2]) if len(_question) >= 3 else ""))

        for rec_explain_string, rec_name, input_type in human_ip_verification_identity_record:
            form_body += r"""%s %s<input type="%s" name="%s" /><br/>""" % (
                rec_explain_string,
                ('<span style="color: red;">(必填)<span> ' if human_ip_verification_answer_any_one_questions_is_ok else ""),
                html_escape(input_type), html_escape(rec_name))

        if 'origin' in request.args:
            form_body += r"""<input type="hidden" name="origin" value="%s" style="width: 190px;" />""" % html_escape(
                request.args.get('origin'))

        return r"""<!doctype html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <title>%s</title>
        </head>
        <body>
          <h1>%s</h1>
          <p>这样的验证只会出现一次，通过后您会被加入白名单，之后相同IP的访问不会再需要验证。<br/>
          提示: 由于手机和宽带IP经常会发生改变，您可能会多次看到这一页面。</p>
          %s <br>
          <pre style="border: 1px dashed;">%s</pre>
          <form method='post'>%s<button type='submit'>递交</button>
          </form>
        </body>
        </html>""" % (
            html_escape(human_ip_verification_title), html_escape(human_ip_verification_title),
            ("只需要回答出以下<b>任意一个</b>问题即可" if human_ip_verification_answer_any_one_questions_is_ok
             else "你需要回答出以下<b>所有问题</b>"),
            human_ip_verification_description, form_body)

    elif request.method == 'POST':
        dbgprint('Verifying Request Form', request.form)

        # 遍历所有问题, 看有没有正确回答上来
        for q_id, _question in enumerate(human_ip_verification_questions):
            submitted_answer = request.form.get(str(q_id), '')
            if submitted_answer == '':  # 没有回答这个问题
                if human_ip_verification_answer_any_one_questions_is_ok:  # 如果只需要回答一个, 那么就跳过
                    continue
                else:  # 如果全部都需要回答, 那么报错
                    return generate_simple_resp_page(b'Please answer question: ' + _question[0].encode(), 200)

            if submitted_answer != _question[1]:  # 如果回答了, 但是答案错误
                return generate_simple_resp_page(b'Wrong answer in: ' + _question[0].encode(), 200)
            elif human_ip_verification_answer_any_one_questions_is_ok:
                break  # 只需要正确回答出一个, 就通过

        else:  # 如果在for中是break跳出的, 就不会执行else, 只有正常执行完for才会进入else
            if human_ip_verification_answer_any_one_questions_is_ok:  # 如果只需要回答一个, 进入else表示一个问题都没回答
                return generate_simple_resp_page(b'Please answer at least ONE question', 200)

        record_dict = {}
        for rec_explain_string, rec_name, form_type in human_ip_verification_identity_record:
            if rec_name not in request.form:
                return generate_simple_resp_page(b'Param Missing: ' + rec_explain_string.encode(), 200)
            else:
                record_dict[rec_name] = request.form.get(rec_name)

        origin = '/'
        if 'origin' in request.form:
            try:
                origin = base64.urlsafe_b64decode(request.form.get('origin')).decode(encoding='utf-8')
            except:
                return generate_error_page(
                    "Unable to decode origin from value:" + html_escape(request.form.get('origin')), is_traceback=True)
            else:
                netloc = urlsplit(origin).netloc
                if netloc and netloc != my_host_name:
                    origin = '/'

        if identity_verify_required:
            if not custom_identity_verify(record_dict):
                return generate_simple_resp_page(b'Verification Failed, please check', 200)

        resp = generate_html_redirect_page(origin, msg=human_ip_verification_success_msg)

        if human_ip_verification_whitelist_from_cookies:
            _hash = generate_ip_verify_hash(record_dict)
            resp.set_cookie(
                'zmirror_verify',
                _hash,
                expires=datetime.now() + timedelta(days=human_ip_verification_whitelist_cookies_expires_days),
                max_age=human_ip_verification_whitelist_cookies_expires_days * 24 * 3600
                # httponly=True,
                # domain=my_host_name
            )
            record_dict['__zmirror_verify'] = _hash

        elif enable_custom_access_cookie_generate_and_verify:
            try:
                _hash = custom_generate_access_cookie(record_dict, request)

                dbgprint('SelfGeneratedCookie:', _hash)

                if _hash is None:
                    return generate_simple_resp_page(b'Verification Failed, please check', 200)

                resp.set_cookie(
                    'zmirror_verify',
                    _hash,
                    expires=datetime.now() + timedelta(days=human_ip_verification_whitelist_cookies_expires_days),
                    max_age=human_ip_verification_whitelist_cookies_expires_days * 24 * 3600
                    # httponly=True,
                    # domain=my_host_name
                )
                record_dict['__zmirror_verify'] = _hash
            except:
                traceback.print_exc()
                return generate_error_page(errormsg='Server error when generating verification cookie', is_traceback=True)

        ip_whitelist_add(request.remote_addr, info_record_dict=record_dict)
        return resp


# noinspection PyUnusedLocal
@app.route('/', methods=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'HEAD', 'PATCH'])
@app.route('/<path:input_path>', methods=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'HEAD', 'PATCH'])
def main_function(input_path='/'):
    """本程序的实际入口函数"""
    dbgprint('-----BeginRequest-----')

    # this_request 类似于 flask 的 request, 是 zmirror 特有的一个 thread-local 变量
    # 这个变量的重要性不亚于 request, 在 zmirror 各个部分都会用到
    # 其各个变量的含义如下:
    # this_request.start_time             处理请求开始的时间, unix 时间戳
    #             .remote_domain          当前请求对应的远程域名
    #             .is_external_domain     远程域名是否是外部域名, 比如google镜像, www.gstatic.com 就是外部域名
    #             .is_https               是否需要用https 来请求远程域名
    #             .remote_url             远程服务器的url, 比如 https://google.com/search?q=233
    #             .url_no_scheme          没有协议前缀的url,比如 google.com/search?q=233 通常在缓存中用
    #             .remote_path_query      对应的远程path+query, 比如 /search?q=2333
    #             .remote_path            对应的远程path,  比如 /search
    #             .client_header          经过转换和重写以后的访问者请求头
    #             .content_type           远程服务器响应头中的 content_type, 比如 "text/plain; encoding=utf-8"
    #             .mime                   远程服务器响应的MIME, 比如 "text/html"
    #             .cache_control          远程服务器响应的cache_control内容
    #             .remote_response        远程服务器的响应, requests.Response
    #             .temporary_domain_alias 用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项

    this_request.start_time = time()  # to display compute time
    this_request.temporary_domain_alias = ()  # init temporary_domain_alias

    # 将用户请求的URL解析为对应的目标服务器URL
    _temp = decode_mirror_url()
    this_request.remote_domain = _temp['domain']  # type: str
    this_request.is_https = _temp['is_https']  # type: bool
    this_request.remote_path = _temp['path']  # type: str
    this_request.remote_path_query = _temp['path_query']  # type: str
    this_request.is_external_domain = this_request.remote_domain not in domain_alias_to_target_set
    this_request.remote_url = assemble_remote_url()  # type: str
    this_request.url_no_scheme = this_request.remote_url[this_request.remote_url.find('//') + 2:]  # type: str
    dbgprint('after extract, url:', request.url, '   path:', request.path)

    # 对用户请求进行检查和过滤
    # 不符合条件的请求(比如爬虫)将终止执行
    # 函数不会修改 this_request
    r = filter_client_request()
    if r is not None:  # 如果函数返回值不是None, 则表示需要响应给用户
        dbgprint('-----EndRequest(filtered out)-----')
        return r

    # 对用户请求进行第一级重定向(隐式重写前的重定向)
    # 函数不会修改 this_request
    r = prior_request_redirect()
    if r is not None:
        return r

    # 进行请求的隐式重写/重定向
    # 隐式重写只对 zmirror 内部生效, 对浏览器透明
    # 重写可能会修改 flask 的内置 request 变量
    # 可能会修改 this_request
    try:
        has_been_rewrited = rewrite_client_request()
    except:
        return generate_error_page(errormsg="Error occurs when rewriting client request", is_traceback=True)

    if ssrf_check_layer_1():
        return generate_simple_resp_page(
            b'SSRF Prevention! Your Domain Are NOT ALLOWED.', 403)

    # 提取出经过必要重写后的客户请求头
    this_request.client_header = extract_client_header()  # type: dict

    # 对用户请求进行第二级重定向(隐式重写后的重定向)
    r = posterior_request_redirect()
    if r is not None:
        return r

    try:
        resp = request_remote_site_and_parse()
    except:
        traceback.print_exc()
        return generate_error_page(is_traceback=True)

    dbgprint('-----EndRequest-----')
    return resp


@app.route('/crossdomain.xml')
def crossdomain_xml():
    return Response("""<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<allow-access-from domain="*"/>
<site-control permitted-cross-domain-policies="all"/>
<allow-http-request-headers-from domain="*" headers="*" secure="false"/>
</cross-domain-policy>""", content_type='text/x-cross-domain-policy')


@app.route('/about_zmirror')
def about_zmirror():
    return Response("""zmirror
version: {version}
Author: {author}
Github: {github_url}
Mirroring: {source_site}
Note: Love Luciaz Forever!
""".format(version=__VERSION__, author=__AUTHOR__, github_url=__GITHUB_URL__, source_site=target_domain),
                    content_type='text/plain')


# ################# End Flask #################

# ################# Begin Post (auto)Exec Section #################

# ########### domain replacer prefix string buff ###############
prefix_buff = {}
for _domain in allowed_domains_set:
    prefix_buff[_domain] = calc_domain_replace_prefix(_domain)

if human_ip_verification_enabled:
    single_ip_allowed_set = load_ip_whitelist_file()

if custom_text_rewriter_enable:
    try:
        from custom_func import custom_response_text_rewriter
    except:
        identity_verify_required = False
        warnprint('Cannot import custom_response_text_rewriter custom_func.py,'
                  ' `custom_text_rewriter` is now disabled(if it was enabled)')
        traceback.print_exc()
        raise

if identity_verify_required:
    try:
        from custom_func import custom_identity_verify
    except:
        identity_verify_required = False
        warnprint('Cannot import custom_identity_verify from custom_func.py,'
                  ' `identity_verify` is now disabled (if it was enabled)')
        traceback.print_exc()
        raise

if enable_custom_access_cookie_generate_and_verify:
    try:
        from custom_func import custom_generate_access_cookie, custom_verify_access_cookie
    except:
        enable_custom_access_cookie_generate_and_verify = False
        errprint('Cannot import custom_generate_access_cookie and custom_generate_access_cookie from custom_func.py,'
                 ' `enable_custom_access_cookie_generate_and_verify` is now disabled (if it was enabled)')
        traceback.print_exc()
        raise

try:
    from custom_func import *
except:
    pass

if enable_cron_tasks:
    for _task_dict in cron_tasks_list:
        try:
            _task_dict['target'] = globals()[_task_dict['target']]
            cron_task_container(_task_dict, add_task_only=True)
        except Exception as e:
            errprint('UnableToInitCronTask', e)
            traceback.print_exc()
            raise

    th = threading.Thread(target=cron_task_host, daemon=True)
    th.start()

# ################# End Post (auto)Exec Section #################

if __name__ == '__main__':
    errprint('Please use `python3 wsgi.py` to run')
    exit()
