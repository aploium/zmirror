# coding=utf-8
import os
import re
import ipaddress
from urllib.parse import urljoin, urlsplit, urlunsplit, quote_plus
from . import CONSTS

if "ZMIRROR_UNITTEST" in os.environ:
    # 这边根据环境变量得到的unittest_mode信息会被config中的覆盖掉
    # 只是因为此时还没有加载 config, 所以先根据env里的临时定一下
    unittest_mode = True
else:
    unittest_mode = False

from . import utils_simple

# if _unittest_mode:
#     print("reloading config 18")
#     importlib.reload(importlib.import_module("config_default"))

try:  # 加载默认设置
    from config_default import *
except:  # coverage: exclude
    print('the config_default.py is missing, this program may not works normally\n'
          'config_default.py 文件丢失, 这会导致配置文件不向后兼容, 请重新下载一份 config_default.py')
    raise  # v0.23.1+ 当 config_default.py 不存在时, 程序会终止运行

# if _unittest_mode:
#     unittest_mode = True
#     print("reloading config 26")
#     importlib.reload(importlib.import_module("config"))

try:  # 加载用户自定义配置文件, 覆盖掉默认配置的同名项
    from config import *
except:  # coverage: exclude
    print(
        'the config_default.py is missing, fallback to default configs(if we can), '
        'please COPY the config_default.py to config.py, and change it\'s content, '
        'or use the configs in the more_configs folder\n'
        '自定义配置文件 config.py 丢失或存在错误, 将使用默认设置, 请将 config_default.py 复制一份为 config.py, '
        '并根据自己的需求修改里面的设置'
        '(或者使用 more_configs 中的配置文件)'
    )
    raise  # v0.23.1+ 当config文件存在错误或不存在时, 程序会终止运行
else:
    target_domain = target_domain.strip("./ \t").replace("https://", "").replace("http://", "")

my_host_name_no_port = my_host_name  # 不带有端口号的本机域名

if my_host_port is not None:
    my_host_name += ':' + str(my_host_port)  # 带有端口号的本机域名, 如果为标准端口则不带显式端口号
    my_host_name_urlencoded = quote_plus(my_host_name)  # url编码后的
else:
    my_host_name_urlencoded = my_host_name

if external_domains is None:
    external_domains = []
external_domains = list([d.strip("./ \t").replace("https://", "").replace("http://", "") for d in external_domains])

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
target_domain_root = utils_simple.extract_root_domain(target_domain)[0]  # type: str
my_host_name_root = utils_simple.extract_root_domain(target_domain)[0]  # type: str

# ########## Handle dependencies #############

if not enable_stream_content_transfer:
    steamed_mime_keywords = ()

if not url_custom_redirect_enable:
    url_custom_redirect_list = {}
    url_custom_redirect_regex = ()
    shadow_url_redirect_regex = ()
    plain_replace_domain_alias = []

if isinstance(plain_replace_domain_alias, tuple):
    plain_replace_domain_alias = list(plain_replace_domain_alias)

if not enable_stream_content_transfer:
    enable_stream_transfer_async_preload = False

if not enable_automatic_domains_whitelist:
    domains_whitelist_auto_add_glob_list = tuple()

if not enable_individual_sites_isolation:
    isolated_domains = set()
else:
    for isolated_domain in isolated_domains:
        if isolated_domain not in external_domains_set:
            print('An isolated domain:', isolated_domain,
                  'would not have effect because it did not appears in the `external_domains` list')

if enable_custom_access_cookie_generate_and_verify:
    human_ip_verification_whitelist_from_cookies = False

if not is_use_proxy:
    requests_proxies = None
if human_ip_verification_enabled:
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

# 遍历编译 custom_inject_content 中的regex
custom_inject_content = custom_inject_content or {}
for k, v in custom_inject_content.items():
    if not v:
        continue
    for a in v:
        if a.get("url_regex") is None:
            continue
        a["url_regex"] = re.compile(a["url_regex"], flags=re.I)
