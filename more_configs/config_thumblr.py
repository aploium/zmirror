# coding=utf-8
# 这是 thumblr.com 的配置文件
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 修改 my_host_name 为你自己的域名
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# 由于注册过程中有 google captcha 出现, zmirror暂时还无法兼容captcha, 所以无法注册
# 但是其他功能基本完整(包括登录以后的功能)

# Github: https://github.com/aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'
my_host_port = None  # None表示使用默认端口, 可以设置成非标准端口, 比如 81

# ############## Target Domain Settings ##############
target_domain = 'www.tumblr.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = (
    'tumblr.co',
    'tumblr.com',
    'api.tumblr.com',
    'api.tumblr.com',
    'assets.tumblr.com',
    'www.tumblr.com',
    'cynicallys.tumblr.com',
    'mx.tumblr.com',
    'px.srvcs.tumblr.com',
    'media.tumblr.com',
    '30.media.tumblr.com',
    '31.media.tumblr.com',
    '32.media.tumblr.com',
    '33.media.tumblr.com',
    '34.media.tumblr.com',
    '35.media.tumblr.com',
    '36.media.tumblr.com',
    '37.media.tumblr.com',
    '38.media.tumblr.com',
    '39.media.tumblr.com',
    '40.media.tumblr.com',
    '41.media.tumblr.com',
    '42.media.tumblr.com',
    '43.media.tumblr.com',
    '44.media.tumblr.com',
    '45.media.tumblr.com',
    '46.media.tumblr.com',
    '47.media.tumblr.com',
    '48.media.tumblr.com',
    '49.media.tumblr.com',
    '50.media.tumblr.com',
    '90.media.tumblr.com',
    '65.media.tumblr.com',
    '65.media.tumblr.com',
    '66.media.tumblr.com',
    '67.media.tumblr.com',
    '91.media.tumblr.com',
    '92.media.tumblr.com',
    '93.media.tumblr.com',
    '94.media.tumblr.com',
    '95.media.tumblr.com',
    '96.media.tumblr.com',
    '97.media.tumblr.com',
    '98.media.tumblr.com',
    '99.media.tumblr.com',
    'secure.assets.tumblr.com',
    'secure.static.tumblr.com',
    'secure.assets.tumblr.com',
    'ls.srvcs.tumblr.com',
    'media.tumblr.com',
    'media.tumblr.com',
    'assets.tumblr.com',
    'assets.tumblr.com',
    'vt.tumblr.com',
    'vt.tumblr.com',
    'vt.tumblr.com',
    'vt.tumblr.com',
    'secure.static.tumblr.com',
    'secure.static.tumblr.com',
    'secure.static.tumblr.com',

    'sb.scorecardresearch.com',
    'cookiex.ngd.yahoo.com',
    'www.google.com',
    'www.gstatic.com',
    'fonts.gstatic.com',
)

# 强制所有站点使用HTTPS
force_https_domains = 'ALL'

# 自动动态添加域名
enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = ('*.tumblr.com', )

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)
