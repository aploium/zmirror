# coding=utf-8
# 这是 dropbox 的配置文件
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 修改 my_host_name 为你自己的域名
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# 功能不稳定. 并且由于要加载大量脚本, 所以刚开始速度会很慢, 使用一小段时间以后, 积累一些缓存后会变快

# Github: https://github.com/aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'
my_host_port = None  # None表示使用默认端口, 可以设置成非标准端口, 比如 81

# ############## Target Domain Settings ##############
target_domain = 'www.dropbox.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = (
    'ajax.googleapis.com',
    'api-content-photos.dropbox.com',
    'api-content.dropbox.com',
    'api-d.dropbox.com',
    'api-notify.dropbox.com',
    'api.demandbase.com',
    'api.dropbox.com',
    'api.dropboxapi.com',
    'api.v.dropbox.com',
    'b.6sc.co',
    'b92.yahoo.co.jp',
    'block.dropbox.com',
    'block.v.dropbox.com',
    'blogs.dropbox.com',
    'bolt.dropbox.com',
    'cf.dropboxstatic.com',
    'cfl.dropboxstatic.com',
    'client-cf.dropbox.com',
    'client-lb.dropbox.com',
    'client-web.dropbox.com',
    'client.dropbox.com',
    'client.v.dropbox.com',
    'connect.facebook.net',
    'd.dropbox.com',
    'd.v.dropbox.com',
    'db.tt',
    'dbxlocal.dropboxstatic.com',
    'dl-debug.dropbox.com',
    'dl-web.dropbox.com',
    'dl.dropbox.com',
    'dl.dropboxusercontent.com',
    'dropboxstatic.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'forums.dropbox.com',
    'j.6sc.co',
    'linux.dropbox.com',
    'log.getdropbox.com',
    'm.dropbox.com',
    'marketing.dropbox.com',
    'notify.dropbox.com',
    'photos-1.dropbox.com',
    'photos-2.dropbox.com',
    'photos-3.dropbox.com',
    'photos-4.dropbox.com',
    'photos-5.dropbox.com',
    'photos-6.dropbox.com',
    'photos-thumb.dropbox.com',
    'photos-thumb.x.dropbox.com',
    'photos.dropbox.com',
    'platform.twitter.com',
    's.yimg.com',
    's3.amazonaws.com',
    'snapengage.dropbox.com',
    'status.dropbox.com',
    'www.dropboxstatic.com',
    'www.facebook.com',
    'www.v.dropbox.com'
    'dropbox.com',
    'www.googletagmanager.com',
    'www.google-analytics.com',
    'flash.dropboxstatic.com',
    'flash.dropboxstatic.com',
    'ac.dropboxstatic.com',
)

# 强制所有站点使用HTTPS
force_https_domains = 'ALL'

# 自动动态添加域名
enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = ('*.dropbox.com', '*.dropboxstatic.com',)


# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)
