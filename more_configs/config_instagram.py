# coding=utf-8
# 这是为instagram镜像配置的示例配置文件
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 修改 my_host_name 为你自己的域名
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# instagram所有功能完整可用(暂时还没发现不能用的功能),
# 由于instagram官方的设定, 网页版是无法上传文件的, 只能看别人的动态
#
# Github: https://github.com/Aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'
my_host_port = None  # None表示使用默认端口, 可以设置成非标准端口, 比如 81

# ############## Target Domain Settings ##############
target_domain = 'www.instagram.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集会不断告诉你新域名
external_domains = (
    # 下面的 `Automatic Domains Whitelist` 功能会自动检测并添加其他的子域名
    'instagramstatic-a.akamaihd.net',
    'scontent.cdninstagram.com',
    'help.instagram.com',
    'blog.instagram.com',
    'api.instagram.com',

    'www.facebook.com',
    'connect.facebook.net',
    'static.xx.fbcdn.net',
    'pixel.facebook.com',
    'facebook.com',
    'scontent.xx.fbcdn.net',
    '3-edge-chat.facebook.com',
    'm.facebook.com',
    'fbcdn-photos-a-a.akamaihd.net',
    'api.facebook.com',
    'api-read.facebook.com',
    'l.facebook.com',
    'zh-cn.facebook.com',
    'upload.facebook.com',
    'vupload2.facebook.com',
    'vupload-edge.facebook.com',
    'staticxx.facebook.com',
    'external.xx.fbcdn.net',

    'fonts.googleapis.com',

    'scontent-lax3-1.cdninstagram.com',
    'l.instagram.com',
    'scontent-sjc2-1.cdninstagram.com',
)

force_https_domains = 'ALL'

enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = (
    '*.facebook.com', '*.fbcdn.net', '*.facebook.net', '*.akamaihd.net', '*.instagram.com', '*.cdninstagram.com')

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)
