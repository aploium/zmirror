# coding=utf-8
# 这是为twitter(PC站)镜像配置的示例配置文件
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 修改 my_host_name 为你自己的域名
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# 由于twitterPC和twitterMobile实际上是相互独立的, 而且由于逻辑非常复杂, 即使使用镜像隔离功能, 也会导致手机站不正常
#   所以把twitterPC和twitterMobile分成两个配置文件
# 使用本配置文件运行的twitter镜像, 支持所有的twitter功能(暂时还没发现不能用的功能)
#
# ########################################
# 警告: twitter镜像在非https环境下可能会无法注册, 其他功能也可能会出现问题, 请在https环境下部署twitter镜像
# ########################################
#
#
# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
target_domain = 'twitter.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集会不断告诉你新域名
external_domains = [
    'mobile.twitter.com',

    't.co',
    'dev.twitter.com',
    'ads.twitter.com',
    'analytics.twitter.com',
    'pic.twitter.com',
    'api.twitter.com',
    'platform.twitter.com',
    'upload.twitter.com',
    'ton.twitter.com',
    'support.twitter.com',
    'about.twitter.com',
    'tweetdeck-devel.atla.twitter.com',
    'tweetdeck-devel.smf1.twitter.com',
    'tdapi-staging.smf1.twitter.com',
    'tweetdeck.localhost.twitter.com',
    'tweetdeck.twitter.com',
    'tdapi-staging.atla.twitter.com',
    'localhost.twitter.com',
    'donate.twitter.com',
    'syndication.twitter.com',
    'status.twitter.com',
    'engineering.twitter.com',
    'help.twitter.com',
    'blog.twitter.com',
    'business.twitter.com',
    'cards-dev.twitter.com',

    'caps.twitter.com',
    'quickread.twitter.com',
    'tailfeather.twimg.com',
    'publish.twitter.com',
    'brand.twitter.com',
    't.lv.twimg.com',
    'media.twitter.com',

    'g2.twimg.com',
    'hca.twimg.com',
    'g.twimg.com',
    'video.twimg.com',
    'ma.twimg.com',
    'abs.twimg.com',
    'pbs.twimg.com',
    'ton.twimg.com',
    'ma-0.twimg.com',
    'ma-1.twimg.com',
    'ma-2.twimg.com',
    'o.twimg.com',
    'abs-0.twimg.com',
    'abs-1.twimg.com',
    'abs-2.twimg.com',
    'amp.twimg.com',

    'www.google.com',
    'ssl.gstatic.com',
    'www.gstatic.com',
    'apis.google.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'accounts.google.com',
    'accounts.youtube.com',
    'fonts.googleapis.com',
]

force_https_domains = 'ALL'

enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = ('*.twitter.com', '*.twimg.com',)

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

text_like_mime_keywords = ('text', 'json', 'javascript', 'xml', 'x-mpegurl')

# ############## Misc ##############
# 不加这个似乎也没影响的样子..... 不过以防万一还是加上吧
custom_allowed_remote_headers = {
    'access-control-allow-credentials', 'access-control-allow-headers', 'access-control-allow-methods',
    'access-control-max-age', 'access-control-allow-origin', 'x-connection-hash'}
