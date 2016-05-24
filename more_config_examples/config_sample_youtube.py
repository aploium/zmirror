# coding=utf-8
# 这是为Youtube镜像配置的示例配置文件
#
# 使用方法:
#   复制本文件和 custom_func_youtube.py 到 EasyWebsiteMirror.py 同级目录,
#     复制后本文件重命名为 config.py, custom_func_youtube.py 重命名为 custom_func.py
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# Youtube的功能非常复杂...而且有大量不常规的技术, 这个配置的镜像还有一些bug,
#   暂时只支持基础的看视频功能, 评论区很多时候无法正常加载, 无法登陆

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
target_domain = 'www.youtube.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集会不断告诉你新域名
external_domains = [
    'm.youtube.com',
    's.youtube.com',

    'apis.google.com',
    'plus.google.com',
    'accounts.google.com',
    'content.google.com',
    'apis.google.com',
    'www.googletagservices.com',

    'clients1.google.com',
    'clients6.google.com',
    'www.googleapis.com',
    'www.google.com',
    'www.gstatic.com',
    'www.youtube-nocookie.com',
    's.ytimg.com',
    'i.ytimg.com',
    'i1.ytimg.com',
    'encrypted.google.com',
    'fonts.gstatic.com',
    'ssl.gstatic.com',
    'yt3.ggpht.com',
]

force_https_domains = 'ALL'

enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = ('*.google.com', '*.google.com.hk', '*.gstatic.com',
                                        '*.googleusercontent.com', '*.youtube.com', '*.ytimg.com', '*.ggpht.com',
                                        '*.googlevideo.com',)

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

# ############## Misc ##############

custom_text_rewriter_enable = True

stream_transfer_buffer_size = 32768  # 32KB

url_custom_redirect_enable = True
url_custom_redirect_regex = (
    (r'^/api/stats/(?P<ext>.*)', r'/extdomains/https-s.youtube.com/api/stats/\g<ext>'),
    (r'^/user/api/stats(?P<ext>.*)', r'/extdomains/https-s.youtube.com/user/api/stats\g<ext>'),
)
shadow_url_redirect_regex = (
    (r'^/videoplayback(?P<ext>.*)', r'/extdomains/https-r8---sn-q4f7snss.googlevideo.com/videoplayback\g<ext>'),
    (r'^/videoplayback\?ewmytbserver=(?P<prefix>r\d+---sn-[a-z0-9]{8})&(?P<ext>.*?)',
     r'/extdomains/https-\g<prefix>.googlevideo.com/videoplayback?\g<ext>'),
)

text_like_mime_keywords = ('text', 'json', 'javascript', 'xml', 'x-www-form-urlencoded')
