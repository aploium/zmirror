# coding=utf-8
# 这是为Youtube(PC ONLY)镜像配置的示例配置文件
# Youtube手机站的配置文件是 config_youtube_mobile.py
#
# 请耐心看完注释
# 请耐心看完注释
# 请耐心看完注释
# 请耐心看完注释
# 请耐心看完注释
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 复制 custom_func_youtube.py 到zmirror根目录, 并重命名为 custom_func.py
#   3.*本步仅限本地部署需要  在本地hosts(如果不知道这是什么, 请自行google)中加入    127.0.0.1  www.localhost.com
#   4. 运行命令 python3 wsgi.py 来启动本程序
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# Youtube的功能非常复杂...而且有大量不常规的技术, 这个配置的镜像还有一些bug,
#   暂时只支持基础的看视频功能, 评论区很多时候无法正常加载. 可以登录
#   支持视频服务器与网页服务器分离, 请看 custom_func_youtube.py 中的第12行附近的注释
#
# ######### 重要 重要 重要 重要 重要 #########
# ######### 重要 重要 重要 重要 重要 #########
# ######### 重要 重要 重要 重要 重要 #########
# Youtube 镜像无法在`my_host_name`为 127.0.0.1 时运行, 并且在非ssl环境下, 可能会存在未知的bug
#   请自行修改host文件, 把域名 www.localhost.com 指向127.0.0.1
#
# Youtube 的PC端镜像和手机端必须分成两个域名或者同一域名两个不同端口, 分别建立独立的镜像才行.
#   并且如果网页与视频服务器分离, 两者不可共用同一套视频服务器域名
#       比如, PC镜像域名为 pc.my-youtube.com:81 PC镜像使用独立的视频服务器,域名为  pc-video1.lucia.net 和 pc-video2.lucia.net
#           而手机站域名为 mobile.my-youtube.com 或者 pc.my-youtube.com:82 使用独立的视频服务器, 域名为 mob-video1.lucia.net 和 mob-video2.lucia.net
#   总之, 虽然YoutubePC和YoutubeMobile的配置文件只相差一点点, 但是它们必须分别被架设为独立的镜像
#
# ######### 重要 重要 重要 重要 重要 #########
# ######### 重要 重要 重要 重要 重要 #########
# ######### 重要 重要 重要 重要 重要 #########

# ############## Local Domain Settings ##############
my_host_name = 'www.localhost.com'
my_host_scheme = 'http://'
my_host_port = None  # None表示使用默认端口, 可以设置成非标准端口, 比如 81

# ############## Target Domain Settings ##############
target_domain = 'www.youtube.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集会不断告诉你新域名
external_domains = [
    'm.youtube.com',

    's.youtube.com',
    'accounts.youtube.com',

    'apis.google.com',
    'plus.google.com',
    'accounts.google.com',
    'content.google.com',
    'apis.google.com',
    'ajax.googleapis.com',
    'www.googletagservices.com',
    'partner.googleadservices.com',
    'tpc.googlesyndication.com',
    'pagead2.googlesyndication.com',
    'video.google.com',
    'fonts.googleapis.com',
    'maps.googleapis.com',
    'maps.google.com',
    'maps-api-ssl.google.com',
    'support.google.com',
    'csi.gstatic.com',

    'redirector.googlevideo.com',
    'gg.google.com',

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
    'fonts.googleapis.com',

    'youtu.be',

    'daily-0.consent.corp.youtube.com',
    'daily-1.consent.corp.youtube.com',
    'daily-2.consent.corp.youtube.com',
    'daily-3.consent.corp.youtube.com',
    'daily-4.consent.corp.youtube.com',
    'daily-5.consent.corp.youtube.com',
    'daily-6.consent.corp.youtube.com',

    'consent-daily-0.sandbox.youtube.com',
    'consent-daily-1.sandbox.youtube.com',
    'consent-daily-2.sandbox.youtube.com',
    'consent-daily-3.sandbox.youtube.com',
    'consent-daily-4.sandbox.youtube.com',
    'consent-daily-5.sandbox.youtube.com',
    'consent-daily-6.sandbox.youtube.com',
    'consent-autopush.sandbox.youtube.com',
    'www.corp.google.com',
    'spreadsheets.google.com',
    'ytlegos-dashboard.corp.google.com',
]

force_https_domains = 'ALL'

enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = ['*.google.com', '*.google.com.hk', '*.gstatic.com',
                                        '*.googleusercontent.com', '*.youtube.com', '*.ytimg.com',
                                        '*.ggpht.com', '*.googleapis.com', '*.googlevideo.com',
                                        ]

force_decode_remote_using_encode = 'utf-8'

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

# ############## Misc ##############

custom_text_rewriter_enable = True

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
