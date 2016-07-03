# coding=utf-8
# 这是为Google和中文维基(无缝整合)镜像配置的示例配置文件
#
# 使用方法:
#   复制本文件到 zmirror.py 同级目录, 并重命名为 config.py
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# 由于google搜索结果经常会出现中文维基, 所以顺便把它也加入了.
# google跟中文维基之间使用了本程序的镜像隔离功能, 可以保证中文维基站的正常使用
#
# 本配置文件试图还原出一个功能完整的google.
#   但是由于程序本身所限, 还是不能[完整]镜像过来整个[google站群]
#   在后续版本会不断增加可用的网站
#
# 以下google服务完全可用:
#   google网页搜索/学术/图片/新闻/图书/视频(搜索)/财经/APP搜索/翻译/网页快照/...
#   google搜索与中文维基百科无缝结合
# 以下服务部分可用:
#     gg地图(地图可看, 左边栏显示不正常)/G+(不能登录)
# 以下服务暂不可用(因为目前无法解决登录的问题):
#     所有需要登录的东西, docs之类的
#
# 不过, 因为试图反代整个google, 运算速度会慢一些
#   本文件同时也提供了一个轻量版的配置, 请把所有最后面带有 '# 需要轻量级Google镜像请注释掉本行'
#   轻量级配置文件中可用的google功能(完整可用, 没有瑕疵)为:
#       Google搜索/学术/图片搜索/视频搜索/与中文维基百科无缝结合
#   尽管是轻量级, 但是仍然是目前互联网上能找到的最好(功能/整合性/用户体验/访问速度)的Google镜像方案
#
# 速度对比, 在一台256M Ramnode OpenVZ VPS(Intel E3 3.3GHz)上处理Google首页(169.41KB), 测试5次取平均, 排除请求时间, 只测量运算时间
#   全功能: 0.167秒
#   轻量版: 0.045秒

# Github: https://github.com/Aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
target_domain = 'www.google.com.hk'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = (
    'www.google.com',
    'webcache.googleusercontent.com',  # Google网页快照
    'images.google.com.hk',
    'images.google.com',
    'apis.google.com',

    # Google学术
    'scholar.google.com.hk',
    'scholar.google.com',

    # 中文维基百科
    'zh.wikipedia.org',
    'zh.m.wikipedia.org',
    'upload.wikipedia.org',
    'meta.wikimedia.org',
    'login.wikimedia.org',

    # Google静态资源域名
    'ssl.gstatic.com',
    'www.gstatic.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'csi.gstatic.com',
    'fonts.googleapis.com',

    # Google登陆支持, 因为现在登陆还bug多多, 注释掉它们也没关系
    'accounts.google.com',
    'accounts.youtube.com',
    'accounts.google.com.hk',
    'myaccount.google.com',
    'myaccount.google.com.hk',

    # # 需要轻量级Google镜像请注释掉以下的一堆域名...它们会拖慢内容重写速度
    'translate.google.com',  # 需要轻量级Google镜像请注释掉本行
    'translate.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'video.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'books.google.com',  # 需要轻量级Google镜像请注释掉本行
    'cloud.google.com',  # 需要轻量级Google镜像请注释掉本行
    'analytics.google.com',  # 需要轻量级Google镜像请注释掉本行
    'security.google.com',  # 需要轻量级Google镜像请注释掉本行
    'investor.google.com',  # 需要轻量级Google镜像请注释掉本行
    'families.google.com',  # 需要轻量级Google镜像请注释掉本行
    'clients1.google.com',  # 需要轻量级Google镜像请注释掉本行
    'clients2.google.com',  # 需要轻量级Google镜像请注释掉本行
    'clients3.google.com',  # 需要轻量级Google镜像请注释掉本行
    'clients4.google.com',  # 需要轻量级Google镜像请注释掉本行
    'clients5.google.com',  # 需要轻量级Google镜像请注释掉本行
    'talkgadget.google.com',  # 需要轻量级Google镜像请注释掉本行
    'news.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'news.google.com',  # 需要轻量级Google镜像请注释掉本行
    'support.google.com',  # 需要轻量级Google镜像请注释掉本行
    'docs.google.com',  # 需要轻量级Google镜像请注释掉本行
    'books.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'chrome.google.com',  # 需要轻量级Google镜像请注释掉本行
    'profiles.google.com',  # 需要轻量级Google镜像请注释掉本行
    'feedburner.google.com',  # 需要轻量级Google镜像请注释掉本行
    'cse.google.com',  # 需要轻量级Google镜像请注释掉本行
    'sites.google.com',  # 需要轻量级Google镜像请注释掉本行
    'productforums.google.com',  # 需要轻量级Google镜像请注释掉本行
    'encrypted.google.com',  # 需要轻量级Google镜像请注释掉本行
    'm.google.com',  # 需要轻量级Google镜像请注释掉本行
    'research.google.com',  # 需要轻量级Google镜像请注释掉本行
    'maps.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'hangouts.google.com',  # 需要轻量级Google镜像请注释掉本行
    'developers.google.com',  # 需要轻量级Google镜像请注释掉本行
    'get.google.com',  # 需要轻量级Google镜像请注释掉本行
    'afp.google.com',  # 需要轻量级Google镜像请注释掉本行
    'groups.google.com',  # 需要轻量级Google镜像请注释掉本行
    'payments.google.com',  # 需要轻量级Google镜像请注释掉本行
    'photos.google.com',  # 需要轻量级Google镜像请注释掉本行
    'play.google.com',  # 需要轻量级Google镜像请注释掉本行
    'mail.google.com',  # 需要轻量级Google镜像请注释掉本行
    'code.google.com',  # 需要轻量级Google镜像请注释掉本行
    'tools.google.com',  # 需要轻量级Google镜像请注释掉本行
    'drive.google.com',  # 需要轻量级Google镜像请注释掉本行
    'script.google.com',  # 需要轻量级Google镜像请注释掉本行
    'goto.google.com',  # 需要轻量级Google镜像请注释掉本行
    'calendar.google.com',  # 需要轻量级Google镜像请注释掉本行
    'wallet.google.com',  # 需要轻量级Google镜像请注释掉本行
    'privacy.google.com',  # 需要轻量级Google镜像请注释掉本行
    'ipv4.google.com',  # 需要轻量级Google镜像请注释掉本行
    'video.google.com',  # 需要轻量级Google镜像请注释掉本行
    'store.google.com',  # 需要轻量级Google镜像请注释掉本行
    'fi.google.com',  # 需要轻量级Google镜像请注释掉本行
    'apps.google.com',  # 需要轻量级Google镜像请注释掉本行
    'events.google.com',  # 需要轻量级Google镜像请注释掉本行
    'notifications.google.com',  # 需要轻量级Google镜像请注释掉本行
    'plus.google.com',  # 需要轻量级Google镜像请注释掉本行

    'scholar.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'translate.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    't0.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    't1.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    't2.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    't3.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    's-v6exp1-ds.metric.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    'ci4.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'gp3.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行

    # For Google Map (optional)
    'maps-api-ssl.google.com',  # 需要轻量级Google镜像请注释掉本行
    'maps.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    'maps.google.com',  # 需要轻量级Google镜像请注释掉本行
    'fonts.gstatic.com',  # 需要轻量级Google镜像请注释掉本行
    'lh1.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'lh2.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'lh3.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'lh4.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'lh5.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行
    'lh6.googleusercontent.com',  # 需要轻量级Google镜像请注释掉本行

    # 'upload.wikimedia.org',
    'id.google.com.hk',  # 需要轻量级Google镜像请注释掉本行
    'id.google.com',  # 需要轻量级Google镜像请注释掉本行
)

force_https_domains = 'ALL'

# 需要轻量级Google的请一定要注释掉下面这两行, 否则会动态添加大量的域名, 导致很快就变慢(支持的Google服务也变多)
enable_automatic_domains_whitelist = True  # 需要轻量级Google镜像请注释掉本行
domains_whitelist_auto_add_glob_list = ('*.google.com', '*.gstatic.com', '*.google.com.hk')  # 需要轻量级Google镜像请注释掉本行

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

# ############## Sites Isolation ##############
enable_individual_sites_isolation = True

# 镜像隔离, 用于支持Google和维基共存
isolated_domains = {'zh.wikipedia.org', 'zh.m.wikipedia.org'}

# ############## URL Custom Redirect ##############
# 这是一个方便的设置, 如果你访问 /wiki ,程序会自动重定向到后面这个长长的wiki首页
url_custom_redirect_enable = True
url_custom_redirect_list = {'/wiki': '/extdomains/https-zh.wikipedia.org/'}
