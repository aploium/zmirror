# coding=utf-8
# 这是 www.economist.com (经济学人) 的配置文件
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
target_domain = 'www.economist.com'
target_scheme = 'http://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = (
    'horizon.economist.com',
    'media.economist.com',
    'stats.economist.com',
    'sstats.economist.com',
    'execed.economist.com',
    'shop.economist.com',
    'subscriptions.economist.com',
    'espresso.economist.com',
    'jobs.economist.com',
    'success.economist.com',
    'eydisrupters.films.economist.com',
    'films.economist.com',
    'gmat.economist.com',
    'gre.economist.com',
    'infographics.economist.com',
    'marketingsolutions.economist.com',
    'radio.economist.com',

    'cdn.static-economist.com',

    'accounts.google.com',
    'sadmin.brightcove.com',
    'uds.ak.o.brightcove.com',
    'worldif.economist.com',
    'link.brightcove.com',
    'admin.brightcove.com',
    'brightcove01.brightcove.com',
    'c.brightcove.com',
    'goku.brightcove.com',
    'metrics.brightcove.com',
    'players.brightcove.net',

    'ak.sail-horizon.com',
    'analytics.twitter.com',
    'api.adsymptotic.com',
    'api.lytics.io',
    'apis.google.com',
    'b.scorecardresearch.com',
    'sb.scorecardresearch.com',

    'clients1.google.com',

    'connect.facebook.net',

    'consent-st.truste.com',
    'consent.truste.com',
    'cs600.wac.alphacdn.net',

    'cse.google.com',

    'd21j20wsoewvjq.cloudfront.net',
    'd6tizftlrpuof.cloudfront.net',
    'dnn506yrbagrg.cloudfront.net',
    'dcdevtzxo4bb0.cloudfront.net',
    'debates.economist.com',

    'dc.ads.linkedin.com',

    'edge.quantserve.com',

    'dis.us.criteo.com',

    'fonts.gstatic.com',

    'global1.cmdolb.com',
    'global2.cmdolb.com',

    's.yimg.com',

    'mab.chartbeat.com',

    'i.po.st',
    'p.po.st',
    's.po.st',
    'po.st',

    'ib.adnxs.com',
    'secure.adnxs.com',

    'imp2.ads.linkedin.com',

    'js.bizographics.com',
    'mpp.mxptint.net',

    'partner.googleadservices.com',

    'pixel.fetchback.com',

    'pixel.quantserve.com',

    'platform.linkedin.com',

    'platform.twitter.com',

    'service.maxymiser.net',

    'snap.licdn.com',
    'ssl.gstatic.com',
    'stags.bluekai.com',
    'static.chartbeat.com',
    'static.criteo.net',

    'staticxx.facebook.com',
    'syndication.twitter.com',
    't.myvisualiq.net',
    'tags.bkrtx.com',
    'tags.bluekai.com',

    'tt.mbww.com',
    'w.usabilla.com',
    'webservices.sub2tech.com',

    'www.facebook.com',

    'www.linkedin.com',

    'media-llnw.licdn.com',

    'www.googletagservices.com',

    'tags.tiqcdn.com',
    'www.gstatic.com',

    'ping.chartbeat.net',

    's3.amazonaws.com',

    'secure.quantserve.com',

    'www.googleapis.com',

    'sp.analytics.yahoo.com',

    'stats.g.doubleclick.net',

    'sjs.bizographics.com',

    'netdna.bootstrapcdn.com',

    'bam.nr-data.net',

    "csi.gstatic.com",
)

# 'ALL' for all, 'NONE' for none(case sensitive), ('foo.com','bar.com','www.blah.com') for custom
force_https_domains = (
    'cse.google.com', 'connect.facebook.net', 'apis.google.com',
    'api.lytics.io', 'analytics.twitter.com', 'api.adsymptotic.com', 'accounts.google.com',
    'dc.ads.linkedin.com', 'fonts.gstatic.com', 'imp2.ads.linkedin.com', 'mpp.mxptint.net',
    'pixel.quantserve.com', 's.yimg.com', 'secure.adnxs.com', 'ssl.gstatic.com', 'stags.bluekai.com',
    'staticxx.facebook.com', 'www.facebook.com', 'www.linkedin.com', 'sstats.economist.com',
    's3.amazonaws.com'
)

enable_automatic_domains_whitelist = True
# 自动动态添加域名
# example:
# domains_whitelist_auto_add_glob_list = ('*.google.com', '*.gstatic.com', '*.google.com.hk')
domains_whitelist_auto_add_glob_list = (
    '*.brightcove.com', '*.static-economist.com', '*.cdnetworks.net', '*.alphacdn.net', '*.economist.com',
    '*.cedexis-radar.net',
    '*.chartbeat.com', '*.licdn.com',
    '*.bluekai.com', '*.gstatic.com', '*.cloudfront.net',
    '*.scorecardresearch.com', '*.tiqcdn.com', '*.doubleclick.net',
    '*.chartbeat.net', '*.quantserve.com', '*.bizographics.com',
)

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)
