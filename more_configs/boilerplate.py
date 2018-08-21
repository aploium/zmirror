# coding=utf-8
# 这是为一个*空白*配置文件, 可以作为自己创建其他镜像的基础
# 其中包含了一些最常见的静态资源站, 可以减少开发难度
# 在性能上, 由于zmirror的机制, 可以添加任意多的.com和.net域名而不影响性能. 添加其他后缀的域名也只有第一个会影响性能
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# boilerplate version: 1.0.0

# Github: https://github.com/aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'  # !!!本机的域名!!!! 必须修改!
my_host_scheme = 'http://'  # 本机的协议, 可选为 "http://" 和 "https://"

# ############## Target Domain Settings ##############
target_domain = 'example.com'  # !!!!你的目标域名!!!!
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = [
    "www.example.com",
    "www.example1.com",
    "www.example2.com",
]

# 这些是一些公共的静态资源域名, 会被自动添加到你上面的 external_domains 中
BOILERPLATE_EXTERNAL_DOMAINS = [

    # Google域名
    'www.google.com',
    'ssl.gstatic.com',
    'accounts.google.com',
    'apis.google.com',
    'www.gstatic.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'csi.gstatic.com',
    'www.googleapis.com',
    'fonts.googleapis.com',
    'ajax.googleapis.com',
    'manifest.googlevideo.com',
    'storage.googleapis.com',
    't0.gstatic.com',
    't1.gstatic.com',
    't2.gstatic.com',
    't3.gstatic.com',
    's-v6exp1-ds.metric.gstatic.com',
    'ci4.googleusercontent.com',
    'gp3.googleusercontent.com',
    'accounts.gstatic.com',
    # For Google Map (optional)
    'maps-api-ssl.google.com',
    'maps.gstatic.com',
    'maps.google.com',
    'fonts.gstatic.com',
    'lh1.googleusercontent.com',
    'lh2.googleusercontent.com',
    'lh3.googleusercontent.com',
    'lh4.googleusercontent.com',
    'lh5.googleusercontent.com',
    'lh6.googleusercontent.com',
    '-v6exp3-v4.metric.gstatic.com',
    '-v6exp3-ds.metric.gstatic.com',
    'if-v6exp3-v4.metric.gstatic.com',
    'maps.googleapis.com',
    'myphonenumbers-pa.googleapis.com',
    'plus.googleapis.com',
    'youtube.googleapis.com',
    "www-onepick-opensocial.googleusercontent.com",

    # youtube, 尽管不能看视频, 但是一些静态资源会从中加载
    "www.youtube.com",
    'accounts.youtube.com',
    "s.ytimg.com",
    'i.ytimg.com',
    'i1.ytimg.com',
    'yt3.ggpht.com',

    # facebook, 同youtube
    "facebook.com",
    "ssl.facebook.com",
    "staticxx.facebook.com",
    "api.facebook.com",
    "secure.facebook.com",
    "zh-cn.facebook.com",

    # twitter静态域名
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

    # cdnjs
    "cdnjs.cloudflare.com",
    # 微软的奇怪cdn
    "ajax.aspnetcdn.com",
    # js deliver cdn
    "cdn.jsdelivr.net",
    # jquery cdn
    "code.jquery.com",
    # boostrap-maxcdn
    "maxcdn.bootstrapcdn.com",
]

# 在这里面的站点会被强制使用HTTPS, 暂不支持通配符
force_https_domains = [
    # "example.com",
    # "example.org",
]

# 自动动态添加域名
enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = (
    # 将你的域名通配符填写到这, 比如下面这样:
    "*.example.com",
    # "*.example.org",
)

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

# ### 其他高级配置请看 config_default.py 中的详细说明


# ------------ 以下部分为一些简单的逻辑, 请不要修改下面的代码 ----------------
external_domains += BOILERPLATE_EXTERNAL_DOMAINS  # 将公共静态资源域名加入到external_domains中
# 将公共静态资源域名设置为强制HTTPS
if force_https_domains == "NONE":
    force_https_domains = BOILERPLATE_EXTERNAL_DOMAINS
elif isinstance(force_https_domains, (list, tuple)):
    force_https_domains = list(force_https_domains) + BOILERPLATE_EXTERNAL_DOMAINS
