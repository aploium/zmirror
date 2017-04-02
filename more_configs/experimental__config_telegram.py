# coding=utf-8
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# Telegram 本身不支持 HTTP，必须使用 HTTPS

# Github: https://github.com/aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = 'example.org'  # !!!本机的域名!!!! 必须修改!
my_host_scheme = 'https://'  # 本机的协议, 必须使用 "https://" ！
verbose_level = 2

# ############## Target Domain Settings ##############
target_domain = 'web.telegram.org'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = [
    "telegram.org"
]

TELEGRAM_API_SERVERS = [
    "venus-1.web.telegram.org",
    "flora-1.web.telegram.org",
    "pluto-1.web.telegram.org",
    "aurora-1.web.telegram.org",
    "vesta-1.web.telegram.org",
    "venus.web.telegram.org",
    "flora.web.telegram.org",
    "pluto.web.telegram.org",
    "aurora.web.telegram.org",
    "vesta.web.telegram.org",
    "t.me",
    "telegram.me",
]

# 在这里面的站点会被强制使用HTTPS, 暂不支持通配符
force_https_domains = [
]

# 自动动态添加域名
enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = (
    "*.web.telegram.org",
)

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

custom_text_rewriter_enable = True

# ############## Cron Tasks ##############
# v0.21.4+ Cron Tasks, if you really know what you are doing, please do not disable this option
# 定时任务, 除非你真的知道你在做什么, 否则请不要关闭本选项
enable_cron_tasks = True

cron_tasks_list = [
    # builtin cache flush, if you really know what you are doing, please do not remove these two tasks
    #   lower priority would be execute first
    # 对内置缓存的清理, 除非你真的知道你在做什么, 否则请不要移除这两个定时任务
    #   priority值越低, 运行顺序的优先级越高
    dict(name='cache_clean_soft', priority=42, interval=60 * 15, target='cache_clean'),
    dict(name='cache_clean_force_all', priority=42, interval=3600 * 24 * 7, target='cache_clean',
         kwargs={'is_force_flush': True}),
    # below is the complete syntax.
    # dict(name='just a name', priority=10, interval=60 * 10, target='your_own_cron_function', args=(1,2,), kwargs={'a':1}),
]

external_domains += TELEGRAM_API_SERVERS
if force_https_domains == "NONE":
    force_https_domains = TELEGRAM_API_SERVERS
elif isinstance(force_https_domains, (list, tuple)):
    force_https_domains = list(force_https_domains) + TELEGRAM_API_SERVERS

