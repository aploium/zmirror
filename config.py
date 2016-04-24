# coding=utf-8

# ############## Local Domain Settings ##############
# Your domain name, eg: 'blah.foobar.com'
my_host_name = 'g.zju.tools'
# Your domain's scheme, 'http://' or 'https://'
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
# Target main domain
#  Notice: ONLY the main domain and external domains are ALLOWED to cross this proxy
target_domain = 'www.google.com'
# Target domain's scheme, 'http://' or 'https://'
target_scheme = 'https://'
# domain also included in the proxy zone, mostly are the main domain's static file domains
external_domains = (
    'scholar.google.com',

    'ssl.gstatic.com',
    'www.gstatic.com',
    'apis.google.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'accounts.google.com',
    'accounts.youtube.com',
)
# 'ALL' for all, 'NONE' for none, ('foo.com','bar.com','www.blah.com') for custom
force_https_domains = 'ALL'

# ############## Proxy Settings ##############
# Global proxy option, True or False (case sensitive)
# Tip: If you want to make an GOOGLE mirror in China, you need an foreign proxy.
#        However, if you run this script in foreign server, which can access google directly, set it to False
is_use_proxy = True
# If is_use_proxy = False, the following setting would NOT have any effect
requests_proxies = dict(
    http="http://127.0.0.1:8123",
    https="https://127.0.0.1:8123",
)

# ############## Output Settings ##############
# Verbose level (0~3) 0:important and error 1:info 2:warning 3:debug. Default is 2
verbose_level = 2
