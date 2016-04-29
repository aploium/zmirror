# coding=utf-8
# This is the sample config, please copy or rename it to 'config.py'
# DO NOT delete or commit following settings

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
verbose_level = 3
# Is print an extra log copy to file (stdout will remain the same)
# is_log_to_file = True
# log_file_path = r'c:\google_mirror.log'

# ############## Cache Settings ##############
# Global option
cache_enable = True

# ############## Custom Text Filter Functions ##############
# Global option
custom_text_rewriter_enable = False

# ############## CDN Settings ##############
# If you have an CDN service (like qiniu,cloudflare,etc..), you are able to storge static resource in CDN domains.
# HowTo:
#   Please config your CDN service's "source site" or "源站"(chinese) to your domain (same as the front my_host_name)
# And then add the CDN domain in the follow. Currently we only support ONE CDN domain.

# Global option
enable_static_resource_CDN = True
# Your CDN domain, such as 'cdn.example.com', domain only, do not add slash(/), do not add scheme (http://)
# the scheme would be the same as `my_host_scheme` front
CDN_domain = 'cdn.zju.tools'


