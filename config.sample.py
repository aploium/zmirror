# coding=utf-8
# This is the sample config, please copy or rename it to 'config.py'
# DO NOT delete or commit following settings

# Github: https://github.com/Aploium/EasyWebsiteMirror

# ############## Explain to the default config ##############
#     The default config is an site mirror to `example.com` along with `www.iana.org`
# you can just rename or copy this file to 'config.py' and then execute `python3 EasyWebsiteMirror.py`,
# it will start an localhost web server.
#     Then, enter http://localhost/ you will actually access to the example.com.
#     More, you can click the "More information..." link in that page,
# which would bring you to http://localhost/extdomains/www.iana.org/  it's the auto url rewrite.
#     You don't need to write any code, or do any complex settings. Just change the settings of this page!
#
#     There is another config example of www.google.com for you, in the bottom of this file.
#
# Let Magic Happens !!

# ############## Local Domain Settings ##############
# Your domain name, eg: 'blah.foobar.com'
my_host_name = 'localhost'
# Your domain's scheme, 'http://' or 'https://', it affects the user.
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
# Target main domain
#  Notice: ONLY the main domain and external domains are ALLOWED to cross this proxy
target_domain = 'example.com'
# Target domain's scheme, 'http://' or 'https://', it affects the server only.
target_scheme = 'http://'
# domain(s) also included in the proxy zone, mostly are the main domain's static file domains or sub domains
#     tips: you can find a website's external domains by using the developer tools of your browser,
# it will log all network traffics for you
external_domains = (
    'www.example.com',
    'www.iana.org',
    'iana.org',
)
# 'ALL' for all, 'NONE' for none(case sensitive), ('foo.com','bar.com','www.blah.com') for custom
force_https_domains = 'NONE'

# ############## Proxy Settings ##############
# Global proxy option, True or False (case sensitive)
# Tip: If you want to make an GOOGLE mirror in China, you need an foreign proxy.
#        However, if you run this script in foreign server, which can access google directly, set it to False
is_use_proxy = False

# If is_use_proxy = False, the following setting would NOT have any effect
# DO NOT support socks4/5 proxy. If you want to use socks proxy, please use Privoxy to convert them to http(s) proxy.
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)

# ############## Output Settings ##############
# Verbose level (0~3) 0:important and error 1:info 2:warning 3:debug. Default is 3 (for first time runner)
verbose_level = 3

# ############## Cache Settings ##############
# Cache remote static files to your local storge. And access them directly from local storge if necessary.
# an 304 response support is implanted inside
local_cache_enable = True

# ############## Custom Text Rewriter Function ##############
# Please see https://github.com/Aploium/EasyWebsiteMirror#custom-rewriter-advanced-function for more information
custom_text_rewriter_enable = False

# ############## CDN Settings ##############
# If you have an CDN service (like qiniu,cloudflare,etc..), you are able to storge static resource in CDN domains.
# CDN will dramatically increase your clients' access speed if you have many of them
# HowTo:
#   Please config your CDN service's "source site" or "源站"(chinese) to your domain (same as the front my_host_name)
# And then add the CDN domain in the follow.
# Please see https://github.com/Aploium/EasyWebsiteMirror#cdn-support for more information
enable_static_resource_CDN = False
# Only file's extension(from it's url suffix), in this list, will it be cached in CDN
static_file_extensions_list = [
    'gif', 'jpeg', 'jpg', 'jpeg', 'png', 'ico', 'bmp', 'tif', 'webp',  # images
    'woff', 'woff2',  # web font
    'mp3', 'wmv', 'wav',  # sounds
    'js', 'css',  # static
]

# Your CDN domains, such as 'cdn.example.com', domain only, do not add slash(/), do not add scheme (http://)
#     If your CDN storge your file permanently (like qiniu), you can disable local cache to save space,
# but if your CDN is temporarily storge (like cloudflare), please keep local cache enabled.
#
# example: ('cdn1.example.com','cdn2.example.com','cdn3.example.com')
CDN_domains = ('cdn1.example.com', 'cdn2.example.com', 'cdn3.example.com')

# ############## Search Engine Deny ##############
# If turns to True, will send an 403 if user-agent contains 'spider' or 'bot'
# And, don't worry, no browser's user-agent contains these two words.
# default: False
is_deny_spiders_by_403 = False

# However, if spider's ua contains one of these strings, it will be allowed
# Because some CDN provider's resource fetcher's UA contains spider string. You can let them access
# the example 'qiniu' is the cdn fetcher of qiniu(七牛, China)
# Tips: How to find out your CDN provider's UA if it was denied.
#     Set the verbose_level to 3, let the bot access(and denied), then see the log file(or stdout),
# you will find string like:   "A Spider/Bot was denied, UA is: qiniu-imgstg-spider-1.0"
# choose key word(s) from it and add it(them) to the white list.
# default: ('qiniu', 'cdn')
spider_ua_white_list = ('qiniu', 'cdn')

# ############## Sample Config For Google Mirror ##############
# Please remove the following commit if you want to use google mirror
# and then don't forget to set up the proxy if your machine is within the China mainland (GFW Zone)

# target_domain = 'www.google.com'
# target_scheme = 'https://'
# external_domains = (
#     'scholar.google.com',
#
#     'ssl.gstatic.com',
#     'www.gstatic.com',
#     'apis.google.com',
#     'encrypted-tbn0.gstatic.com',
#     'encrypted-tbn1.gstatic.com',
#     'encrypted-tbn2.gstatic.com',
#     'encrypted-tbn3.gstatic.com',
#     'accounts.google.com',
#     'accounts.youtube.com',
# )
# force_https_domains = 'ALL'
