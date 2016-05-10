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

# #####################################################
# ################## BASIC Settings ###################
# #####################################################

# ############## Global Settings ##############
# If client's ua CONTAINS this, it's access will be granted.Only one value allowed.
# this white name also affects any other client filter (Human/IP verification, etc..)
# Please don't use this if you don't use filters.
global_ua_white_name = 'qiniu-imgstg-spider'

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

# #####################################################
# ################# ADVANCED Settings #################
# #####################################################

# ############## Output Settings ##############
# Verbose level (0~3) 0:important and error 1:info 2:warning 3:debug. Default is 3 (for first time runner)
verbose_level = 3

# ############## Cache Settings ##############
# Cache remote static files to your local storge. And access them directly from local storge if necessary.
# an 304 response support is implanted inside
# Notice: It was relied by `cdn_redirect_encode_query_str_into_url`
local_cache_enable = True

# ############## CDN Settings ##############
# If you have an CDN service (like qiniu,cloudflare,etc..), you are able to storge static resource in CDN domains.
# CDN will dramatically increase your clients' access speed if you have many of them
# Post would never be cached
# HowTo:
#   Please config your CDN service's "source site" or "源站"(chinese) to your domain (same as the front my_host_name)
# And then add the CDN domain in the follow.
# Please see https://github.com/Aploium/EasyWebsiteMirror#cdn-support for more information
enable_static_resource_CDN = False

# v0.14.0+ Now, instead of simply distinguish static resource using their url extension name,
#    we can use MIME, which is more accurate and won't miss some modern ones without extension.
# The MIME-based CDN rewrite only works when you request an resource for the second time,
#    Disadvantage: it will reduce (just a little) the first two user's experience
#                  and increase memory consume for about several MB
#    Advantage: avoid caching some one-time-use resource
# v0.14.0+ 之前仅根据资源的后缀名来进行CDN重写, 现在可以根据首次实际请求后资源返回的MIME来进行,
#     好处是可以避免漏掉一些现代化的、没有后缀名的资源
# 不过硬URL重写只能在第二次请求这个资源的时候生效
#    坏处: 轻微地减少前两个用户的访问速度(基本可以忽略), 并且增加内存消耗(大概几个到十几个MB)
#    好处: 避免缓存了一些一次性的资源
#
# Dependency 依赖: enable_static_resource_CDN == True
mime_based_static_resource_CDN = True

# v0.14.0+ Soft CDN Redirect 软CDN重定向
# Normally, we are trying to rewrite the URL in document(html/css/js) hard-code,
# However, some times we cannot rewrite CDN resource in document itself(or it's generated dynamically)
# Don't worry, we can return an redirect order to our client.
# Valid values(number) are 0 301 302 307 , 0 for disable redirect, serve these resources by our own
#     301 (recommended) means permanently redirect. 302 are equal to 307 means temporary redirect
#     If use 301, client will skip us and directly turn to the CDN if it need this resource again
#     302 or 307 means client will ask us again if it need this resource again
# Only GET request would be redirected to CDN
# To avoid redirection loop, browsers with CDN fetcher's User-Agent would never be redirected
#     particle match is OK. No regex, plain text match only.
#     for this reason, #### PLEASE ONLY ENABLE THIS AFTER YOU SET YOUR CDN FETCHER'S USER-AGENT ####
#     please figure it out and write it(them) to the setting `spider_ua_white_list` or `global_ua_white_name`
#     how I know? please refer to the commit of option `spider_ua_white_list` below
#     If client's ua CONTAINS any one string in global_ua_white_name or spider_ua_white_list, it will not be redirected.
#     tips: many identity strings won't cause performance loss, we have implanted cache
# 通常情况下, 程序会尝试直接在文本(html/css/js)中重写静态资源链接,
# 但是这并不总对所有资源生效, 有时候并不能直接在文本中改写静态资源到CDN上，比如说是动态组装的url，
# 这时候我们可以通过返回重定向信息给浏览器，软性重定向到CDN
# 仅有GET请求会被重定向到CDN
# 允许的值(数字)为 0 301 302 307
#     0 表示关闭, 不软性重定向到CDN
#     301 (推荐)表示永久性重定向, 在接下来很长一段时间内, 下次浏览器需要此资源时会跳过我们，直接请求CDN
#     302 和 307 表示临时重定向，重定向仅此次生效, 下次需要时仍然会向我们请求
# 为了避免重定向循环, User-Agent带有CDN特征字符的请求不会被重定向，只需要部分匹配即可
# ### 请务必先弄清楚你的CDN提供商的机器人的UA, 确保放行它们后再启用本选项 ###
#     请找出能标示它的UA特征串, 并填写在 spider_ua_white_list 或 global_ua_white_name 中
#     关于如何找出CDN提供商机器人的UA,请看下面选项 spider_ua_white_list 的注释
#     如果UA字符串[包含] global_ua_white_name 或 spider_ua_white_list 中的任意一个字符串, 它将被放行
#     即使填入多个特征串也不会造成性能损失(有内置缓存)
#
# Dependency 依赖:
#     enable_static_resource_CDN == True
#     mime_based_static_resource_CDN == True
cdn_redirect_code_if_cannot_hard_rewrite = 0

# v0.14.1+
# When use soft redirect, whether encode(gzip + base64) query string into url path.
#     recommended to enable, this can increase some CDN compatibility.
#     and will add an extra extension to it.
#     has no effect to legacy rewrite
#     will use the following `mime_to_use_cdn` 's settings to convert MIME to extension
#     Only when request's UA contains CDN fetcher's string, will program try to resolve encoded query string from it.
# Why Base64, not CRC32?
#     If use CRC32, we must keep an CRC32-raw value map table, no matter in mem or disk.
#         If our server was down unexpectedly, we would loss the entire, or at least part of the map.
#         which let the server can't resolve the request's really query string.
#         more, because the map, we couldn't use multi server to do load balance (unless write complex sync program)
#     However,if we encoded the query string into the url itself, no local map is required.
#         Even if the server suffers the worse disaster, we won't loss the raw request params.
#         Because the 301, browsers will always request the transformed url.
#         More, we could switch the server swiftly, or use multi server to do load balance easily.
#         PS: NEEDN'T to storge doesn't means we won't, we would still do some cache storge for performance.
#         And don't worry the url would be too long, because we use base64, if we got an long long request string,
#         it would be shorten after gzip and base64.
#     Secure problems: Using base64 may give away the query string, leads to security problems.
#         I would add AES to in the later version.
#
# 将url中请求参数的部分gzip压缩+base64编码进url路径中, 并添加对应的扩展名, 这样能增加对某些(实际上是大部分)对参数支持不好的CDN的兼容性
# 将根据下面的 `mime_to_use_cdn` 选项中的设置来进行MIME到扩展名的转换
# 仅当请求者的UA中包含CDN的特征串时，程序才会试图从中解析编码的查询参数
# 推荐开启(默认开启), 对传统CDN重写没有影响
# 为什么用Base64将参数编入, 而不是用CRC32:
#     尽管用CRC32比用Base64要短很多(性能也有优势), 但是如果用CRC32, 意味着我们必须在本地保留一个CRC32到原参数的映射表,
#         当服务器意外崩溃时(或手工重启), 我们将会丢失全部或一部分映射(除非每建立一个映射就写一次磁盘, 但是那样太慢了)
#         丢失一部分映射意味着我们会无法解析客户端的某些请求, 可能会极大地影响用户体验.
#         而且如果使用了CRC32来记录, 我们就无法使用多台镜像服务器来进行负载均衡, (除非写复杂的同步机制)
#             尽管至少目前来看程序性能还可以, 一台服务器足以支撑, 但是一个好的程序必须有很好的可伸缩性和弹性.
#     如果使用base64, 尽管url会变得很长, 但是我们可以随时从url中读取原始请求参数, 不需要在本地维持一个映射表,
#         这样,当服务器意外崩溃或者人为重启后, 我们仍然能解析用户(CDN)的请求.
#         多台镜像服务器的负载均衡也可以在不写任何同步机制的情况下被简单地部署.
#         也不用担心base64后的url会变得太长而出错, 对于过长的查询参数(暂定128字符以上),
#             在base64之前会用gzip压缩, 总的长度会比原来的更短, 被gzip的参数在url中会多一个 z 标记
#
# Dependency 依赖:
#     enable_static_resource_CDN == True
#     mime_based_static_resource_CDN == True
#     cdn_redirect_code_if_cannot_hard_rewrite != 0
#
# eg: https://foo.com/a.php?q=something (assume it returns an css) (base64 only)
#     ---> https://cdn.domain.com/a.php_ewm0_.cT1zb21ldGhpbmc=._ewm1_.css
# eg2: https://foo.com/a/b/?love=live (assume it returns an jpg) (base64 only)
#     ---> https://cdn.domain.com/a/b/_ewm0_.bG92ZT1saXZl._ewm1_.jpg
# eg3: https://foo.com/a/b/?love=live[and a long long query string] (assume it returns an jpg) (gzip + base64)
#     ---> https://cdn.domain.com/a/b/_ewm0z_.[some long long base64 encoded string]._ewm1_.jpg
# eg4:(no query string): https://foo.com/a (assume it returns an png) (no change)
#     ---> https://cdn.domain.com/a  (no change)
cdn_redirect_encode_query_str_into_url = True

# v0.14.0 first add; v0.14.1 change format
# format: 'MIME':'extension'
# the extension affects the former `cdn_redirect_encode_query_str_into_url` option
mime_to_use_cdn = {
    'application/javascript': 'js', 'application/x-javascript': 'js', 'text/javascript': 'js',  # javascript
    'text/css': 'css',  # css
    # img
    'image/gif': 'gif', 'image/jpg': 'jpg', 'image/jpeg': 'jpg', 'image/png': 'png',
    'image/svg+xml': 'svg', 'image/webp': 'webp',
    # Fonts
    'application/vnd.ms-fontobject': 'eot', 'font/eot': 'eot', 'font/opentype': 'woff',
    'application/x-font-ttf': 'woff',
    'application/font-woff': 'woff', 'application/x-font-woff': 'woff', 'font/woff': 'woff',
    'application/font-woff2': 'woff2',
    # CDN the following large files MAY be not a good idea, you choose
    # 'image/bmp': 'bmp', 'video/mp4': 'mp4', 'video/ogg': 'ogg', 'video/webm': 'webm',
    # icon files MAY change frequently, you choose
    # 'image/vnd.microsoft.icon': 'ico', 'image/x-icon': 'ico',
}

# v0.14.0+ By disabling legacy extension based file recognize method, we could gain some performance advantage
#     More, I'm no longer maintaining the codes of legacy cdn, it may have bugs
# v0.14.0+ 由于有了基于MIME的CDN重写，可以关闭传统的后缀名重写，能提高一些性能
#     并且我也不再维护传统CDN, 如果继续使用它, 可能会有潜在的bug
disable_legacy_file_recognize_method = True

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

# ############## Human/IP verification ##############
# We could disallow untrusted IP's access by asking users some questions which only your people knew the answer
# Of course, this can also deny Chinese GFW's access
# If an user passed this verification, then his/her IP would be added to whitelist
# You can also acquire some identity information from users.
human_ip_verification_enabled = False

# can be html
human_ip_verification_description = r"""本站仅允许浙江大学师生访问.如果您也来自浙江大学, 请您回答以下问题
This site ONLY allow people from Zhejiang University to access, please answer the following question(s).
"""

human_ip_verification_default_whitelist_networks = (
    '127.0.0.1',  # localhost

    '183.157.0.0/16',  # Zhejiang University

    # Zhejiang China Mobile
    # '211.140.0.0/16',
    # '218.205.0.0/16',
    # '211.138.112.0/19',
    # '112.17.230.0/19',

)

human_ip_verification_title = '本网站只有内部人员才可以访问 | This site was only available for our members'
human_ip_verification_success_msg = 'Verify Success! \n You will not be asked this again in 30 days'

# Please make sure you have write permission.
human_ip_verification_whitelist_file_path = 'ip_whitelist.txt'
human_ip_verification_whitelist_log = 'ip_whitelist.log'

# salt, please CHANGE it
human_ip_verification_answers_hash_str = 'AploiumLoveLuciazForever'

# questions and answer that users from non-permitted ip should answer. Can have several questions
human_ip_verification_questions = (
    ('Please write your question here', 'CorrectAnswer'),
    # ('Another question', 'AnotherAnswer'),
    # ('最好是一些只有内部人员才知道答案的问题, 比如说 "英译中:zdlgmygdwg"', '[略]'),
    # ('能被轻易百度到答案的问题是很不好的,比如:浙江大学的校长是谁', '竺可桢'),
)

# user's identity information that should given. Would be logged in to log file.
human_ip_verification_identity_record = (
    # question_description,                 question_internal_name,  form_input_type)
    ("Please input your student/teacher ID number", "student_id", "text"),
    ("Please input your student/teacher password", "password", "password"),
    # ("请输入您的学号或工号", "student_id"),
)

# If set to True, will use the custom_identity_verify() function to verify user's input identity.
# And dict will be passed to that function
# ### IT IS AN EXPERT SETTING THAT YOU HAVE TO WRITE SOME YOUR OWN PYTHON CODES ###
identity_verify_required = False

# If sets to True, would add an cookie to verified user, automatically whitelist them even if they have different ip
human_ip_verification_whitelist_from_cookies = True
human_ip_verification_whitelist_cookies_expires_days = 30

# If set to True, an valid cookie is required, IP white list would be ignored.
# If set to False, identity will not be verified but just logged to file
must_verify_cookies = False

# ############## Custom Text Rewriter Function ##############
# Please see https://github.com/Aploium/EasyWebsiteMirror#custom-rewriter-advanced-function for more information
# ### IT IS AN EXPERT SETTING THAT YOU HAVE TO WRITE SOME YOUR OWN PYTHON CODES ###
custom_text_rewriter_enable = False

# ############## Custom URL Redirect ##############
# If enabled, server will use an 302 to redirect from the source to the target
#
# 1.It's quite useful when some url's that normal rewrite can't handle perfectly.
#   (script may not rewrite all urls perfectly when you tries to put several individual sites to one mirror,
#      eg: if you put google and wikipedia together, you can't search in wikipedia, this can fix)
#
# 2.It can also do url shorten jobs, but because it only rewrite url PATH, you cannot change the url's domain.
#     eg1: http://foo.com/wiki  --->  http://foo.com/extdomains/zh.wikipedia.org/
#     eg2: http://foo.com/scholar  --->  http://foo.com/extdomains/https-scholar.google.com/
url_custom_redirect_enable = False

# Only applies to url PATH, other parts remains untouched
# It's an plain text list. Less function but higher performance, have higher priority than regex rules
# eg: "http://foo.com/im/path.php?q=a#mark" , in this url, "/im/path.php" this is PATH
url_custom_redirect_list = {
    # This example is to fix search bugs(in wiki) when you put google together with zh.wikipedia.org in one mirror.
    '/w/load.php': '/extdomains/https-zh.wikipedia.org/w/load.php',
    '/w/index.php': '/extdomains/https-zh.wikipedia.org/w/index.php',
    '/w/api.php': '/extdomains/https-zh.wikipedia.org/w/api.php',

    # This example acts as an tinyurl program
    '/wiki': '/extdomains/https-zh.wikipedia.org/',
}

# If you want more complicated regex redirect, please add then in this dict.
# If url FULLY MATCH the first regex, the second regex for re.sub  will be applied
# Same as above, only the url PATH will be applied (maybe change in later version)
# Please see https://docs.python.org/3.5/library/re.html#re.sub for more rules
url_custom_redirect_regex = (
    # This example fix mobile wikipedia's search bug
    # will redirect /wiki/Some_wiki_page to /extdomains/https-zh.m.wikipedia.org/wiki/Some_wiki_page
    (r'^/wiki/(?P<name>.*)$', '/extdomains/https-zh.m.wikipedia.org/wiki/\g<name>'),
    # (r'^/wiki/(?P<name>.*)', '/extdomains/https-zh.m.wikipedia.org//wiki/\g<name>'),
)

# #####################################################
# ###################### SAMPLE #######################
# #####################################################

# ############## Sample Config For Google Mirror ##############
# Please remove the following commit if you want to use google mirror
# and then don't forget to set up the proxy if your machine is within the China mainland (GFW Zone)

# target_domain = 'www.google.com.hk'
# target_scheme = 'https://'
# external_domains = (
#     'scholar.google.com',
#     'scholar.google.com.hk',
#
#     'www.google.com',
#     'ssl.gstatic.com',
#     'www.gstatic.com',
#     'apis.google.com',
#     'encrypted-tbn0.gstatic.com',
#     'encrypted-tbn1.gstatic.com',
#     'encrypted-tbn2.gstatic.com',
#     'encrypted-tbn3.gstatic.com',
#     'accounts.google.com',
#     'accounts.youtube.com',
#
#     'books.google.com',
#
#     # For Google Map (Optional)
#     'maps.google.com',
#     'fonts.gstatic.com',
#     'maps.gstatic.com',
#     'lh1.googleusercontent.com',
#     'lh2.googleusercontent.com',
#     'lh3.googleusercontent.com',
#     'lh4.googleusercontent.com',
#     'lh5.googleusercontent.com',
#
#     # For zh wikipedia (Optional)
#     'zh.wikipedia.org',
#     'zh.m.wikipedia.org',
#     'upload.wikipedia.org',
#     'meta.wikimedia.org',
#     'login.wikimedia.org',
# )
# force_https_domains = 'ALL'
# is_deny_spiders_by_403 = True
#
# human_ip_verification_enabled = True  # Optional, if set to True, you should modify other settings of that section
