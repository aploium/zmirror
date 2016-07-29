# coding=utf-8
# This is the sample config, please copy it to 'config.py'
# DO NOT delete or commit following settings

# Github: https://github.com/Aploium/zmirror

# ############## Explain to the default config ##############
# The default config is an site mirror to `www.kernel.org` along with `*.kernel.org`
#   you can just copy this file to 'config.py' and then execute `python3 wsgi.py`,
#   it will start an localhost web server.
# Then, enter http://127.0.0.1/ you will actually access to the www.kernel.org  (the linux kernel website)
#   More, you can click and browse around. everything is within the mirror.
# For most sites, you don't need to write any code, or do any complex settings. Just change the settings of this page!
#
# 默认配置文件是对 www.kernel.org (linux内核的网站)及其所有子站的镜像.
#   请复制一份本文件为 'config.py' 然后运行 `python3 wsgi.py`
#   然后访问 http://127.0.0.1 , 你将看到的是 www.kernel.org 的首页
#   www.kernel.org 和它的所有子站都被自动地加入到了这个反向代理镜像中.
#   你可以在网站中随意点击, 随意浏览, 而不会跑到镜像外. (*.kernel.org以外的网站仍然会跑到外面, 因为把它们没有加入镜像)
#
# There are config samples for www.google.com+zh.wikipedia.org/twitter/youtube, please see the 'more_configs'
# 在 'more_configs' 文件夹下还有适用于Google(含中文维基)/twitter(功能完整)/youtube的配置文件

# #####################################################
# ################## BASIC Settings ###################
# #####################################################

# ############## Local Domain Settings ##############
# Your domain name, eg: 'blah.foobar.com'
my_host_name = '127.0.0.1'

# v0.18.2+
# Your port, if use the default value(80 for http, 443 for https), please set it to None
#   otherwise please set your port (number)
#   an non-standard port MAY prevent the gfw's observe, but MAY also cause compatibility problems
my_host_port = None

# Your domain's scheme, 'http://' or 'https://', it affects the user.
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
# Target main domain
#  Notice: ONLY the main domain and external domains are ALLOWED to cross this proxy
target_domain = 'www.kernel.org'

# Target domain's scheme, 'http://' or 'https://', it affects the server only.
target_scheme = 'https://'

# domain(s) also included in the proxy zone, mostly are the main domain's static file domains or sub domains
#     tips: you can find a website's external domains by using the developer tools of your browser,
# it will log all network traffics for you
external_domains = (
    # actually, the kernel.org has many sub-domains, but we just add one of them for example
    # the following `Automatic Domains Whitelist` would detect and add the others automatically
    #
    # 实际上, kernel.org 有大量的子域名, 但是我们在这里并不把它们全部添加进来, 而只是添加一个作为示例
    # 下面的 `Automatic Domains Whitelist` 功能会自动检测并添加其他的子域名
    'g.kernel.org',
)

# 'ALL' for all, 'NONE' for none(case sensitive), ('foo.com','bar.com','www.blah.com') for custom
force_https_domains = 'NONE'

# v0.19.0+ Automatic Domains Whitelist (Experimental)
# by given wild match domains (glob syntax, '*.example.com'), if we got domains match these cases,
#   it would be automatically added to the `external_domains`
# However, before you restart your server, you should check the 'automatic_domains_whitelist.log' file,
#   and manually add domains to the config, or it would not work after you restart your server
# You CANNOT relay on the automatic whitelist, because the basic (but important) rewrite require specified domains to work.
# For More Supported Pattern Please See: https://docs.python.org/3/library/fnmatch.html#module-fnmatch
# 如果给定以通配符形式的域名, 当程序遇到匹配的域名时, 将会自动加入到 `external_domains` 的列表中
# 但是, 当你重启服务器程序前, 请检查程序目录下 'automatic_domains_whitelist.log' 文件,
#   并将里面的域名手动添加到 `external_domains` 的列表中 (因为程序不会在运行时修改本配置文件)
# 自动域名添加白名单功能并不能取代 `external_domains` 中一个个指定的域名,
#   因为基础重写(很重要)不支持使用通配符(否则会带来10倍以上的性能下降).
# 如果需要使用 * 以外的通配符, 请查看 https://docs.python.org/3/library/fnmatch.html#module-fnmatch 这里的的说明
enable_automatic_domains_whitelist = True
# example:
# domains_whitelist_auto_add_glob_list = ('*.google.com', '*.gstatic.com', '*.google.com.hk')
domains_whitelist_auto_add_glob_list = ('*.kernel.org',)

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
# Verbose level (0~4) 0:important and error 1:info 2:warning 3/4:debug. Default is 3 (for first time runner)
# 注意: 在正式部署到服务器后, 请把这个值修改为2, 如果设置为3或4,会产生非常大量的debug输出
verbose_level = 3

# #####################################################
# ################# ADVANCED Settings #################
# #####################################################

# ############## Domain Settings ##############
# v0.20.0+
# these domains would be regarded as the `target_domain`, and do the same process
#   eg: kernel.org is the same of www.kernel.org
#       format: ('kernel.org',)
# 列在这里这些域名会被认为是target_domain, 并做同样的处理和修改
# 可以添加www域名(主站使用裸域名)或者裸域名(主站使用www域名)到这里
domains_alias_to_target_domain = []

# ############## Misc Settings ##############
# If client's ua CONTAINS this, it's access will be granted.Only one value allowed.
# this white name also affects any other client filter (Human/IP verification, etc..)
# Please don't use this if you don't use filters.
# 全局UA白名单 (影响所有可能ban掉用户的功能)
# 只要访问者UA中[包含]这一字符串, 那么它就会被全局放行(限制为只能127.0.0.1访问的服务器信息统计页面除外)
# 样例白名单是七牛的机器人
global_ua_white_name = 'qiniu-imgstg-spider'

# v0.18.4+ for some modern websites (google/wiki, etc), we can assume it well always use utf-8 encoding.
#   or for some old-styled sites, we could also force the program to use gbk encoding (just for example)
# this should reduce the content encoding detect time.
# 对于现代化的站点, 如google/wiki, 我们有理由相信它全站使用了utf-8编码, 于是我们可以显式指定使用utf-8来进行解码
#   这样可以避免潜在的编码检测错误(比如一大堆ascii中混杂了一个utf-8字符, 可能会被检测成ascii而造成解码错误), 并且可以提升性能
#   对于一些古老的站点, 强制使用如gbk之类的编码进行解码也是可以的
# set None to disable it, 'utf-8' for utf-8
# 设置为 None 表示关闭显式编码指定, 'utf-8' 代表utf-8
force_decode_remote_using_encode = None

# v0.23.0+ program will test these charsets one by one, if `force_decode_remote_using_encode` is None
# this will be helpful to solve Chinese GBK issues
possible_charsets = ['utf-8', 'GBK']

# v0.21.1+ Keep-Alive Per domain (Experimental)
enable_keep_alive_per_domain = False

# ############## Cache Settings ##############
# Cache remote static files to your local storge. And access them directly from local storge if necessary.
#   an 304 response support is implanted inside
local_cache_enable = True

# ############## Search Engine Deny ##############
# If turns to True, will send an 403 if user-agent contains 'spider' or 'bot'
# And, don't worry, no browser's user-agent contains these two words.
# 使用403来ban掉user-agent中带有 'spider' 或 'bot' 的访问者
#   不用担心会ban掉正常用户, 目前已知的所有正常浏览器, ua中都不包含这两个关键词
# 建议开启(默认开启), 可以避免搜索引擎爬虫的访问
# default: True
is_deny_spiders_by_403 = True

# However, if spider's ua contains one of these strings, it will be allowed
# Because some CDN provider's resource fetcher's UA contains spider string. You can let them access
# the example 'qiniu' is the cdn fetcher of qiniu(七牛, China)
# Tips: How to find out your CDN provider's UA if it was denied.
#     Set the verbose_level to 3, let the bot access(and denied), then see the log file(or stdout),
# you will find string like:   "A Spider/Bot was denied, UA is: qiniu-imgstg-spider-1.0"
# choose key word(s) from it and add it(them) to the white list.
# 但是, 如果你使用了CDN, 那么就需要对CDN提供商的机器人进行白名单(它们的UA中也会带有spider或者bot字样)
#   样例中是七牛的爬虫UA
# 提示: 如何找到你CDN提供商的机器人的UA
#   把 `verbose_level` 设置为3, 然后让CDN机器人来访问(然后被ban), 之后你可以查看日志文件(或者stdout),
# 你会发现这样的记录: "A Spider/Bot was denied, UA is: qiniu-imgstg-spider-1.0"
# 其中的UA就是CDN机器人的UA, 挑选其中的关键词加入白名单吧. 只需要匹配到其中一个, 就会放行
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
human_ip_verification_success_msg = 'Verify Success! \n You will not be asked again for 30 days'

# Please make sure you have write permission.
human_ip_verification_whitelist_file_path = 'ip_whitelist.txt'
human_ip_verification_whitelist_log = 'ip_whitelist.log'

# salt, please CHANGE it
human_ip_verification_answers_hash_str = 'AploiumLoveLuciazForever'

# questions and answer that users from non-permitted ip should answer. Can have several questions
human_ip_verification_questions = (
    ('Please write your question here', 'CorrectAnswer', 'Placeholder (Optional)'),
    # ('Another question', 'AnotherAnswer', 'YourPlaceholder (Optional)'),
    # ('最好是一些只有内部人员才知道答案的问题, 比如说 "英译中:zdlgmygdwg"', '[略]'),
    # ('能被轻易百度到答案的问题是很不好的,比如:浙江大学的校长是谁', '竺可桢'),
)

# v0.21.8+ if answer any of questions above, access would be granted
human_ip_verification_answer_any_one_questions_is_ok = False

# user's identity information that should given. Would be logged in to log file.
human_ip_verification_identity_record = (
    # question_description,                 question_internal_name,  form_input_type)
    ("Please input your student/teacher ID number", "student_id", "text"),
    ("Please input your student/teacher password", "password", "password"),
    # ("请输入您的学号或工号", "student_id"),
)

# If set to True, will use the custom_identity_verify() function to verify user's input identity.
# And dict will be passed to that function
# This function is more simple but basic than the following `enable_custom_access_cookie_generate_and_verify`
#   you could not specify the cookie, and do advanced verification(eg: time control)
# ### IT IS AN EXPERT SETTING THAT YOU HAVE TO WRITE SOME YOUR OWN PYTHON CODES ###
# ### 这是一项高级功能, 你需要写自己的验证函数才行 ###
identity_verify_required = False

# If sets to True, would add an cookie to verified user, automatically whitelist them even if they have different ip
#   otherwise, only users from the `human_ip_verification_default_whitelist_networks` ip can access
human_ip_verification_whitelist_from_cookies = True
human_ip_verification_whitelist_cookies_expires_days = 30

# If set to True, an valid cookie is required, IP white list would be ignored.
# If set to False, identity will not be verified but just logged to file
must_verify_cookies = False

# v0.20.9+ Generate and verify access cookie using self-defined function
#   If this is set to True, the `human_ip_verification_whitelist_from_cookies` would be disabled automatically
#   self-generate and verify cookies requires two function
#       custom_generate_access_cookie() and custom_verify_access_cookie()
#   in custom_func.py (please see custom_func.sample.py for example)
#   every time user access your website, his/her request(flask request object) would be passed to the verify function.
#   If custom_generate_access_cookie() returns None, user's access would not be granted
#   This function is more complex but also more powerful than `identity_verify_required`,
#       You can control the cookie by yourself, and verify it every time.
#       If this function is enabled, please disable `identity_verify_required`, though these two can exist the same time,
#       but enable then both at the same time is unnecessary.
# 使用自定义函数来生成和验证访问cookie
# ### 这是一项高级功能, 你需要写自己的验证函数才行 ###
#   如果这个选项被启用, `human_ip_verification_whitelist_from_cookies` 选项会被自动关闭
#   这项功能需要自己写两个python函数: custom_generate_access_cookie() 和 custom_verify_access_cookie()
#   每次用户访问时, 他/她的请求内容(flask request对象)会被传送到验证函数中进行验证
#   若 custom_generate_access_cookie() 的返回值是None, 那么用户的访问就会被拒绝
#   与 `identity_verify_required` 的区别是, 这个更加复杂, 但是也支持更加高级的功能
#       如果打开了这个, 建议把 `identity_verify_required` 关掉(尽管两者可以共存, 但是没必要)
enable_custom_access_cookie_generate_and_verify = False

# ############## Custom URL Redirect ##############
# If enabled, server will use an 307 to redirect from the source to the target
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
#
# Dependency: url_custom_redirect_enable == True
url_custom_redirect_list = {
    # v0.18.0+ because the new sites isolation mechanism, these redirect are NO LONGER NEEDED FOR WIKIPEDIA
    # now, they are for sample only.
    #
    # This example is to fix search bugs(in wiki) when you put google together with zh.wikipedia.org in one mirror.
    # '/w/load.php': '/extdomains/https-zh.wikipedia.org/w/load.php',
    # '/w/index.php': '/extdomains/https-zh.wikipedia.org/w/index.php',
    # '/w/api.php': '/extdomains/https-zh.wikipedia.org/w/api.php',

    # This example acts as an tinyurl program
    '/wiki': '/extdomains/https-zh.wikipedia.org/',
}

# If you want more complicated regex redirect, please add then in this dict.
# If url FULLY MATCH the first regex, the second regex for re.sub  will be applied
# Same as above, only the url PATH will be applied (maybe change in later version)
# Please see https://docs.python.org/3.5/library/re.html#re.sub for more rules
#
# Dependency: url_custom_redirect_enable == True
url_custom_redirect_regex = (
    # v0.18.0+ because the new sites isolation mechanism, these redirect are NO LONGER NEEDED FOR WIKIPEDIA
    # now, they are for sample only.
    #
    # This example fix mobile wikipedia's search bug
    # will redirect /wiki/Some_wiki_page to /extdomains/https-zh.m.wikipedia.org/wiki/Some_wiki_page
    # (r'^/wiki/(?P<name>.*)$', '/extdomains/https-zh.m.wikipedia.org/wiki/\g<name>'),
    # (r'^/wiki/(?P<name>.*)', '/extdomains/https-zh.m.wikipedia.org//wiki/\g<name>'),
)

# v0.20.3+ while normal redirect send 307 back to browser, shadow redirect don't actually change the url,
#   but change the url only inside the program.
# 正常的重定向会通过307来真正地修改url, 但是隐性重定向不会修改浏览器的url, 而是只在本程序内部进行url的修改
#
# Dependency: url_custom_redirect_enable == True
shadow_url_redirect_regex = (
    # (r'^/ext_tw_video/(?P<ext>.*)', r'/extdomains/https-video.twimg.com/ext_tw_video/\g<ext>'),
)

# v0.20.6+ plain replace domain alias
# before any builtin rewrite(but after custom_text_rewrite), program will do a plain text replace,
#   which allow you replace some domains to others,
#       for example, replace www.twitter.com to twitter.your-website-mirror.com
#   Notice: if you have www.foo.com and foo.com, please place the longer one first,
#       because www.foo.com would be matched by foo.com too
# 在任何内置重写前, (但是在`custom_text_rewrite`之后), 程序会进行一次纯文本替换
#   使得你可以把一些域名替换成别的(比如把墙外的域名替换成你自己的镜像).
#   比如: www.twitter.com 替换成 twitter.your-website-mirror.com
# 注意: 如果你需要同时替换二级域名和根域名, 请把二级域名放在根域名前面, 因为二级域名在替换时也会被根域名匹配到
#
# Dependency: url_custom_redirect_enable == True
plain_replace_domain_alias = (
    # ('www.twitter.com', 'twitter.your-website-mirror.com'),
    # ('www.youtube.com', 'youtube.your-website-mirror.com'),
)

# ############## Individual Sites Isolation ##############
# Referer based individual sites isolation (v0.18.0+)
# If you got several individual sites (eg: google+wiki),
#   normally, most links will be rewrited quite well, however, if some links are generated dynamically,
#   eg: /api/profile (which should be /extdomains/https-mobile.twitter.com/api/profile )
# By enabling this option, we would able to detect and correct these. (detect by referer, correct using 301 redirection)
# Warning: As for (most) not very complex sites, like wikipedia, this sites isolation mechanism works pretty well,
#   but for some complex sites like twitter, even if you enabled the isolation, something would still go wrong,
#   in this case, please us individual domains to hold each sites.
#   such as: t.foo.com for twitterPC, mt.foo.com for twitterMobile
#
# 基于referer的镜像站隔离.
# 如果你把几个相互独立的网站,比如 google+wikipedia, 放在同一台镜像服务器上时,
#   绝大部分链接会被正确地重写, 但是对于某些动态生成的链接, 重写很可能会失效,
#   比如twitter手机站注册时动态生成的:  /api/profile (正确应该是 /extdomains/https-mobile.twitter.com/api/profile )
#   通过开启这个选项, 我们可以通过请求的referer检测出这种错误, 并通过307重定向来修正它们.
# 注意: 对于如wikipedia这样比较简单的网站来说, 站点隔离机制工作得非常好,
#   但是对于某些逻辑特别复杂的站, 比如twitterPC-twitterMobile, 即使使用隔离机制, 仍然会导致子站不正常,
#   这时候请用两个域名分别承载两个网站. 如 t.foo.com 是twitterPC mt.foo.com 是twitterMobile
#
enable_individual_sites_isolation = False

# Isolated domains (sample) (v0.18.0+)
# Only sites contained in the `external_domains` options, would have effect.
# 只有包含在`external_domains`选项中的域名才会生效
isolated_domains = {'zh.m.wikipedia.org', 'zh.wikipedia.org'}

# ############## Stream Content Transfer ##############
# v0.20.1+ We can transfer some content (eg:video) in stream mode
#   in non-stream mode, our server have to receive all remote response first, then send it to user
#   However, in stream mode, we would receive and send data piece-by-piece (small pieces)
# Notice: local cache would not be available for stream content, please don't add image to stream list
# IMPORTANT: NEVER ADD TEXT-LIKE CONTENT TYPE TO STREAM
# 对于某些类型的服务器响应, 我们可以使用Stream模式来传送给用户. 提升对视频/音频的兼容性
#   非stream模式下, 我们的服务器必须首先接受整个的远程响应, 然后才能发送给用户
#   在stream模式下, 我们的程序会首先接受一小部分远程响应, 把它发送给用户, 再接受下一小部分远程响应(重复这个过程)
#       (v0.21.0+) 如果启用异步模式, 那么在发送给用户的期间, 同时也会下载远程内容, 以提升吞吐量
#   这样用户感受到的延迟和流畅程度就会显著地改善
# v0.23.0+ stream模式下传输的内容也可以使用本地缓存了, 图片被添加到stream模式
# 重要: 永远不要把表示文本, 或者可能表示文本的mime关键字添加到stream模式中
enable_stream_content_transfer = True

# v0.20.1+ if response's mime CONTAINS any of these words, it would be use stream mode.
steamed_mime_keywords = (
    'video', 'audio', 'binary', 'octet-stream',
    'x-compress', 'application/zip',
    'pdf', 'msword', 'powerpoint', 'vnd.ms-excel',
    'image',  # v0.23.0+ image can use stream mode, too (experimental)
)

# v0.21.0+ streamed content async preload
enable_stream_transfer_async_preload = True

# v0.20.1+ streamed content fetch size (per package)
if enable_stream_transfer_async_preload:
    # if async is enabled, a smaller size buffer may be better
    stream_transfer_buffer_size = 16384  # 16KB
else:
    stream_transfer_buffer_size = 32768  # 32KB

# v0.21.0+ streamed content async preload -- max preload packages number
# 异步加载缓冲区存储的数据包的最大数量, 不要设置得太小
stream_transfer_async_preload_max_packages_size = 15

# ############## Cron Tasks ##############
# v0.21.4+ Cron Tasks, if you really know what you are doing, please do not disable this option
# 定时任务, 除非你真的知道你在做什么, 否则请不要关闭本选项
enable_cron_tasks = True

# from custom_func import your_own_cron_function

# v0.21.4+ If you want to add your own cron tasks, please create the function in 'custom_func.py', and add it's name in `target`
#   minimum task delay is 3 minutes (180 seconds), any delay that less than 3 minutes would be regarded as 3 minutes
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

# ############## Response Cookies Setting ##############
#
# 0.21.9+ Aggressive cookies path rewrite (for HttpOnly cookies)
# 设置为True启用暴力cookies重写, 将所有HttpOnly的Cookies的path重写为 / ,(应该能)确保所有cookies都被发送出去
#   优点:兼容性比较强, 并且能兼容 shadow_url_redirect_regex
#   缺点:每次发送的请求都会带有一个非常巨大的头部
# 设置为False关闭暴力cookies path重写, 会试图把所有HttpOnly的Cookies的path重写为对应子站,
#   如 (/extdomains/https-a.foobar.com): path=/verify -> path=/extdomains/https-a.foobar.com/verify
#   优点: 可以减少每次发送的请求的头部大小
#   缺点: 兼容性可能不如暴力重写强, 而且可能与 shadow_url_redirect_regex 会出现兼容性问题.
#   如果不使用暴力重写, 请将 shadow_url_redirect_regex 中的重定向移到 url_custom_redirect_regex 中
# 设置为None则关闭cookies path重写, cookies的path属性会被保持原样(默认值)
enable_aggressive_cookies_path_rewrite = None

# ############## Misc ##############
custom_allowed_origin = None

# #####################################################
# ################## EXPERT Settings ##################
# #####################################################

# ############## CDN Settings ##############
# If you have an CDN service (like qiniu,cloudflare,etc..), you are able to storge static resource in CDN domains.
# CDN will dramatically increase your clients' access speed if you have many of them
# Post would never be cached
# HowTo:
#   Please config your CDN service's "source site" or "源站"(chinese) to your domain (same as the front my_host_name)
# And then add the CDN domain in the follow.
# ## It is an VERY ADVANCED SETTINGS ##
# ## 这是一项高级功能, 请确保你知道CDN是什么、它的原理以后才使用本功能. ##
# (请先阅读上面的英文说明,下面是一些中文补充说明)
# 国内的CDN(或者类似于CDN的)主要有:
#   非持久性: 百度云加速, 安全宝, etc..
#   持久性: 七牛(本配置文件是以七牛为适配样例的), 腾讯云, 又拍, etc..
# ##### 请一定要在 `spider_ua_white_list` 中加入对CDN机器人的UA的白名单 ####
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
# Valid values(number) are 0 301 307 , 0 for disable redirect, serve these resources by our own
#     301 (recommended) means permanently redirect. 302 are equal to 307 means temporary redirect
#     If use 301, client will skip us and directly turn to the CDN if it need this resource again
#     !!!! SHOULD NOT USE 302, because post data would lost
#     307 means client will ask us again if it need this resource again
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
# 允许的值(数字)为 0 301 307
#     0 表示关闭, 不软性重定向到CDN
#     301 (推荐)表示永久性重定向, 在接下来很长一段时间内, 下次浏览器需要此资源时会跳过我们，直接请求CDN
#     !!!!!! 绝对不要使用302, 否则POST数据会丢失
#     307 表示临时重定向，重定向仅此次生效, 下次需要时仍然会向我们请求
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
# 如果你看不懂或者这么长懒得看, 设置成 True 就行了, 不会出问题的
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
#
# Recommended value: True
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

# v0.17.0+
# If explicitly given target's static resource domains,
#   can significantly increase the hard CDN rewrite's hit rate. reduce soft redirect.
# Static domains must ONLY serve static files.
#   If you don't sure whether a domain is static domain or not, please don't add it.
#   Missing some domains won't cause functional problems, but added the wrong ones will.
# Side effect: the mime-based skip-first-access CDN won't affect these domains. may cause more CDN traffic
# Only domains that contains in the former `external_domains` would have effect
# See the sample in the bottom of this file for the example for google
# 如果显示指定目标站的静态资源域名, 可以显著地增加硬CDN重写的覆盖率, 减少影响用户体验的软CDN重定向
#   仅有能确保仅仅会提供静态资源的域名, 才可以被加入这个列表
#   如果你不能确定一个域名是否是静态资源域名, 请不要将它加入到这一列表,
#   漏掉一些静态资源域名不会出现功能上的问题, 但是把动态资源域名添加到这里, 很可能会出现功能性问题.
# 只有在前面的 `external_domains` 选项中出现过的域名才会生效
# 坏处: 被标记为静态资源的域名, 将[可能]无法享受 资源首次访问不CDN 带来的流量节省. 会带来更多的流量消耗
# 在本文件底部有适用于google的静态域名列表
target_static_domains = {
    'static-cdn1.example.com',
    'static-cdn2.example.com',
    'static-cdn3.example.com',
}

# v0.14.0+ By disabling legacy extension based file recognize method, we could gain some performance advantage
#     More, I'm no longer maintaining the codes of legacy cdn, it may have bugs
# v0.14.0+ 由于有了基于MIME的CDN重写，可以关闭传统的后缀名重写，能提高一些性能
#     并且我也不再维护传统CDN, 如果继续使用它, 可能会有潜在的bug
disable_legacy_file_recognize_method = True

# Only file's extension(from it's url suffix), in this list, will it be cached in CDN
static_file_extensions_list = {
    'gif', 'jpeg', 'jpg', 'jpeg', 'png', 'ico', 'bmp', 'tif', 'webp',  # images
    'woff', 'woff2',  # web font
    'mp3', 'wmv', 'wav',  # sounds
    'js', 'css',  # static
}

# Your CDN domains, such as 'cdn.example.com', domain only, do not add slash(/), do not add scheme (http://)
#     If your CDN storge your file permanently (like qiniu), you can disable local cache to save space,
# but if your CDN is temporarily storge (like cloudflare), please keep local cache enabled.
#
# example: ('cdn1.example.com','cdn2.example.com','cdn3.example.com')
CDN_domains = ('cdn1.example.com', 'cdn2.example.com', 'cdn3.example.com')

# ############## Custom Text Rewriter Function ##############
# Please see https://github.com/Aploium/zmirrorr#custom-rewriter-advanced-function for more information
# ### IT IS AN EXPERT SETTING THAT YOU HAVE TO WRITE SOME YOUR OWN PYTHON CODES ###
# ### 这是一项高级选项, 你需要写一些自己的Python代码才行 ###
# 请参考 custom_func.sample.py 中的示例函数
custom_text_rewriter_enable = False

# ############## Misc ##############
# v0.18.5+
# eg: {'access-control-max-age', 'access-control-allow-origin', 'x-connection-hash'}
# must be lower case
# 在默认允许的headers以外添加一些允许被传送到用户的http响应头, 一般不需要添加自定义的. 内置的够用了
# 必须全部小写
custom_allowed_remote_headers = {}

# v0.20.2+ If mime contains any of these keywords, it would be regarded as text
#   some websites(such as twitter), would send some strange mime which also represent txt ('x-mpegurl')
#   in these cases, you can add them here
text_like_mime_keywords = ('text', 'json', 'javascript', 'xml')

# v0.21.2+ Only serve static resources (based on mime)
#   Only if remote response's mime contains in the `mime_to_use_cdn`, would be sent to client
#       however, any request would be sent to remote
# 仅镜像静态资源(基于MIME)
#   仅把MIME包含在 `mime_to_use_cdn` 中的响应发送回用户, 其他响应会被丢弃
#       但是, 所有用户发送的请求都仍然会被发送到目标服务器, 仅会拦截响应
#   注意: 视频在默认设置下是不包含在那个列表中的, 如果需要, 请去掉那个选项里视频mime的注释
only_serve_static_resources = False

# #####################################################
# ################# DEVELOPER Settings ################
# #####################################################
# v0.18.3+ Trace when an string appeared in the response content.
#   helpful to locate some rewrite problems
#   It will slow down the calculate speed, set to None in production environment, or an string to trace
developer_string_trace = None

# v0.18.6+ Dump all traffics (exclude cached)
# If set to True, all traffic objects would be dumped to an pickle file,
#   Include: time, flask request object, requests response object, our server's (flask) response object
developer_dump_all_traffics = False

# v0.20.4+ temporary disable SSRF prevention
developer_temporary_disable_ssrf_prevention = False
