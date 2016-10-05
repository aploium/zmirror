# coding=utf-8
# 这是一个 **功能残缺** 的facebook
#
# 使用方法:
#   1. 复制本文件到 zmirror 根目录(wsgi.py所在目录), 并重命名为 config.py
#   2. 修改 my_host_name 为你自己的域名
#
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置
#
# 存在很多问题. 最大的问题是当地址栏发生改变时, 不会自动刷新, 以后会加入刷新脚本
#

# Github: https://github.com/aploium/zmirror

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'
my_host_port = None  # None表示使用默认端口, 可以设置成非标准端口, 比如 81

# ############## Target Domain Settings ##############
target_domain = 'www.facebook.com'
target_scheme = 'https://'

# 这里面大部分域名都是通过 `enable_automatic_domains_whitelist` 自动采集的, 我只是把它们复制黏贴到了这里
# 实际镜像一个新的站时, 手动只需要添加很少的几个域名就可以了.
# 自动采集(如果开启的话)会不断告诉你新域名
external_domains = (

    "facebook.com",
    "m.facebook.com",
    "mqtt.facebook.com",
    "s-static.ak.facebook.com",
    "profile.ak.facebook.com",
    "static.ak.facebook.com",
    "b.static.ak.facebook.com",
    "graph.facebook.com",
    "ssl.facebook.com",
    "staticxx.facebook.com",
    "api.facebook.com",
    "secure-profile.facebook.com",
    "secure.facebook.com",
    "zh-cn.facebook.com",
    "login.facebook.com",
    "message-facebook.com",
    "attachments.facebook.com",
    "touch.facebook.com",
    "apps.facebook.com",
    "upload.facebook.com",
    "developers.facebook.com",
    "act.channel.facebook.com",
    "0-act.channel.facebook.com",
    "1-act.channel.facebook.com",
    "2-act.channel.facebook.com",
    "3-act.channel.facebook.com",
    "4-act.channel.facebook.com",
    "5-act.channel.facebook.com",
    "6-act.channel.facebook.com",
    "inyour-slb-01-05-ash3.facebook.com",
    "origincache-starfacebook-ai-01-05-ash3.facebook.com",
    "beta-chat-01-05-ash3.facebook.com",
    "channel-ecmp-05-ash3.facebook.com",
    "channel-staging-ecmp-05-ash3.facebook.com",
    "channel-testing-ecmp-05-ash3.facebook.com",
    "0-edge-chat.facebook.com",
    "1-edge-chat.facebook.com",
    "2-edge-chat.facebook.com",
    "3-edge-chat.facebook.com",
    "4-edge-chat.facebook.com",
    "5-edge-chat.facebook.com",
    "6-edge-chat.facebook.com",
    "api-read.facebook.com",
    "bigzipfiles.facebook.com",
    "check4.facebook.com",
    "check6.facebook.com",
    "code.facebook.com",
    "connect.facebook.com",
    "edge-chat.facebook.com",
    "pixel.facebook.com",
    "star.c10r.facebook.com",
    "star.facebook.com",
    "zh-tw.facebook.com",
    "b-api.facebook.com",
    "b-graph.facebook.com",
    "orcart.facebook.com",
    "s-static.facebook.com",
    "vupload.facebook.com",
    "vupload2.vvv.facebook.com",
    "d.facebook.com",
    "fbexternal-a.akamaihd.net",
    "fbcdn-creative-a.akamaihd.net",
    "fbcdn-video-a-a.akamaihd.net",
    "fbcdn-video-b-a.akamaihd.net",
    "fbcdn-video-c-a.akamaihd.net",
    "fbcdn-video-d-a.akamaihd.net",
    "fbcdn-video-e-a.akamaihd.net",
    "fbcdn-video-f-a.akamaihd.net",
    "fbcdn-video-g-a.akamaihd.net",
    "fbcdn-video-h-a.akamaihd.net",
    "fbcdn-video-i-a.akamaihd.net",
    "fbcdn-video-j-a.akamaihd.net",
    "fbcdn-video-k-a.akamaihd.net",
    "fbcdn-video-l-a.akamaihd.net",
    "fbcdn-video-m-a.akamaihd.net",
    "fbcdn-video-n-a.akamaihd.net",
    "fbcdn-video-o-a.akamaihd.net",
    "fbcdn-video-p-a.akamaihd.net",
    "fbcdn-vthumb-a.akamaihd.net",
    "fbcdn-sphotos-a-a.akamaihd.net",
    "fbcdn-sphotos-b-a.akamaihd.net",
    "fbcdn-sphotos-c-a.akamaihd.net",
    "fbcdn-sphotos-d-a.akamaihd.net",
    "fbcdn-sphotos-e-a.akamaihd.net",
    "fbcdn-sphotos-f-a.akamaihd.net",
    "fbcdn-sphotos-g-a.akamaihd.net",
    "fbcdn-sphotos-h-a.akamaihd.net",
    "fbcdn-profile-a.akamaihd.net",
    "fbcdn-photos-a.akamaihd.net",
    "fbcdn-photos-e-a.akamaihd.net",
    "fbcdn-sphotos-a.akamaihd.net",
    "fbstatic-a.akamaihd.net",
    "fbcdn.net",

    "video.xx.fbcdn.net",
    "video.xx.fbcdn.net",
    "scontent.xx.fbcdn.net",
    "external.xx.fbcdn.net",

    "scontent-a.xx.fbcdn.net",
    "scontent-b.xx.fbcdn.net",
    "scontent-c.xx.fbcdn.net",
    "scontent-d.xx.fbcdn.net",
    "scontent-e.xx.fbcdn.net",
    "scontent-mxp.xx.fbcdn.net",
    "scontent-a-lax.xx.fbcdn.net",
    "scontent-a-sin.xx.fbcdn.net",
    "scontent-b-lax.xx.fbcdn.net",
    "scontent-b-sin.xx.fbcdn.net",
    "vthumb.ak.fbcdn.net",
    "photos-a.ak.fbcdn.net",
    "photos-b.ak.fbcdn.net",
    "photos-c.ak.fbcdn.net",
    "photos-d.ak.fbcdn.net",
    "photos-e.ak.fbcdn.net",
    "photos-f.ak.fbcdn.net",
    "photos-g.ak.fbcdn.net",
    "photos-h.ak.fbcdn.net",
    "creative.ak.fbcdn.net",
    "external.ak.fbcdn.net",
    "b.static.ak.fbcdn.net",
    "static.ak.fbcdn.net",
    "origincache-ai-01-05-ash3.fbcdn.net",
    "profile.ak.fbcdn.net",
    "vpn.tfbnw.net",
    "ent-a.xx.fbcdn.net",
    "ent-b.xx.fbcdn.net",
    "ent-c.xx.fbcdn.net",
    "ent-d.xx.fbcdn.net",
    "ent-e.xx.fbcdn.net",
    "s-external.ak.fbcdn.net",
    "s-static.ak.fbcdn.net",
    "static.thefacebook.com",
    "ldap.thefacebook.com",
    "attachment.fbsbx.com",
    "connect.facebook.net",
    "live.fb.com",
    "work.fb.com",
    "techprep.fb.com",
    "nonprofits.fb.com",
    "managingbias.fb.com",
    "rightsmanager.fb.com",
    "instantarticles.fb.com",
    "messengerplatform.fb.com",
    "threatexchange.fb.com",

    "cx.atdmt.com",

    "fb-s-d-a.akamaihd.net",
    "fbcdn-photos-a-a.akamaihd.net",
    "fbcdn-photos-c-a.akamaihd.net",
    "fbcdn-photos-d-a.akamaihd.net",
    "fbcdn-photos-b-a.akamaihd.net",
    "fb-s-c-a.akamaihd.net",

    "ar-ar.facebook.com",
    "bg-bg.facebook.com",
    "bs-ba.facebook.com",
    "ca-es.facebook.com",
    "da-dk.facebook.com",
    "el-gr.facebook.com",
    "es-la.facebook.com",
    "es-es.facebook.com",
    "fa-ir.facebook.com",
    "fi-fi.facebook.com",
    "fr-fr.facebook.com",
    "fr-ca.facebook.com",
    "hi-in.facebook.com",
    "hr-hr.facebook.com",
    "id-id.facebook.com",
    "it-it.facebook.com",
    "ko-kr.facebook.com",
    "mk-mk.facebook.com",
    "ms-my.facebook.com",
    "pl-pl.facebook.com",
    "pt-br.facebook.com",
    "pt-pt.facebook.com",
    "ro-ro.facebook.com",
    "sl-si.facebook.com",
    "sr-rs.facebook.com",
    "th-th.facebook.com",
    "vi-vn.facebook.com",
    "error.facebook.com",
    "ja-jp.facebook.com",
    "de-de.facebook.com",
    "l.facebook.com",
    "static.xx.fbcdn.net",
    "scontent-lax3-1.xx.fbcdn.net",
    "external-lax3-1.xx.fbcdn.net",
    "video-lax3-1.xx.fbcdn.net",

)

# 强制所有 Facebook 站点使用HTTPS
force_https_domains = 'ALL'

# 自动动态添加域名
enable_automatic_domains_whitelist = True
domains_whitelist_auto_add_glob_list = (
    "*.facebook.com", "*.fbcdn.net", "*.akamaihd.net",
    "*.fb.com", "*.facebook.net",
)

# ############# Additional Functions #############
custom_inject_content = {
    "head_first": [
        {
            "content": r"""<script>
zmirror_facebook_href = window.location.href;
zmirror_facebook_refresh_flag = false;
setInterval(function() {
  if (window.location.href != zmirror_facebook_href && !zmirror_facebook_refresh_flag){
    zmirror_facebook_refresh_flag = true;
    location.reload();
  }
}, 500);
</script>""",
        },
    ]
}

# ############## Proxy Settings ##############
# 如果你在墙内使用本配置文件, 请指定一个墙外的http代理
is_use_proxy = False
# 代理的格式及SOCKS代理, 请看 http://docs.python-requests.org/en/latest/user/advanced/#proxies
requests_proxies = dict(
    http='http://127.0.0.1:8123',
    https='https://127.0.0.1:8123',
)
