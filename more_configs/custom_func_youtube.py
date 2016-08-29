# coding=utf-8
"""
This is the custom functions for youtube mirror
please copy it to YOUR_EWM_FOLDER/custom_func.py

Without this file, twitter mirror won't work normally
"""
import re
from random import randint
import traceback
from urllib.parse import urlsplit
from zmirror.zmirror import *

# 如果你想视频服务器和网页服务器分开, 通过多个视频服务器来进行负载均衡,
#   请设置在主网页服务器上设置 is_master = True ,在视频服务器上部署后设置 is_master = False
#   在主服务器上的 videocdn_domain_list 中设置好视频服务器的域名
#   在每个视频服务器上设置 videocdn_this_site_name 为这个视频服务器的域名
#
# 如果想在同一台服务器上同时提供网页和视频的服务, 不需要修改设置
is_master = False

# 注: 如果使用了非标准端口, 请在下面所有需要填写域名的地方后面加上端口号, 如 'videocdn1.mycdn.com:20822'
videocdn_this_site_name = my_host_name
# 如果你想视频服务器和网页服务器分开, 请注释掉上面一行, 去掉下面一行的注释, 并把域名改成这一台视频服务器的域名
# videocdn_this_site_name = 'videocdn1.mycdn.com'  # 使用标准端口
# videocdn_this_site_name = 'videocdn1.mycdn.com:20822'  # 使用非标准端口


videocdn_domain_list = [
    # 你用来提供视频服务的域名, 注意, 一级域名和顶级域名必须一样(例子中 'mycdn.com' 的部分).
    #   必须是三级域名. 二级或四级域名不可以
    'videocdn1.mycdn.com',
    'videocdn2.mycdn.com',
    'videocdn3.mycdn.com',
    'videocdn4.mycdn.com',
    'videocdn5.mycdn.com',
    # 'videocdn6.mycdn.com:20822', # 如果使用非标准端口, 请加上端口号
]

# get videocdn domain's root domain
try:
    if videocdn_this_site_name != my_host_name:
        temp0 = videocdn_domain_list[0]
    else:
        temp0 = videocdn_this_site_name
except:
    temp0 = videocdn_this_site_name
temp0 = urlsplit("//" + temp0).hostname  # 为了支持带有端口号的域名
temp = temp0.split('.')
if len(temp) <= 2 or len(temp) == 3 and temp[1] in ('com', 'net', 'org', 'co', 'edu', 'mil', 'gov', 'ac'):
    videocdn_video_root_domain = temp0
else:
    videocdn_video_root_domain = '.'.join(temp[1:])

len_cdn_domains = len(videocdn_domain_list)

if is_master:
    video_cdn_domain = videocdn_domain_list[randint(0, len_cdn_domains - 1)]
else:
    video_cdn_domain = videocdn_this_site_name

# ################### REGEX ###################
# regex patton from @stephenhay, via https://mathiasbynens.be/demo/url-regex
REGEX_OF_URL = r'(https?|ftp):\/\/[^\s/$.?#].[^\s]*'

regex_youtube_video_videoplayback_resolve = re.compile(
    ('https(%|%25)3A(%|%25)2F(%|%25)2F' if my_host_scheme == 'http://' else '') +
    r'''(?P<prefix>r\d+---sn-[a-z0-9]{8})\.googlevideo\.com(?P<percent>%|%25)2Fvideoplayback(%|%25)3F''',
    flags=re.IGNORECASE)

regex_youtube_video_url_resolve = re.compile(
    (r'https:(?P<escape_slash>\\?)/\\?/' if my_host_scheme == 'http://' else '') +
    r'''(?P<prefix>r\d+---sn-[a-z0-9]{8})\.googlevideo\.com''')

regex_youtube_video_c_videoplayback_resolve = re.compile(
    ('https://' if my_host_scheme == 'http://' else '') +
    r'''(?P<prefix>r\d+---sn-[a-z0-9]{8})\.c\.youtube\.com/videoplayback\?''',
    flags=re.IGNORECASE)


def custom_response_text_rewriter(raw_text, content_mime, remote_url):
    # if 'html' in content_mime or 'x-www-form-urlencoded' in content_mime:
    raw_text = regex_youtube_video_videoplayback_resolve.sub(
        ('http\g<percent>3A\g<percent>2F\g<percent>2F' if my_host_scheme == 'http://' else '') +
        video_cdn_domain + '\g<percent>2Fvideoplayback\g<percent>3Fewmytbserver\g<percent>3D\g<prefix>\g<percent>26', raw_text)
    raw_text = regex_youtube_video_url_resolve.sub(
        ('http:\g<escape_slash>/\g<escape_slash>/' if my_host_scheme == 'http://' else '') + video_cdn_domain, raw_text)

    raw_text = regex_youtube_video_c_videoplayback_resolve.sub(
        ('http://' if my_host_scheme == 'http://' else '') +
        video_cdn_domain + '/videoplayback?ewmytbserver=\g<prefix>&', raw_text)

    if 'javascript' in content_mime:
        raw_text = raw_text.replace(r'\\.googlevideo\\.com$', r".*?\\."
                                    # + my_host_name_root.replace('.',r'\\.')
                                    + videocdn_video_root_domain.replace('.', r'\\.')
                                    + '$')

        _buff = re.escape(videocdn_video_root_domain) + '|' + re.escape(my_host_name_root)
        raw_text = raw_text.replace(r'-nocookie)?\.com\/|(m\.)?[a-z0-9\-]',
                                    r'-nocookie)?\.com\/|' + _buff + r'|(m\.)?[a-z0-9\-]')  # xp

        raw_text = raw_text.replace(r'googlevideo\.com|play\.google\.com|',
                                    r'googlevideo\.com|' + _buff + r'|play\.google\.com|')  # hr

        raw_text = raw_text.replace(r'prod\.google\.com|sandbox\.google\.com',
                                    r'prod\.google\.com|' + _buff + r'|sandbox\.google\.com')  # gx

        raw_text = raw_text.replace(r'corp\.google\.com|borg\.google\.com',
                                    r'corp\.google\.com|' + _buff + r'|borg\.google\.com')  # Saa

    return raw_text
