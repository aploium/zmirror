# coding=utf-8
"""
This is the custom functions for youtube mirror
please copy it to YOUR_EWM_FOLDER/custom_func.py

Without this file, twitter mirror won't work normally
"""
import re
from EasyWebsiteMirror import *

regex_youtube_video_videoplayback_resolve = re.compile(
    r'''(?P<prefix>r\d+---sn-[a-z0-9]{8})\.googlevideo\.com(?P<percent>%|%25)2Fvideoplayback(%|%25)3F''', flags=re.IGNORECASE)
regex_youtube_video_url_resolve = re.compile(r'''(?P<prefix>r\d+---sn-[a-z0-9]{8})\.googlevideo\.com''')


def custom_response_text_rewriter(raw_text, content_mime, remote_url):
    raw_text = regex_youtube_video_videoplayback_resolve.sub(
        my_host_name + '\g<percent>2Fvideoplayback\g<percent>3Fewmytbserver\g<percent>3D\g<prefix>\g<percent>26', raw_text)
    raw_text = regex_youtube_video_url_resolve.sub(my_host_name, raw_text)

    if 'javascript' in content_mime:
        raw_text = raw_text.replace(r'\\.googlevideo\\.com$', r".*?\\." + my_host_name_root.replace('.', r'\\.') + '$')

        _buff = re.escape(my_host_name_root)
        raw_text = raw_text.replace(r'-nocookie)?\.com\/|(m\.)?[a-z0-9\-]',
                                    r'-nocookie)?\.com\/|' + _buff + r'|(m\.)?[a-z0-9\-]')  # xp

        raw_text = raw_text.replace(r'googlevideo\.com|play\.google\.com|',
                                    r'googlevideo\.com|' + _buff + r'|play\.google\.com|')  # hr

        raw_text = raw_text.replace(r'prod\.google\.com|sandbox\.google\.com',
                                    r'prod\.google\.com|' + _buff + r'|sandbox\.google\.com')  # gx

        raw_text = raw_text.replace(r'corp\.google\.com|borg\.google\.com',
                                    r'corp\.google\.com|' + _buff + r'|borg\.google\.com')  # Saa
    return raw_text
