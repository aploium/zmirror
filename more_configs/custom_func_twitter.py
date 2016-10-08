# coding=utf-8
"""
This is the custom functions for twitter mirrors(PC/mobile)
please copy it to YOUR_EWM_FOLDER/custom_func.py

Without this file, twitter mirror won't work normally
"""
import re
from zmirror.zmirror import add_ssrf_allowed_domain, get_group, \
    force_https_domains, my_host_scheme, my_host_name, encode_mirror_url, \
    decode_mirror_url

regex_twitter_data_expanded = re.compile(
    r'''data-expanded-url\s*=\s*'''
    '''"(?P<scheme>(https?:)?\\?/\\?/)(?P<domain>([-a-z0-9]+\.)+[a-z]+)(?P<path>[^\s;+?#'"]*?)"'''
    , flags=re.IGNORECASE)


def handle_expand_url(mobj):
    domain = get_group('domain', mobj)
    if not domain:
        return mobj.group()
    add_ssrf_allowed_domain(domain)
    if 'https' in get_group('scheme', mobj) or force_https_domains == 'ALL':
        scheme_prefix = 'https-'
    else:
        scheme_prefix = ''

    return 'data-expanded-url="%s"' % ('/extdomains/' + scheme_prefix + domain + get_group('path', mobj))


def custom_response_text_rewriter(raw_text, content_mime, remote_url):
    # For twitter expand replace
    regex_twitter_data_expanded.sub(handle_expand_url, raw_text)

    # For twitter t.co redirect
    raw_text = raw_text.replace('https://t.co/', my_host_scheme + my_host_name + '/extdomains/https-t.co/')

    # For twitter video
    if decode_mirror_url()["domain"] == 'video.twimg.com':
        raw_text = raw_text.replace('/ext_tw_video/',
                                    encode_mirror_url('/ext_tw_video/', remote_domain='video.twimg.com', is_scheme=False))

    return raw_text
