# coding=utf-8
import re
from zmirror import *

# regex patton from @stephenhay, via https://mathiasbynens.be/demo/url-regex
REGEX_OF_URL = r'(https?|ftp):\/\/[^\s/$.?#].[^\s]*'
# pre compile an regex will enhance it's performance
regex_ubb_img_rewriter = re.compile(r'\[upload=[\w, ]+?\](?P<image_url>' + REGEX_OF_URL + r'?)\[/upload\]')

# Example for Twitter
regex_twitter_data_expanded = re.compile(
    r'''data-expanded-url\s*=\s*'''
    '''"(?P<scheme>(https?:)?\\?/\\?/)(?P<domain>([-a-z0-9]+\.)+[a-z]+)(?P<path>[^\s;+?#'"]*?)"'''
    , flags=re.IGNORECASE)


def custom_response_text_rewriter(raw_text, content_mime, remote_url):
    # Only text content (txt/html/css/js/json) would be passed to this function

    # Tips: If you can use plain string.replace, DO NOT USE REGEX, because regex is hundreds times slower than string.replace
    # string.replace won't cause performance problem

    # replace UBB image to image tag
    # eg. from [upload=jpg]http://foo.bar/blah.jpg[/upload]
    #     to <img src="http://foo.bar/blah.jpg"></img>
    raw_text = regex_ubb_img_rewriter.sub(r'<img src="\g<image_url>" style="max-width: 100%;"></img>', raw_text)

    # For twitter expand replace
    regex_twitter_data_expanded.sub(demo__handle_expand_url, raw_text)

    if 'search' in remote_url and (content_mime == 'text/html' or content_mime == 'application/json'):
        raw_text = demo__google_result_open_in_new_tab(raw_text, content_mime)

    # remove google analytics
    raw_text = raw_text.replace('www.google-analytics.com/analytics.js', '')

    # Add your own analytics codes
    if content_mime == 'text/html':
        # Your statistic code
        my_statistic_code = r"""<!--Your Own Static Code-->"""
        # Add to just before the html head
        raw_text = raw_text.replace('</head>', my_statistic_code + '</head>', 1)

    return raw_text


def custom_identity_verify(identity_dict):
    """
    Return True and False, if False, user's access will not be granted.
    An dict contains user's identity will be passed to this function.
       You can do some verification, for example, you can try to login to an internal site,
    if login succeed, you return True, otherwise False

    :type identity_dict: dict
    """
    True_or_False = True
    return True_or_False


def custom_generate_access_cookie(input_dict, flask_request):
    """
    generate access cookies, to identity user (or deny)
    See option `enable_custom_access_cookie_generate_and_verify`
    :param input_dict: a dict contains user's input
    :param flask_request: user's flask request object
    :return: cookie string or None. If returns None, client's access would be denied.
    """
    # example, calling the builtin access cookie generate function
    return generate_ip_verify_hash(input_dict)


def custom_verify_access_cookie(zmirror_verify_cookie, flask_request):
    """
    verify user's access cookie. return True for access granted, False for denied
    See option `enable_custom_access_cookie_generate_and_verify`
    :param flask_request: the flask request object
    :return: bool
    """
    # example, calling the builtin cookie verify function
    return verify_ip_hash_cookie(zmirror_verify_cookie)


# just_another_demo_custom_identity_verify
def demo__custom_identity_verify(identity_dict):
    """
    For CC98 identity verify

    :type identity_dict: dict
    """
    import hashlib
    import requests
    import config

    if 'cc98_username' not in identity_dict or 'cc98_password' not in identity_dict:
        return False

    try:
        pass_md5 = hashlib.md5()
        pass_md5.update(identity_dict['cc98_password'].encode())
        pass_md5 = pass_md5.hexdigest()
        if config.is_use_proxy:
            proxy = config.requests_proxies
        else:
            proxy = None
        r = requests.post('http://www.cc98.org/sign.asp', data={
            'a': 'i',
            'u': identity_dict['cc98_username'],
            'p': pass_md5,
            'userhidden': 2
        }, proxies=proxy)
        if r.text == '9898':
            return True
        else:
            return False
    except:
        return False


# Demo for Twitter
def demo__handle_expand_url(mobj):
    import config
    from zmirror import add_ssrf_allowed_domain, get_group

    domain = get_group('domain', mobj)
    if not domain:
        return mobj.group()
    add_ssrf_allowed_domain(domain)
    if 'https' in get_group('scheme', mobj) or config.force_https_domains == 'ALL':
        scheme_prefix = 'https-'
    else:
        scheme_prefix = ''

    return 'data-expanded-url="%s"' % ('/extdomains/' + scheme_prefix + domain + get_group('path', mobj))


def demo__google_result_open_in_new_tab(raw_text, content_mime):
    """Force google search's result to open in new tab. to avoid iframe problem
    在新标签页中打开google搜索结果
    """

    def hexlify_to_json(ascii_str):
        buff = ''
        for char in ascii_str:
            if char in '\'\"<>&=':
                buff += r'\x' + hex(ord(char))[2:]
            else:
                buff += char
        buff = buff.replace('\\', '\\\\')
        buff = buff.replace('/', r'\/')
        return buff

    if content_mime == 'application/json':
        raw_text = raw_text.replace(
            hexlify_to_json('<h3 class="r"><a href="'),
            hexlify_to_json('<h3 class="r"><a target="_blank" href="')
        )
        raw_text = raw_text.replace(
            hexlify_to_json('<h3 class="r"><a class="l" href="'),
            hexlify_to_json('<h3 class="r"><a target="_blank" class="l" href="')
        )
    else:
        raw_text = raw_text.replace('<h3 class="r"><a href="', '<h3 class="r"><a target="_blank" href="')
        raw_text = raw_text.replace('<h3 class="r"><a class="l" href="', '<h3 class="r"><a target="_blank" class="l" href="')

    return raw_text
