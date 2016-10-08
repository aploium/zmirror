# coding=utf-8
import re
from flask import Response, Request
from zmirror.zmirror import *

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
    """
    Allow you do some custom modifications/rewrites to the response content.
        eg: add your own statistic code
    Only text content (txt/html/css/js/json) would be passed to this function

    Notice: the remote response "Location" headers(occurs in 301/302/307) will be passed to this function too,
        with an special content_mime as "mwm/headers-location"

    Please remember to set `custom_text_rewriter_enable` to True in the config

    (请先看完上面的英文)
    在简单情况下, 你可以只对源站的响应文本进行一些简单的字符串上的修改(比如添加你自己的统计代码, 改一些文字之类)

    稍微复杂一点, 你还可以调用zmirror本身的其他实用函数,
      以内置twitter镜像为例, 它调用了zmirror内置的 encode_mirror_url() 函数, 来将url转化为镜像url

    更加高级一点, 在自定义重写函数中, 还能影响zmirror本身的行为,
      比如可以通过 try_match_and_add_domain_to_rewrite_white_list() 动态添加域名到重写名单(external_domains)中,

    :param raw_text: raw response html/css/js text content
    :type raw_text: str
    :param content_mime: response's mime
    :type content_mime: str
    :param remote_url: remote url
    :type remote_url: str
    :return: modified response text content
    :rtype: str
    """

    # Tips: If you can use plain string.replace, DO NOT USE REGEX, because regex is hundreds times slower than string.replace
    # string.replace won't cause performance problem

    # Example: replace UBB image to image tag
    # eg. from [upload=jpg]http://foo.bar/blah.jpg[/upload]
    #     to <img src="http://foo.bar/blah.jpg"></img>
    raw_text = regex_ubb_img_rewriter.sub(r'<img src="\g<image_url>" style="max-width: 100%;"></img>', raw_text)

    # Example: For twitter expand replace
    regex_twitter_data_expanded.sub(demo__handle_expand_url, raw_text)

    if 'search' in remote_url and (content_mime == 'text/html' or content_mime == 'application/json'):
        raw_text = demo__google_result_open_in_new_tab(raw_text, content_mime)

    # Example: remove google analytics
    raw_text = raw_text.replace('www.google-analytics.com/analytics.js', '')

    # Example: Add your own analytics codes
    if content_mime == 'text/html':
        # Your statistic code
        my_statistic_code = r"""<!--Your Own Statistic Code-->"""
        # Add to just before the html head
        raw_text = raw_text.replace('</head>', my_statistic_code + '</head>', 1)

    return raw_text


def custom_prior_redirect_func(request, parse):
    """
    用于在 prior_request_redirect 阶段的自定义重定向

    若返回一个 flask.Response 对象, 则执行重定向, 直接返回这个 Response
    若返回None, 则不进行重定向

    不应该修改parse变量 (添加头和cookie除外)

    详见 `config_default.py` 中 `Custom Redirection` 部分

    :param request: flask request object
    :type request: Request
    :param parse: the zmirror parse variable
    :type parse: ZmirrorThreadLocal
    :rtype: Union[Response, None]
    """
    print(request.url, parse.remote_url)

    from flask import redirect

    # 如果你想重定向, 请使用这句
    # return redirect("/location/you/want/redirect/to")

    return None  # 不进行自定义重定向


def custom_identity_verify(identity_dict):
    """
    Return True and False, if False, user's access will not be granted.
    An dict contains user's identity will be passed to this function.
       You can do some verification, for example, you can try to login to an internal site,
    if login succeed, you return True, otherwise False

    :type identity_dict: dict
    """
    true_or_false = True
    return true_or_false


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
    :param zmirror_verify_cookie: cookie string
    :param flask_request: the flask request object
    :type zmirror_verify_cookie: str
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
    from zmirror.zmirror import add_ssrf_allowed_domain, get_group

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
        _buff = ''
        for char in ascii_str:
            if char in '\'\"<>&=':
                _buff += r'\x' + hex(ord(char))[2:]
            else:
                _buff += char
        _buff = _buff.replace('\\', '\\\\')
        _buff = _buff.replace('/', r'\/')
        return _buff

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
