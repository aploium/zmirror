# coding=utf-8
import requests
import re
import config
from EasyWebsiteMirror import add_ssrf_allowed_domain, get_group

# regex patton from @stephenhay, via https://mathiasbynens.be/demo/url-regex
REGEX_OF_URL = r'(https?|ftp):\/\/[^\s/$.?#].[^\s]*'
# pre compile an regex will enhance it's performance
regex_ubb_img_rewriter = re.compile(r'\[upload=[\w, ]+?\](?P<image_url>' + REGEX_OF_URL + r'?)\[/upload\]')

# Example for Twitter
regex_twitter_data_expanded = re.compile(
    r'''data-expanded-url\s*=\s*'''
    '''"(?P<scheme>(https?:)?\\?/\\?/)(?P<domain>([-a-z0-9]+\.)+[a-z]+)(?P<path>[^\s;+?#'"]*?)"'''
    , flags=re.IGNORECASE)


# Example for Twitter
def handle_expand_url(mobj):
    domain = get_group('domain', mobj)
    if not domain:
        return mobj.group()
    add_ssrf_allowed_domain(domain)
    if 'https' in get_group('scheme', mobj) or config.force_https_domains == 'ALL':
        scheme_prefix = 'https-'
    else:
        scheme_prefix = ''

    return 'data-expanded-url="%s"' % ('/extdomains/' + scheme_prefix + domain + get_group('path', mobj))


def custom_response_html_rewriter(raw_text):
    # replace UBB image to image tag
    # eg. from [upload=jpg]http://foo.bar/blah.jpg[/upload]
    #     to <img src="http://foo.bar/blah.jpg"></img>
    raw_text = regex_ubb_img_rewriter.sub(r'<img src="\g<image_url>" style="max-width: 100%;"></img>', raw_text)

    # For twitter expand replace
    regex_twitter_data_expanded.sub(handle_expand_url, raw_text)

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


# just_another_demo_custom_identity_verify
def just_another_demo_custom_identity_verify(identity_dict):
    """
    For CC98 identity verify

    :type identity_dict: dict
    """
    import hashlib
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
