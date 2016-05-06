# coding=utf-8
import re

# regex patton from @stephenhay, via https://mathiasbynens.be/demo/url-regex
REGEX_OF_URL = r'(https?|ftp):\/\/[^\s/$.?#].[^\s]*'
# pre compile an regex will enhance it's performance
regex_ubb_img_rewriter = re.compile(r'\[upload=[\w, ]+?\](?P<image_url>' + REGEX_OF_URL + r'?)\[/upload\]')


def custom_response_html_rewriter(raw_text):
    # replace UBB image to image tag
    # eg. from [upload=jpg]http://foo.bar/blah.jpg[/upload]
    #     to <img src="http://foo.bar/blah.jpg"></img>
    raw_text = regex_ubb_img_rewriter.sub(r'<img src="\g<image_url>" style="max-width: 100%;"></img>', raw_text)

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
