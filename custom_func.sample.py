# coding=utf-8
import re

# regex patton from @stephenhay, via https://mathiasbynens.be/demo/url-regex
REGEX_OF_URL = r'(https?|ftp):\/\/[^\s/$.?#].[^\s]*'


def custom_response_html_rewriter(raw_text):
    # replace UBB image to image tag
    # eg. from [upload=jpg]http://foo.bar/blah.jpg[/upload]
    #     to <img src="http://foo.bar/blah.jpg"></img>
    raw_text = re.sub(r'\[upload=[\w, ]+?\](?P<image_url>' + REGEX_OF_URL + r'?)\[/upload\]',
                      r'<img src="\g<image_url>"></img>',
                      raw_text)
    return raw_text
