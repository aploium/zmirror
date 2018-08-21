# coding=utf-8
import re
from flask import Response, Request
from zmirror.zmirror import *

server_path = encode_mirror_url("https://venus.web.telegram.org/test").replace("venus.web.telegram.org/test", "");
regex_api_server = re.compile(r'(?<=return [a-z]\=\")https:\/\/(?=\"\+[a-z]\+\"\.web\.telegram\.org\/\"\+[a-z])');

def custom_response_text_rewriter(raw_text, content_mime, remote_url):
    if "app.js" in remote_url:
        raw_text = regex_api_server.sub(server_path, raw_text)

    return raw_text

