#!/usr/bin/env python3
# coding=utf-8
import os

os.chdir(os.path.dirname(__file__))
import requests
import traceback
from datetime import datetime, timedelta
import re
import base64
import zlib
from time import time
from html import escape as html_escape
from urllib.parse import urljoin, urlsplit
from flask import Flask, request, make_response, Response, redirect
from ColorfulPyPrint import *  # TODO: Migrate logging tools to the stdlib

try:
    from fastcache import lru_cache

    infoprint('lur_cache loaded from fastcache')
except:
    from functools import lru_cache

    warnprint('package fastcache not found, fallback to stdlib lru_cache.  '
              'Considering install it using "pip3 install fastcache"')
from config import *

if local_cache_enable:
    try:
        from cache_system import FileCache, get_expire_from_mime

        cache = FileCache(max_size_kb=8192)
    except Exception as e:
        errprint('Can Not Create Local File Cache: ', e, ' local file cache is disabled automatically.')
        local_cache_enable = False

__VERSION__ = '0.12.0-dev'
__author__ = 'Aploium <i@z.codes>'
static_file_extensions_list = set(static_file_extensions_list)
external_domains_set = set(external_domains or [])
allowed_domains_set = external_domains_set.copy()
allowed_domains_set.add(target_domain)
ColorfulPyPrint_set_verbose_level(verbose_level)
myurl_prefix = my_host_scheme + my_host_name
cdn_domains_number = len(CDN_domains)
if not is_use_proxy:
    requests_proxies = None
if human_ip_verification_enabled:
    import ipaddress

    buff = []
    for network in human_ip_verification_default_whitelist_networks:
        buff.append(ipaddress.ip_network(network, strict=False))
    human_ip_verification_default_whitelist_networks = tuple(buff)
    for question in human_ip_verification_questions:
        human_ip_verification_answers_hash_str += question[1]

url_rewrite_cache = {}

# PreCompile Regex
# Advanced url rewriter, see function response_text_rewrite()
regex_adv_url_rewriter = re.compile(
    r"""(?P<prefix>\b(href\s*=|src\s*=|url\s*\(|@import\s*)\s*)""" +  # prefix, eg: src=
    r"""(?P<quote_left>["'])?""" +  # quote  "'
    r"""(?P<domain_and_scheme>(https?:)?\?/\?/(?P<domain>([-a-z0-9]+\.)+[a-z]+))?""" +  # domain and scheme
    r"""(?P<path>[^\s;+?#'"]*?""" +  # full path(with query string)  /foo/bar.js?love=luciaZ
    r"""(\.(?P<ext>[-_a-z0-9]+?))?""" +  # file ext
    r"""(?P<query_string>\?[^\s?#'"]*?)?)""" +  # query string  ?love=luciaZ
    r"""(?P<quote_right>["'\)]\W)""",  # right quote  "'
    flags=re.IGNORECASE
)
# Basic url rewriter for target main site, see function response_text_rewrite()
regex_basic_main_url_rewriter = re.compile(
    r'(https?:)?//' + re.escape(target_domain) + '/',
    flags=re.IGNORECASE
)
# Basic url rewriter for external sites, see function response_text_rewrite()
regex_basic_ext_url_rewriter = {}
for _domain in external_domains:
    regex_basic_ext_url_rewriter[_domain] = re.compile(r'(https?:)?//' + re.escape(_domain), flags=re.IGNORECASE)
# Response Cookies Rewriter, see response_cookie_rewrite()
regex_cookie_rewriter = re.compile(r'\bdomain=(\.?([\w-]+\.)+\w+)\b', flags=re.IGNORECASE)
# Request Domains Rewriter, see rewrite_client_requests_text()
regex_request_rewriter = re.compile(
    re.escape(my_host_name) + r'(/|(%2F))extdomains(/|(%2F))(https-)?(?P<origin_domain>\.?([\w-]+\.)+\w+)\b',
    flags=re.IGNORECASE)

app = Flask(__name__)


# ###################### Functional Tests ####################### #
# 0. test environment
#    0.0 global search keyword: lovelive ,scholar keyword: gravity
#    0.1 Firefox/46.0 Windows/10 x64
#
# 1. www.google.com load  [OK]
#    1.0 basic [OK]
#    1.1  search hint [OK]
#
# 2. webpage search [OK]
#    2.0 basic [OK]
#    2.1 search result page 2,3 [OK]
#    2.2 search tools [OK]
#    2.3 result item click [OK]
#       2.3.0 basic [OK]
#       2.3.1 result item (left) click, with redirect [OK]
#       2.3.2 result item (right) click, with top banner [OK]
#    2.4 search item cache [Not Supported Yet]
#
# 3. image search [OK]
#    3.0 basic [OK]
#    3.1 all images lazy load [OK]
#    3.2 image detail banner [OK]
#       3.2.0 basic [OK]
#       3.2.1 HD lazy load [OK]
#       3.2.2 relative images show [OK]
#       3.2.3 relative images click/HD lazy load  [OK]
#       3.2.4 view image page [OK]
#       3.2.5 view raw image (ps: raw image may be blocked by GFW, thus NOT accessible) [OK]
#    3.3  scroll down lazy load [OK]
#
# 5. google scholar (/scholar)
#    5.0 basic [OK]
#    5.1 search (gravity) [OK]
#        5.1.0 basic [OK]
#        5.1.1 result item click and redirect [OK]
#        5.1.2 citations click [OK]
#        5.1.3 search filters ("Since year 2015") [OK]
#
# 6. video search (ps: DO NOT support youtube) [OK]
#    6.0 basic [OK]
#    6.1 video thumb show [OK]
#    6.2 result item click redirect [OK]
#    6.3 page 2,3 [OK]
#

# ########## Begin Utils #############
def set_request_for_debug(dummy_request):
    global request
    request = dummy_request


def strx(*args, sep=' '):
    output = ''
    for arg in args:
        output += str(arg) + sep
    output.rstrip(sep)
    return output


@lru_cache(maxsize=1024)
def check_global_ua_pass(ua_str):
    if ua_str is None:
        return False
    ua_str = ua_str.lower()
    if global_ua_white_name in ua_str:
        return True
    else:
        return False


@lru_cache(maxsize=128)
def is_mime_represents_text(input_mime):
    """
    Determine whether an mime is text (eg: text/html: True, image/png: False)
    :param input_mime: str
    :return: bool
    """
    for text_word in ('text', 'json', 'javascript', 'xml'):
        if text_word in input_mime:
            return True
    return False


def generate_simple_resp_page(errormsg=b'We Got An Unknown Error', error_code=500):
    return make_response(errormsg, error_code)


def generate_html_redirect_page(target_url, msg='', delay_sec=1):
    resp_content = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>重定向 (Page Redirect)</title>
<meta http-equiv="refresh" content="%d; url=%s">
<script>setTimeout(function(){location.href="%s"} , %d000);</script>
</head>
<body>
<pre>%s</pre>
<hr />
You are now redirecting to <a href="%s">%s</a>, if it didn't redirect automatically, please click that link.
</body>
</html>""" % (
        delay_sec, html_escape(target_url), html_escape(target_url), delay_sec + 1,
        html_escape(msg), html_escape(target_url), html_escape(target_url)
    )
    resp_content = resp_content.encode('utf-8')
    return Response(response=resp_content)


@lru_cache(maxsize=32)
def generate_304_response(content_type=None):
    r = Response(content_type=content_type, status=304)
    r.headers.add('X-Cache', 'FileHit-304')
    return r


def generate_ip_verify_hash(input_dict):
    strbuff = human_ip_verification_answers_hash_str
    for key in input_dict:
        strbuff += key + input_dict[key]
    input_key_hash = hex(zlib.adler32(strbuff.encode(encoding='utf-8')))[2:]
    output_hash = hex(zlib.adler32(
        (input_key_hash + human_ip_verification_answers_hash_str).encode(encoding='utf-8')
    ))[2:]
    return input_key_hash + output_hash


@lru_cache(maxsize=2048)
def verify_ip_hash_cookie(hash_cookie_value):
    """

    :type hash_cookie_value: str
    """
    try:
        input_key_hash = hash_cookie_value[:8]
        output_hash = hash_cookie_value[8:]
        calculated_hash = hex(zlib.adler32(
            (input_key_hash + human_ip_verification_answers_hash_str).encode(encoding='utf-8')
        ))[2:]
        if output_hash == calculated_hash:
            return True
        else:
            return False
    except:
        return False


def put_response_to_local_cache(url, our_resp, req, remote_resp):
    """
    put our response object(headers included) to local cache
    :param url: client request url
    :param our_resp: our response(flask response object) to client, would be storged
    :param req: the flask request object
    :param remote_resp: the requests request object (the one returned by send_request() )
    :return: None
    """
    # Only cache GET method, and only when remote returns 200(OK) status
    if local_cache_enable and req.method == 'GET' and remote_resp.status_code == 200:
        # the header's character cases are different in flask/apache(win)/apache(linux)
        content_type = remote_resp.headers.get('content-type', '') or remote_resp.headers.get('Content-Type', '')
        last_modified = remote_resp.headers.get('last-modified', None) or remote_resp.headers.get('Last-Modified', None)
        cache.put_obj(
            url,
            our_resp,
            expires=get_expire_from_mime(content_type[:content_type.find(';')]),
            obj_size=len(remote_resp.content),
            last_modified=last_modified,
            info_dict={'content-type': content_type,  # storge extra info for future use
                       'last-modified': last_modified
                       },
        )


def try_get_cached_response(url, client_header):
    """

    :type client_header: dict
    """
    # Only use cache when client use GET
    if local_cache_enable and request.method == 'GET' and cache.is_cached(url):
        if 'if-modified-since' in client_header and \
                cache.is_unchanged(url, client_header.get('if-modified-since', None)):
            cached_info = cache.get_info(url)
            dbgprint('FileCacheHit-304', cached_info, url)
            return generate_304_response()
        else:
            dbgprint('FileCacheHit-200')
            resp = cache.get_obj(url)
            assert isinstance(resp, Response)
            resp.headers.add('X-Cache', 'FileHit')
            return resp
    else:
        return None


def regex_url_reassemble(match_obj):
    """
    Reassemble url parts split by the regex.
    :param match_obj: match object of stdlib re
    :return: re assembled url string (included prefix(url= etc..) and suffix.)
    """
    if match_obj.group() in url_rewrite_cache:  # Read Cache
        return url_rewrite_cache[match_obj.group()]

    def get_group(name):  # return a blank string if the match group is None
        obj = match_obj.group(name)
        if obj is not None:
            return obj
        else:
            return ''

    prefix = get_group('prefix')
    quote_left = get_group('quote_left')
    quote_right = get_group('quote_right')
    path = get_group('path')
    match_domain = get_group('domain')
    # path must be not blank
    if not path \
            or ('src' in prefix or 'href' in prefix) \
                    and (not quote_left or quote_right == ')'):  # url after src and href must be ' or " quoted
        return match_obj.group()

    remote_path = request.path
    if request.path[:11] == '/extdomains':
        remote_path_raw = request.path[12:]
        find_pos = remote_path_raw.find('/')
        remote_path = remote_path_raw[find_pos:]
        remote_domain = remote_path_raw[:find_pos]
        if remote_domain[:6] == 'https-':
            remote_domain = remote_domain[6:]
    else:
        remote_domain = target_domain
    # dbgprint('remote_path:', remote_path, 'remote_domain:', remote_domain, v=5)

    domain = match_domain or remote_domain
    # dbgprint('rewrite match_obj:', match_obj, 'domain:', domain, v=5)
    # skip if the domain are not in our proxy list
    if domain not in allowed_domains_set:
        return match_obj.group()  # return raw, do not change

    # this resource's absolute url path to the domain root.
    # dbgprint('match path', path, v=5)
    path = urljoin(remote_path, path)
    # dbgprint('middle path', path, v=5)
    # add extdomains prefix in path if need
    if domain in external_domains_set:
        if force_https_domains != 'NONE' and (force_https_domains == 'ALL' or domain in force_https_domains):
            scheme_prefix = 'https-'
        else:
            scheme_prefix = ''
        path = urljoin('/extdomains/' + scheme_prefix + domain + '/', path.lstrip('/'))
    # dbgprint('final_path', path, v=5)
    if enable_static_resource_CDN and get_group('ext') in static_file_extensions_list:
        # pick an cdn domain due to the length of url path
        # an advantage of choose like this (not randomly), is this can make higher CDN cache hit rate.

        # CDN rewrite, rewrite static resources to cdn domains.
        # A lot of cases included, the followings are just the most typical examples.
        # http(s)://target.com/img/love_lucia.jpg --> http(s)://your.cdn.domains.com/img/love_lucia.jpg
        # http://external.com/css/main.css --> http(s)://your.cdn.domains.com/extdomains/external.com/css/main.css
        # https://external.pw/css/main.css --> http(s)://your.cdn.domains.com/extdomains/https-external.pw/css/main.css
        replace_to_scheme_domain = my_host_scheme + CDN_domains[len(path) % cdn_domains_number]
    else:
        replace_to_scheme_domain = ''

    # reassemble!
    # prefix: src=  quote_left: "
    # path: /extdomains/target.com/foo/bar.js?love=luciaZ
    reassembled = prefix + quote_left \
                  + urljoin(replace_to_scheme_domain, path) \
                  + quote_right

    url_rewrite_cache[match_obj.group()] = reassembled  # write cache

    return reassembled


@lru_cache(maxsize=1024)
def is_denied_because_of_spider(ua_str):
    ua_str = ua_str.lower()
    if 'spider' in ua_str or 'bot' in ua_str:
        for allowed_ua in spider_ua_white_list:
            if allowed_ua in ua_str:
                dbgprint('A Spider/Bot', ua_str, ' was permitted because of white list:', allowed_ua)
                return False
        dbgprint('A Spider/Bot was denied, UA is:', ua_str)
        return True
    else:
        return False


def load_ip_whitelist_file():
    set_buff = set([])
    if os.path.exists(human_ip_verification_whitelist_file_path):
        with open(human_ip_verification_whitelist_file_path, 'r', encoding='utf-8') as fp:
            set_buff.add(fp.readline().strip())
    return set_buff


def append_ip_whitelist_file(ip_to_allow):
    try:
        with open(human_ip_verification_whitelist_file_path, 'a', encoding='utf-8') as fp:
            fp.write(ip_to_allow + '\n')
    except:
        errprint('Unable to write whitelist file')
        traceback.print_exc()


def ip_whitelist_add(ip_to_allow, info_record_dict=None):
    if ip_to_allow in single_ip_allowed_set:
        return
    dbgprint('ip white added', ip_to_allow, 'info:', info_record_dict)
    single_ip_allowed_set.add(ip_to_allow)
    append_ip_whitelist_file(ip_to_allow)
    # dbgprint(single_ip_allowed_set)
    try:
        with open(human_ip_verification_whitelist_log, 'a', encoding='utf-8') as fp:
            fp.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " " + ip_to_allow
                     + " " + str(request.user_agent)
                     + " " + repr(info_record_dict) + "\n")
    except:
        errprint('Unable to write log file', os.path.abspath(human_ip_verification_whitelist_log))
        traceback.print_exc()


@lru_cache(maxsize=256)
def is_ip_not_in_allow_range(ip_address):
    if ip_address in single_ip_allowed_set:
        return False
    ip_address_obj = ipaddress.ip_address(ip_address)
    for allowed_network in human_ip_verification_default_whitelist_networks:
        if ip_address_obj in allowed_network:
            return False
    return True


# ########## End utils ###############


# ################# Begin Server Response Handler #################
def copy_response(requests_response_obj, content=b''):
    """
    Copy and parse remote server's response headers, generate our flask response object

    :param requests_response_obj: remote server's response, requests' response object (only headers and status are used)
    :param content: pre-rewrited response content, bytes
    :return: flask response object
    """
    resp = make_response(content, requests_response_obj.status_code)
    assert isinstance(resp, Response)
    for header_key in requests_response_obj.headers:
        # Add necessary response headers from the origin site, drop other headers
        if header_key.lower() in (
                'content-type', 'date', 'expires', 'cache-control', 'last-modified', 'server'):
            resp.headers[header_key] = requests_response_obj.headers[header_key]
        # Rewrite the redirection header if we got one, rewrite in-zone domains to our domain
        if header_key.lower() == 'location':
            resp.headers[header_key] = response_text_rewrite(requests_response_obj.headers[header_key])
        # Rewrite The Set-Cookie Header, change the cookie domain to our domain
        if header_key.lower() == 'set-cookie':
            # cookie_header_str = dump_cookie_jars_to_header_string_dict(requests_response_obj.cookies)
            for cookie_string in response_cookies_deep_copy(requests_response_obj):
                resp.headers.add('Set-Cookie', response_cookie_rewrite(cookie_string))
                # resp.headers[header_key] = response_cookie_rewrite(requests_response_obj.headers[header_key])
    dbgprint('OurRespHeaders:\n', resp.headers)

    return resp


def response_cookies_deep_copy(req_obj):
    """
    It's a BAD hack to get RAW cookies headers, but so far, we don't have better way.
    We'd go DEEP inside the urllib's private method to get raw headers

    raw_headers example:
    [('Cache-Control', 'private'),
    ('Content-Length', '48234'),
    ('Content-Type', 'text/html; Charset=utf-8'),
    ('Server', 'Microsoft-IIS/8.5'),
    ('Set-Cookie','BoardList=BoardID=Show; expires=Mon, 02-May-2016 16:00:00 GMT; path=/'),
    ('Set-Cookie','aspsky=abcefgh; expires=Sun, 24-Apr-2016 16:00:00 GMT; path=/; HttpOnly'),
    ('Set-Cookie', 'ASPSESSIONIDSCSSDSSQ=OGKMLAHDHBFDJCDMGBOAGOMJ; path=/'),
    ('X-Powered-By', 'ASP.NET'),
    ('Date', 'Tue, 26 Apr 2016 12:32:40 GMT')]

    :type req_obj: requests.models.Response
    """
    raw_headers = req_obj.raw._original_response.headers._headers  # PyCharm may raise an warning to this line
    header_cookies_string_list = []
    for name, value in raw_headers:
        if name.lower() == 'set-cookie':
            header_cookies_string_list.append(value)
    return header_cookies_string_list


def response_content_rewrite(remote_resp_obj):
    """
    Rewrite requests response's content's url. Auto skip binary (based on MIME).
    :type remote_resp_obj: requests.models.Response
    :param remote_resp_obj: requests response object
    :return: bytes
    """
    # Skip if response is binary
    content_mime = remote_resp_obj.headers.get('content-type', '') or remote_resp_obj.headers.get('Content-Type', '')
    content_mime = content_mime[:content_mime.find(';')]

    if content_mime and is_mime_represents_text(content_mime):
        # Do text rewrite if remote response is text-like (html, css, js, xml, etc..)
        dbgprint('Text-like', content_mime, remote_resp_obj.text[:15], remote_resp_obj.content[:15])

        # simply copy the raw text, for custom rewriter function first.
        resp_text = remote_resp_obj.text
        # try to apply custom rewrite function if we got an html
        try:
            if custom_text_rewriter_enable and content_mime == 'text/html':
                resp_text2 = custom_response_html_rewriter(resp_text)
                resp_text = resp_text2
        except Exception as e:  # just print err and fallback to normal rewrite
            errprint('Custom Rewrite Function "custom_response_html_rewriter(text)" in custom_func.py ERROR', e)
            traceback.print_exc()

        # then do the normal rewrites
        try:
            resp_text = response_text_rewrite(resp_text)
        except:
            traceback.print_exc()

        return resp_text.encode(encoding='utf-8')  # return bytes
    else:
        # simply don't touch binary response content
        dbgprint('Binary', content_mime)
        return remote_resp_obj.content


def response_text_rewrite(resp_text):
    """
    rewrite urls in text-like content (html,css,js)
    :type resp_text: str
    """

    # v0.9.2+: advanced url rewrite engine (based on previously CDN rewriter)
    resp_text = regex_adv_url_rewriter.sub(regex_url_reassemble, resp_text)

    # basic url rewrite, rewrite the main site's url
    # http(s)://target.com/foo/bar --> http(s)://your-domain.com/foo/bar
    resp_text = regex_basic_main_url_rewriter.sub(myurl_prefix + '/', resp_text)

    # External Domains Rewrite
    # http://external.com/foo1/bar2 --> http(s)://your-domain.com/extdomains/external.com/foo1/bar2
    # https://external.com/foo1/bar2 --> http(s)://your-domain.com/extdomains/https-external.com/foo1/bar2
    for domain in external_domains:
        # Explicit HTTPS scheme must be kept
        resp_text = resp_text.replace('https://' + domain,
                                      myurl_prefix + '/extdomains/' + 'https-' + domain)
        # Implicit schemes replace, will be replaced to the same as `my_host_scheme`, unless forced
        resp_text = regex_basic_ext_url_rewriter[domain].sub(
            '{0}{1}/extdomains/{2}{3}'.format(my_host_scheme, my_host_name,
                                              ('https-' if ('NONE' != force_https_domains) and (
                                                  ('ALL' == force_https_domains) or (
                                                      domain in force_https_domains)
                                              ) else ''), domain),
            resp_text
        )

        # rewrite "foo.domain.tld" and 'foo.domain.tld'
        resp_text = resp_text.replace('"%s"' % domain, '\"' + my_host_name + '/extdomains/' + domain + '\"')
        resp_text = resp_text.replace("'%s'" % domain, "\'" + my_host_name + '/extdomains/' + domain + "\'")

    return resp_text


def response_cookie_rewrite(cookie_string):
    """
    rewrite response cookie string's domain to `my_host_name`
    :type cookie_string: str
    """
    cookie_string = regex_cookie_rewriter.sub('domain=' + my_host_name, cookie_string)
    return cookie_string


# ################# End Server Response Handler #################


# ################# Begin Client Request Handler #################
def extract_client_header(income_request):
    """
    Extract necessary client header, filter out some.
    :param income_request: flask request object
    :return: dict client request headers
    """
    outgoing_head = {}
    dbgprint('ClientRequestHeaders:', income_request.headers)
    for head_name, head_value in income_request.headers:
        head_name_l = head_name.lower()
        if (head_name_l not in ('host', 'content-length', 'content-type')) \
                or (head_name_l == 'content-type' and head_value != ''):
            outgoing_head[head_name_l] = head_value

    # rewrite referer head if we have
    if 'referer' in outgoing_head:
        outgoing_head['referer'] = rewrite_client_requests_text(outgoing_head['referer'])
    dbgprint('FilteredRequestHeaders:', outgoing_head)
    return outgoing_head


@lru_cache(maxsize=2048)
def rewrite_client_requests_text(raw_text):
    """
    Rewrite proxy domain to origin domain, extdomains supported.
    Also Support urlencoded url.
    This usually used in rewriting request params

    eg. http://foo.bar/extdomains/https-accounts.google.com to http://accounts.google.com
    eg2. foo.bar/foobar to www.google.com/foobar
    eg3. http%3a%2f%2fg.zju.tools%2fextdomains%2Fhttps-accounts.google.com%2f233
            to http%3a%2f%2faccounts.google.com%2f233
    """
    replaced = regex_request_rewriter.sub('\g<origin_domain>', raw_text)
    replaced = replaced.replace(my_host_name, target_domain)
    if raw_text != replaced:
        dbgprint('ClientRequestedUrl: ', raw_text, '<- Has Been Rewrited To ->', replaced)
    return replaced


@lru_cache(maxsize=4096)
def extract_url_path_and_query(full_url):
    """
    Convert http://foo.bar.com/aaa/p.html?x=y to /aaa/p.html?x=y

    :type full_url: str
    :param full_url: full url
    :return: str
    """
    split = urlsplit(full_url)
    result = split.path
    if split.query:
        result += '?' + split.query
    return result


# ################# End Client Request Handler #################


# ################# Begin Middle Functions #################
def send_request(url, method='GET', headers=None, param_get=None, data=None):
    final_url = rewrite_client_requests_text(url)
    final_hostname = urlsplit(final_url).hostname
    # Only external in-zone domains are allowed (SSRF check layer 2)
    if final_hostname not in allowed_domains_set:
        raise ConnectionAbortedError('Tried to access an OUT-OF-ZONE domain:', final_hostname)

    # set zero data to None instead of b''
    if not data:
        data = None

    # Send real requests
    req_start_time = time()
    r = requests.request(
        method, final_url,
        params=param_get, headers=headers, data=data,
        proxies=requests_proxies, allow_redirects=False
    )
    req_time = time() - req_start_time

    # Some debug output
    # print(r.request.headers, r.headers)
    dbgprint(r.request.method, "RemoteUrl:", r.url, "\nRemote Response Len: ", len(r.content),
             "\nRem Resp Stat: ", r.status_code)
    dbgprint("RemoteRequestHeaders: ", r.request.headers)
    if data:
        dbgprint('RemoteRequestRawData: ', r.request.body)
    dbgprint("RemoteResponseHeaders: ", r.headers)

    return r, req_time


def request_remote_site_and_parse(actual_request_url, start_time=None):
    client_header = extract_client_header(request)

    if local_cache_enable:
        resp = try_get_cached_response(actual_request_url, client_header)
        if resp is not None:
            dbgprint('CacheHit,Return')
            if start_time is not None:
                resp.headers.set('X-CP-Time', "%.4f" % (time() - start_time))
            return resp  # If cache hit, just skip next steps

    try:  # send request to remote server
        r, req_time = send_request(actual_request_url, method=request.method, headers=client_header,
                                   data=request.get_data())
    except Exception as e:
        errprint(e)
        traceback.print_exc()
        return generate_simple_resp_page()
    else:
        # copy and parse remote response
        resp = copy_response(r, response_content_rewrite(r))

        if local_cache_enable:  # storge entire our server's response (headers included)
            put_response_to_local_cache(actual_request_url, resp, request, r)
    if start_time is not None:
        resp.headers.add('X-CP-Time', "%.4f" % (time() - start_time - req_time))
    return resp


def filter_client_request():
    dbgprint('Client Request Url: ', request.url)
    # Global whitelist ua
    if check_global_ua_pass(str(request.user_agent)):
        return None

    if is_deny_spiders_by_403 and is_denied_because_of_spider(str(request.user_agent)):
        return generate_simple_resp_page(b'Spiders Are Not Allowed To This Site', 403)

    if human_ip_verification_enabled and ((human_ip_verification_whitelist_from_cookies and must_verify_cookies)
                                          or is_ip_not_in_allow_range(request.remote_addr)):
        if human_ip_verification_whitelist_from_cookies and 'ewm_ip_verify' in request.cookies \
                and verify_ip_hash_cookie(request.cookies.get('ewm_ip_verify')):
            ip_whitelist_add(request.remote_addr, info_record_dict=request.cookies.get('ewm_ip_verify'))
        else:
            return redirect(
                "/ip_ban_verify_page?origin="
                + base64.urlsafe_b64encode(str(request.url).encode(encoding='utf-8')).decode()
                , code=302)

    if url_custom_redirect_enable:
        if request.path in url_custom_redirect_list:
            redirect_to = request.url.replace(request.path, url_custom_redirect_list[request.path])
            dbgprint('Redirect from', request.url, 'to', redirect_to)
            return redirect(redirect_to, code=302)

        for regex_match, regex_replace in url_custom_redirect_regex:
            if re.match(regex_match, request.path, flags=re.IGNORECASE) is not None:
                redirect_to = re.sub(regex_match, regex_replace, request.path, flags=re.IGNORECASE)
                dbgprint('Redirect from', request.url, 'to', redirect_to)
                return redirect(redirect_to, code=302)

    return None


# ################# End Middle Functions #################


# ################# Begin Flask #################
@app.route('/ewm_stat')
def ewm_status():
    if request.remote_addr != '127.0.0.1':
        return generate_simple_resp_page(b'Only 127.0.0.1 are allowed', 403)
    output = ""
    output += strx('is_mime_represents_text', is_mime_represents_text.cache_info())
    output += strx('\ngenerate_304_response', generate_304_response.cache_info())
    output += strx('\nverify_ip_hash_cookie', verify_ip_hash_cookie.cache_info())
    output += strx('\nis_denied_because_of_spider', is_denied_because_of_spider.cache_info())
    output += strx('\nis_ip_not_in_allow_range', is_ip_not_in_allow_range.cache_info())
    output += strx('\nrewrite_client_requests_text', rewrite_client_requests_text.cache_info())
    output += strx('\nextract_url_path_and_query', extract_url_path_and_query.cache_info())
    output += strx('\nurl_rewriter_cache len: ', len(url_rewrite_cache))
    return "<pre>" + output + "</pre>\n"


@app.route('/ip_ban_verify_page', methods=['GET', 'POST'])
def ip_ban_verify_page():
    if request.method == 'GET':
        dbgprint('Verifying IP:', request.remote_addr)
        form_body = ''
        for q_id, _question in enumerate(human_ip_verification_questions):
            form_body += r"""%s <input type="text" name="%d" /><br/>""" % (html_escape(_question[0]), q_id)

        for rec_explain_string, rec_name, input_type in human_ip_verification_identity_record:
            form_body += r"""%s <input type="%s" name="%s" /><br/>""" % (
                html_escape(rec_explain_string), html_escape(input_type), html_escape(rec_name))

        if 'origin' in request.args:
            form_body += r"""<input type="hidden" name="origin" value="%s" />""" % html_escape(
                request.args.get('origin'))

        return r"""<!doctype html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <title>%s</title>
        </head>
        <body>
          <h1>%s</h1>
          <p>这样的验证只会出现一次，通过后您会被加入白名单，之后相同设备的访问不会再需要验证。<br/>
          提示: 由于手机和宽带IP经常会发生改变，您可能会多次看到这一页面。</p>
          <pre style="border: 1px dashed;">%s</pre>
          <form method='post'>%s<button type='submit'>递交</button>
          </form>
        </body>
        </html>""" % (
            html_escape(human_ip_verification_title), html_escape(human_ip_verification_title),
            html_escape(human_ip_verification_description), form_body)

    elif request.method == 'POST':
        for q_id, _question in enumerate(human_ip_verification_questions):
            if request.form.get(str(q_id)) != _question[1]:
                return generate_simple_resp_page(b'You Got An Error In ' + _question[0].encode(), 200)

        record_dict = {}
        for rec_explain_string, rec_name, form_type in human_ip_verification_identity_record:
            if rec_name not in request.form:
                return generate_simple_resp_page(b'Param Missing: ' + rec_explain_string.encode(), 200)
            else:
                record_dict[rec_name] = request.form.get(rec_name)
        origin = '/'
        if 'origin' in request.form:
            try:
                origin = base64.urlsafe_b64decode(request.form.get('origin')).decode(encoding='utf-8')
            except:
                pass
            else:
                netloc = urlsplit(origin).netloc
                if not netloc and netloc != my_host_name:
                    origin = '/'
        resp = generate_html_redirect_page(origin, msg=human_ip_verification_success_msg)

        if identity_verify_required:
            if not custom_identity_verify(record_dict):
                return generate_simple_resp_page(b'Verification Failed, please check', 200)

        if human_ip_verification_whitelist_from_cookies:
            _hash = generate_ip_verify_hash(record_dict)
            resp.set_cookie(
                'ewm_ip_verify',
                _hash,
                expires=datetime.now() + timedelta(days=human_ip_verification_whitelist_cookies_expires_days),
                # httponly=True,
                # domain=my_host_name
            )
            record_dict['__ewm_ip_verify'] = _hash

        ip_whitelist_add(request.remote_addr, info_record_dict=record_dict)
        return resp


@app.route('/extdomains/<path:hostname>', methods=['GET', 'POST'])
@app.route('/extdomains/<path:hostname>/<path:extpath>', methods=['GET', 'POST'])
def get_external_site(hostname, extpath='/'):
    start_time = time()  # to display compute time
    # pre-filter client's request.
    filter_result = filter_client_request()
    if filter_result is not None:
        return filter_result  # Ban or redirect if need

    # if /extdomains/https-**** means server should use https method to request the remote site.
    if hostname[0:6] == 'https-':
        scheme = 'https://'
        hostname = hostname[6:]
    else:
        scheme = 'http://'

    # Only external in-zone domains are allowed (SSRF check layer 1)
    if hostname.rstrip('/') not in allowed_domains_set:
        return generate_simple_resp_page(b'SSRF Prevention! Your Domain Are NOT ALLOWED.', 403)
    actual_request_url = urljoin(urljoin(scheme + hostname, extpath), '?' + urlsplit(request.url).query)

    return request_remote_site_and_parse(actual_request_url, start_time)


@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:input_path>', methods=['GET', 'POST'])
def get_main_site(input_path='/'):
    start_time = time()  # to display compute time
    # pre-filter client's request.
    filter_result = filter_client_request()
    if filter_result is not None:
        return filter_result  # Ban or redirect if need

    actual_request_url = urljoin(target_scheme + target_domain, extract_url_path_and_query(request.url))

    return request_remote_site_and_parse(actual_request_url, start_time)


# ################# End Flask #################

# ################# Begin Post (auto)Exec Section #################
if human_ip_verification_enabled:
    single_ip_allowed_set = load_ip_whitelist_file()
try:
    from custom_func import custom_response_html_rewriter
except:
    identity_verify_required = False
    warnprint('Cannot import custom_response_html_rewriter custom_func.py,'
              ' `custom_text_rewriter` is now disabled(if it was enabled)')
    traceback.print_exc()
    pass

try:
    from custom_func import custom_identity_verify
except:
    identity_verify_required = False
    warnprint('Cannot import custom_identity_verify from custom_func.py,'
              ' `identity_verify` is now disabled (if it was enabled)')
    traceback.print_exc()
    pass
# ################# End Post (auto)Exec Section #################

if __name__ == '__main__':
    app.run(debug=True, port=80, threaded=True)
