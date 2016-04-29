# coding=utf-8
from flask import Flask, request, make_response, Response
import requests
from urllib.parse import urljoin, urlsplit
from ColorfulPyPrint import *
import re

try:
    from custom_func import *
except:
    custom_text_filter_enable = False
    pass
from config import *

if cache_enable:
    from cache_system import FileCache, get_expire_from_mime

    cache = FileCache(max_size_kb=8192)

__VERSION__ = '0.8.5'
# if is_log_to_file:
#     from ColorfulPyPrint.extra_output_destination.file_logger import FileLogger
#
#     file_logger = FileLogger(log_file_path)
#     add_extra_output_destination(file_logger)
ColorfulPyPrint_set_verbose_level(verbose_level)
myurl_prefix = my_host_scheme + my_host_name
if not is_use_proxy:
    requests_proxies = None

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


def generate_error_page(errormsg=b'We Got An Unknown Error', error_code=500):
    return make_response(errormsg, error_code)


def generate_304_response(last_modified=None, content_type=None, is_cache_hit=None):
    r = Response(content_type=content_type, status=304)
    if last_modified:
        r.headers.add('Last-Modified', last_modified)
    if is_cache_hit:
        r.headers.add('X-Cache', 'FileHit-304')
    return r


def put_response_to_cache(url, our_resp, req, remote_resp):
    if cache_enable and req.method == 'GET' and remote_resp.status_code == 200:
        content_type = remote_resp.headers.get('content-type', '') or remote_resp.headers.get('Content-Type', '')
        last_modified = remote_resp.headers.get('last-modified', None) or remote_resp.headers.get('Last-Modified', None)
        cache.put_obj(
            url,
            our_resp,
            expires=get_expire_from_mime(content_type[:content_type.find(';')]),
            obj_size=len(remote_resp.content),
            last_modified=last_modified,
            info_dict={'content-type': content_type,
                       'last-modified': last_modified
                       },
        )


def try_get_cached_response(url, client_header):
    """

    :type client_header: dict
    """
    if cache_enable and request.method == 'GET' and cache.is_cached(url):
        if 'if-modified-since' in client_header and \
                cache.is_unchanged(url, client_header.get('if-modified-since', None)):
            cached_info = cache.get_info(url)
            dbgprint('FileCacheHit-304', cached_info, url)
            return generate_304_response(last_modified=cached_info.get('last_modified'),
                                         content_type=cached_info.get('content_type'))
        else:
            dbgprint('FileCacheHit-200')
            resp = cache.get_obj(url)
            assert isinstance(resp, Response)
            resp.headers.add('X-Cache', 'FileHit')
            return resp
    else:
        return None


def regex_url_rewrite(match_obj):
    def get_group(name):
        obj = match_obj.group(name)
        if obj is not None:
            return obj
        else:
            return ''

    # print(match_obj.string)
    # print(match_obj.groups(), '\n')
    path = urljoin(request.path, get_group('path'))
    domain = get_group('domain')
    if domain != '' and domain != target_domain and domain not in external_domains:
        return match_obj.group()  # return raw, do not change

    if domain in external_domains:
        path = urljoin('/extdomains/' + domain + '/', path.lstrip('/'))

    result = get_group('prefix') \
             + get_group('quote_left') \
             + my_host_scheme + CDN_domain.rstrip('/') \
             + path \
             + get_group('quote_right')
    # print(result, '\n')
    # print('\n', '\n')

    return result


# ########## End utils ###############


# ################# Begin Server Response Handler #################
def copy_response(requests_response_obj, content=b''):
    resp = make_response(content, requests_response_obj.status_code)
    assert isinstance(resp, Response)
    for header_key in requests_response_obj.headers:
        # Add necessary response headers from the origin site, drop other headers
        if header_key.lower() in (  # TODO: (Maybe) Add More Valid Response Headers
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
    dbgprint('RESPONSE HEADERS: \n', resp.headers)

    return resp


def response_cookies_deep_copy(req_obj):
    """
    It's a BAD hack to get RAW cookies headers, but so far, we don't have better way.
    We'd go DEEP inside the urllib's private method.

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
    raw_headers = req_obj.raw._original_response.headers._headers
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
    :return: byte
    """
    # Skip if response is binary
    content_mime = remote_resp_obj.headers.get('content-type', '') or remote_resp_obj.headers.get('Content-Type', '')
    content_mime = content_mime[:content_mime.find(';')]

    if content_mime and is_mime_represents_text(content_mime):
        dbgprint('Texture', content_mime, remote_resp_obj.text[:15], remote_resp_obj.content[:15])
        resp_text = response_text_rewrite(remote_resp_obj.text)
        try:
            if custom_text_rewriter_enable and content_mime == 'text/html':
                resp_text2 = custom_response_html_rewriter(resp_text)
                resp_text = resp_text2
        except Exception as e:
            errprint('Custom Rewrite Function "custom_response_html_rewriter(text)" in custom_func.py ERROR', e)

        return resp_text.encode(encoding='utf-8')
    else:
        dbgprint('Binary', content_mime)
        return remote_resp_obj.content


def response_text_rewrite(resp_text):  # TODO: rewrite external domain resource's "/foo/bar/blah" to "foo/bar/blah"
    # Main Domain Rewrite
    assert isinstance(resp_text, str)
    resp_text = re.sub(
        r"""(?P<prefix>href\s*=|src\s*=|url\s*\(|\s*:)""" +
        r"""(?P<quote_left>\s*["'])?""" +
        r"""(?P<domain_and_scheme>(https?:)?//(?P<domain>[^\s/$.?#]+?(\.[a-z]+)+?)/)?""" +
        r"""(?P<path>[^\s?#'"]*?""" +
        r"""\.(?P<ext>gif|jpe?g|png|js|css|ico|svg|webp|bmp|tif|woff|swf|mp3|wmv|wav)""" +
        r"""(?P<query_string>\?[^\s'"]*?)?)""" +
        r"""(?P<quote_right>["'\)])""",
        regex_url_rewrite,
        resp_text,
        flags=re.IGNORECASE
    )

    resp_text = re.sub(
        r'(https?:)?//' + target_domain.replace('.', r'\.') + '/',
        my_host_scheme + my_host_name + '/',
        resp_text, flags=re.IGNORECASE
    )

    # External Domains Rewrite
    for domain in external_domains:
        # Explicit HTTPS scheme must be kept
        resp_text = resp_text.replace('https://' + domain,
                                      myurl_prefix + '/extdomains/' + 'https-' + domain)
        # Implicit schemes replace
        resp_text = re.sub(
            r'(https?:)?//' + domain.replace('.', r'\.'),
            '{0}{1}/extdomains/{2}{3}'.format(my_host_scheme, my_host_name,
                                              ('https-' if ('NONE' != force_https_domains) and (
                                                  ('ALL' == force_https_domains) or (
                                                      domain in force_https_domains)
                                              ) else ''), domain),
            resp_text, flags=re.IGNORECASE
        )
        # rewrite "foo.domain.tld" and 'foo.domain.tld'
        resp_text = resp_text.replace('"%s"' % domain, my_host_name + '/extdomains/' + domain)
        resp_text = resp_text.replace("'%s'" % domain, my_host_name + '/extdomains/' + domain)

    return resp_text


def response_cookie_rewrite(cookie_string):
    cookie_string = re.sub(r'\bdomain=(\.?([\w-]+\.)+\w+)\b', 'domain=' + my_host_name, cookie_string)
    return cookie_string


# ################# End Server Response Handler #################


# ################# Begin Client Request Handler #################
def extract_client_header(income_request):
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
    replaced = re.sub(
        my_host_name.replace('.', r'\.')
        + r'(/|(%2F))extdomains(/|(%2F))(https-)?(?P<origin_domain>\.?([\w-]+\.)+\w+)\b',
        '\g<origin_domain>',
        raw_text, flags=re.IGNORECASE)
    replaced = replaced.replace(my_host_name, target_domain)
    if raw_text != replaced:
        dbgprint('ClientRequestedUrl: ', raw_text, '<- Has Been Rewrited To ->', replaced)
    return replaced


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
    if (final_hostname not in external_domains) and (final_hostname != target_domain):
        raise ConnectionAbortedError('Tried to access an OUT-OF-ZONE domain:', final_hostname)

    # set zero data to None instead of b''
    if not data:
        data = None

    # Send real requests
    r = requests.request(
        method, final_url,
        params=param_get, headers=headers, data=data,
        proxies=requests_proxies, allow_redirects=False
    )

    # Some debug output
    # print(r.request.headers, r.headers)
    dbgprint(r.request.method, "RemoteUrl:", r.url, "\nRemote Response Len: ", len(r.content),
             "\nRem Resp Stat: ", r.status_code)
    dbgprint("RemoteRequestHeaders: ", r.request.headers)
    if data:
        dbgprint('RemoteRequestRawData: ', r.request.body)
    dbgprint("RemoteResponseHeaders: ", r.headers)

    return r


# ################# End Middle Functions #################


# ################# Begin Flask #################
@app.route('/extdomains/<path:hostname>', methods=['GET', 'POST'])
@app.route('/extdomains/<path:hostname>/<path:extpath>', methods=['GET', 'POST'])
def get_external_site(hostname, extpath='/'):
    if hostname[0:6] == 'https-':
        scheme = 'https://'
        hostname = hostname[6:]
    else:
        scheme = 'http://'

    # Only external in-zone domains are allowed (SSRF check layer 1)
    if hostname.rstrip('/') not in external_domains:
        return generate_error_page(b'SSRF Prevention! Your Domain Are NOT ALLOWED.', 403)

    actual_get_url = urljoin(urljoin(scheme + hostname, extpath), '?' + urlsplit(request.url).query)
    client_header = extract_client_header(request)

    if cache_enable:
        resp = try_get_cached_response(actual_get_url, client_header)
        if resp is not None:
            return resp

    try:
        r = send_request(actual_get_url, method=request.method, headers=client_header, data=request.get_data())
    except Exception as e:
        errprint(e)
        return generate_error_page()
    else:
        resp = copy_response(r, response_content_rewrite(r))

        if cache_enable:
            put_response_to_cache(actual_get_url, resp, request, r)

    return resp


@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:input_path>', methods=['GET', 'POST'])
def hello_world(input_path='/'):
    dbgprint('Client Request Url: ', request.url)

    actual_get_url = urljoin(target_scheme + target_domain, extract_url_path_and_query(request.url))
    client_header = extract_client_header(request)

    if cache_enable:
        resp = try_get_cached_response(actual_get_url, client_header)
        if resp is not None:
            dbgprint('CacheHit,Return')
            return resp

    try:
        r = send_request(actual_get_url, method=request.method, headers=client_header, data=request.get_data())
    except Exception as e:
        errprint(e)
        return generate_error_page()
    else:
        resp = copy_response(r, response_content_rewrite(r))

        if cache_enable:
            put_response_to_cache(actual_get_url, resp, request, r)

    return resp


if __name__ == '__main__':
    app.run(debug=True, port=80, threaded=True)
