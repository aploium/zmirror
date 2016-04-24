# coding=utf-8
from flask import Flask, request, make_response
import requests
from urllib.parse import urljoin, urlsplit
import re
from ColorfulPyPrint import *
from _func import is_mime_represents_text

ColorfulPyPrint_set_verbose_level(4)


my_host_name = 'g.zju.tools'
my_host_scheme = 'http://'
target_domain = 'www.google.com'
target_scheme = 'https://'
external_domains = (
    'scholar.google.com',

    'ssl.gstatic.com',
    'www.gstatic.com',
    'apis.google.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'accounts.google.com',
    'accounts.youtube.com',
)
# 'ALL' for all, 'NONE' for none, ('foo.com','bar.com','www.blah.com') for custom
force_https_domains = 'ALL'

requests_proxies = dict(http="http://127.0.0.1:8123",
                        https="https://127.0.0.1:8123",
                        )
__VERSION__ = '0.7.0'
app = Flask(__name__)
myurl_prefix = my_host_scheme + my_host_name


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

def response_content_rewrite(request_response_obj):
    """
    Rewrite requests response's content's url. Auto skip binary (based on MIME).
    :type request_response_obj: requests.models.Response
    :param request_response_obj: requests response object
    :return: byte
    """
    # Skip if response is binary
    if is_mime_represents_text(request_response_obj.headers.get('Content-Type', '')):
        return response_text_rewrite(request_response_obj.text).encode(encoding='utf-8')
    else:
        return request_response_obj.content


def response_text_rewrite(resp_text):  # TODO: rewrite external domain resource's "/foo/bar/blah" to "foo/bar/blah"
    # Main Domain Rewrite
    assert isinstance(resp_text, str)
    resp_text = re.sub(
        r'(https?:)?//' + target_domain.replace('.', r'\.') + '/',  # TODO: Auto generate this
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


def extract_client_header(income_request):
    outgoing_head = {}
    dbgprint('ClientRequestHeaders:', income_request.headers)
    for head_name, head_value in income_request.headers:
        if head_name not in ('Host', 'Content-Length'):
            outgoing_head[head_name] = head_value

    # rewrite referer head if we have
    if 'Referer' in outgoing_head:
        outgoing_head['Referer'] = rewrite_client_requests_text(outgoing_head['Referer'])
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


def copy_response(requests_response_obj, content=b''):
    resp = make_response(content, requests_response_obj.status_code)

    for header_key in requests_response_obj.headers:
        # Add necessary response headers from the origin site, drop other headers
        if header_key in (  # TODO: (Maybe) Add More Valid Response Headers
                'Content-Type', 'Date', 'Expires', 'Cache-Control', 'Last-Modified', 'Server'):
            resp.headers[header_key] = requests_response_obj.headers[header_key]
        # Rewrite the redirection header if we got one, rewrite in-zone domains to our domain
        if 'Location' == header_key:
            resp.headers[header_key] = response_text_rewrite(requests_response_obj.headers[header_key])
        # Rewrite The Set-Cookie Header, change the cookie domain to our domain
        if 'Set-Cookie' == header_key:
            resp.headers[header_key] = response_cookie_rewrite(requests_response_obj.headers[header_key])
    dbgprint('RESPONSE HEADERS: \n', resp.headers)
    return resp


def generate_error_page(errormsg=b'We Got An Unknown Error', error_code=400):
    return make_response(errormsg, error_code)


@app.route('/extdomains/<path:hostname>', methods=['GET', 'POST'])
@app.route('/extdomains/<path:hostname>/<path:extpath>', methods=['GET', 'POST'])
def get_external_site(hostname, extpath='/'):  # TODO: Add POST support in external domains
    if hostname[0:6] == 'https-':
        scheme = 'https://'
        hostname = hostname[6:]
    else:
        scheme = 'http://'
    # Only external in-zone domains are allowed (SSRF check layer 1)
    if hostname not in external_domains:
        return generate_error_page(b'SSRF Prevention! Your Domain Are NOT ALLOWED.', 403)
    client_header = extract_client_header(request)
    actual_get_url = urljoin(urljoin(scheme + hostname, extpath), '?' + urlsplit(request.url).query)
    try:
        r = send_request(actual_get_url, method=request.method, headers=client_header, data=request.get_data())
    except Exception as e:
        errprint(e)
        return generate_error_page()
    else:
        return copy_response(r, response_content_rewrite(r))


@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:input_path>', methods=['GET', 'POST'])
def hello_world(input_path='/'):  # TODO: Add POST support in main domain
    dbgprint('Client Request Url: ', request.url)
    actual_get_url = urljoin(target_scheme + target_domain, extract_url_path_and_query(request.url))
    client_header = extract_client_header(request)
    try:
        r = send_request(actual_get_url, method=request.method, headers=client_header, data=request.get_data())
    except Exception as e:
        errprint(e)
        return generate_error_page()
    else:
        return copy_response(r, response_content_rewrite(r))


if __name__ == '__main__':
    app.run(debug=True, port=80, threaded=True)
