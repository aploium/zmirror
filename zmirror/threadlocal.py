# coding=utf-8
import threading
import requests

try:
    from typing import Dict, Union, Tuple
except:  # pragma: no cover
    pass


class ZmirrorThreadLocal(threading.local):
    """
    由于Python内置thread-local对代码补全的提示非常不友好, 所以自己继承一个

    如果不知道什么是thread-local, 请看 http://tinyurl.com/hqgb2r8

    本类在 zmirror 中被实例化为变量 parse
    这个变量的重要性不亚于 request, 在 zmirror 各个部分都会用到

    其各个变量的含义如下:
    parse.time                记录请求过程中的各种时间点
         .method              请求的方法, 如 GET POST
         .remote_domain       当前请求对应的远程域名
         .is_external_domain  远程域名是否是外部域名, 比如google镜像, www.gstatic.com 就是外部域名
         .is_https            是否需要用https 来请求远程域名
         .remote_url          远程服务器的url, 比如 https://google.com/search?q=233
         .url_no_scheme       没有协议前缀的url,比如 google.com/search?q=233 通常在缓存中用
         .remote_path_query   对应的远程path+query, 比如 /search?q=2333
         .remote_path         对应的远程path,  比如 /search
         .client_header       经过转换和重写以后的访问者请求头
         .content_type        远程服务器响应头中的 content_type, 比如 "text/plain; encoding=utf-8"
         .mime                远程服务器响应的MIME, 比如 "text/html"
         .request_data        浏览器传入的data(已经经过重写) 可能为str或bytes或None
         .request_data_encoding 浏览器传入的data的编码(如果有) 如果为二进制或编码未知, 则为None
         .request_data_encoded  编码后的二进制 request_data, 只读
         .cache_control       远程服务器响应的cache_control内容
         .remote_response     远程服务器的响应, requests.Response
         .cacheable           是否可以对这一响应应用缓存 (CDN也算是缓存的一种, 依赖于此选项)
         .extra_resp_headers  发送给浏览器的额外响应头 (比如一些调试信息什么的)
         .extra_cookies       额外的cookies, 在目前版本只能添加, 不能覆盖已有cookie
         .streamed_our_response  是否以 stream 模式向浏览器传送这个响应
         .temporary_domain_alias 用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项

    本类的方法:
        .dump()                   dump所有信息到dict
        .set_extra_resp_header()  设置一个响应头, 会发送给访问者, 会在内部操作 self.extra_resp_headers
        .set_cookie()             添加一个cookie 会在内部操作 self.extra_cookies, 目前版本只能添加新的cookie, 不能覆盖已有cookie

    """

    def __init__(self):
        self.init()

    def init(self):
        # 初始化成空白值
        self.method = None
        self.remote_domain = None
        self.is_external_domain = None
        self.is_https = None
        self.remote_url = None
        self.url_no_scheme = None
        self.remote_path_query = None
        self.client_header = None
        self.content_type = None
        self.remote_path = None
        self.mime = None
        self.cache_control = None
        self.remote_response = None
        self.streamed_our_response = False
        self.cacheable = False
        self.request_data = None
        self.request_data_encoding = None
        self.time = {}
        self.extra_resp_headers = {}
        self.temporary_domain_alias = []
        self.extra_cookies = {}

    def dump(self):
        return {
            "time": self.time,
            "method": self.method,
            "remote_domain": self.remote_domain,
            "is_external_domain": self.is_external_domain,
            "is_https": self.is_https,
            "remote_url": self.remote_url,
            "url_no_scheme": self.url_no_scheme,
            "remote_path_query": self.remote_path_query,
            "client_header": self.client_header,
            "content_type": self.content_type,
            "remote_path": self.remote_path,
            "mime": self.mime,
            "cache_control": self.cache_control,
            "temporary_domain_alias": self.temporary_domain_alias,
            "remote_response": self.remote_response,
            "streamed_our_response": self.streamed_our_response,
            "cacheable": self.cacheable,
            "extra_resp_headers": self.extra_resp_headers,
            "extra_cookies": self.extra_cookies,
            "request_data": self.request_data,
            "request_data_encoding": self.request_data_encoding,
        }

    def __str__(self):
        return str(self.dump())

    def set_extra_resp_header(self, name, value):
        """
        :type name: str
        :type value: str
        """
        h = self.extra_resp_headers
        h[name] = value
        self.extra_resp_headers = h

    def set_cookies(self, name, value, ttl=12 * 35 * 24 * 60 * 60, path='/'):
        """
        :param ttl: cookie有效时间, 秒
        :type ttl: int
        :type path: str
        :type name:  str
        :type value:  str
        """
        from http.cookies import SimpleCookie
        c = SimpleCookie()
        c[name] = value
        c[name]["path"] = path
        c[name]["expires"] = ttl

        self.extra_cookies[name] = c[name].OutputString()

    @property
    def remote_domain(self):
        """
        当前请求对应的远程域名
        :rtype: str
        """
        return self.__getattribute__("_remote_domain")

    @remote_domain.setter
    def remote_domain(self, value):
        """:type value: str"""
        self.__setattr__("_remote_domain", value)

    @property
    def is_external_domain(self):
        """
        远程域名是否是外部域名, 比如google镜像, www.gstatic.com 就是外部域名
        :rtype: bool
        """
        return self.__getattribute__("_is_external_domain")

    @is_external_domain.setter
    def is_external_domain(self, value):
        """:type value: bool"""
        self.__setattr__("_is_external_domain", value)

    @property
    def is_https(self):
        """
        是否需要用https 来请求远程域名
        :rtype: bool
        """
        return self.__getattribute__("_is_https")

    @is_https.setter
    def is_https(self, value):
        """:type value: bool"""
        self.__setattr__("_is_https", value)

    @property
    def method(self):
        """
        请求的方法
        :rtype: str
        """
        return self.__getattribute__("_method")

    @method.setter
    def method(self, value):
        """:type value: str"""
        self.__setattr__("_method", value)

    @property
    def remote_url(self):
        """
        远程服务器的url, 比如 https://google.com/search?q=233
        :rtype: str
        """
        return self.__getattribute__("_remote_url")

    @remote_url.setter
    def remote_url(self, value):
        """:type value: str"""
        self.__setattr__("_remote_url", value)

    @property
    def url_no_scheme(self):
        """
        没有协议前缀的url,比如 google.com/search?q=233 通常在缓存中用
        :rtype: str
        """
        return self.__getattribute__("_url_no_scheme")

    @url_no_scheme.setter
    def url_no_scheme(self, value):
        """:type value: str"""
        self.__setattr__("_url_no_scheme", value)

    @property
    def remote_path_query(self):
        """
        对应的远程path+query, 比如 /search?q=2333
        :rtype: str
        """
        return self.__getattribute__("_remote_path_query")

    @remote_path_query.setter
    def remote_path_query(self, value):
        """:type value: str"""
        self.__setattr__("_remote_path_query", value)

    @property
    def remote_path(self):
        """
        对应的远程path,  比如 /search
        :rtype: str
        """
        return self.__getattribute__("_remote_path")

    @remote_path.setter
    def remote_path(self, value):
        """:type value: str"""
        self.__setattr__("_remote_path", value)

    @property
    def client_header(self):
        """
        经过转换和重写以后的访问者请求头
        :rtype: dict[str, str]
        """
        return self.__getattribute__("_client_header")

    @client_header.setter
    def client_header(self, value):
        """:type value: dict[str, str]"""
        self.__setattr__("_client_header", value)

    @property
    def content_type(self):
        """
        远程服务器响应头中的 content_type, 比如 "text/plain; encoding=utf-8"
        :rtype: str
        """
        return self.__getattribute__("_content_type")

    @content_type.setter
    def content_type(self, value):
        """:type value: str"""
        self.__setattr__("_content_type", value)

    @property
    def mime(self):
        """
        远程服务器响应的MIME, 比如 "text/html"
        :rtype: str
        """
        return self.__getattribute__("_mime")

    @mime.setter
    def mime(self, value):
        """:type value: str"""
        self.__setattr__("_mime", value)

    @property
    def cache_control(self):
        """
        远程服务器响应的cache_control内容
        :rtype: str
        """
        return self.__getattribute__("_cache_control")

    @cache_control.setter
    def cache_control(self, value):
        """:type value: str"""
        self.__setattr__("_cache_control", value)

    @property
    def remote_response(self):
        """
        远程服务器的响应, 对象, requests.Response
        :rtype: requests.Response
        """
        return self.__getattribute__("_remote_response")

    @remote_response.setter
    def remote_response(self, value):
        """:type value: requests.Response"""
        self.__setattr__("_remote_response", value)

    @property
    def temporary_domain_alias(self):
        """
        用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项
        :rtype: list
        """
        return self.__getattribute__("_temporary_domain_alias")

    @temporary_domain_alias.setter
    def temporary_domain_alias(self, value):
        """:type value: list"""
        self.__setattr__("_temporary_domain_alias", value)

    @property
    def streamed_our_response(self):
        """我们的响应是否用 stream 模式传送
        :rtype: bool"""
        return self.__getattribute__("_streamed_our_response")

    @streamed_our_response.setter
    def streamed_our_response(self, value):
        """:type value: bool"""
        self.__setattr__("_streamed_our_response", value)

    @property
    def cacheable(self):
        """响应能否被缓存
        :rtype: bool"""
        return self.__getattribute__("_cacheable")

    @cacheable.setter
    def cacheable(self, value):
        """:type value: bool"""
        self.__setattr__("_cacheable", value)

    @property
    def extra_resp_headers(self):
        """额外的响应头
        :rtype: Dict[str, str]"""
        return self.__getattribute__("_extra_resp_headers")

    @extra_resp_headers.setter
    def extra_resp_headers(self, value):
        """:type value: Dict[str, str]"""
        self.__setattr__("_extra_resp_headers", value)

    @property
    def extra_cookies(self):
        """额外的cookie
        :rtype: Dict[str, str]"""
        return self.__getattribute__("_extra_cookies")

    @extra_cookies.setter
    def extra_cookies(self, value):
        """:type value: Dict[str, str]"""
        self.__setattr__("_extra_cookies", value)

    @property
    def time(self):
        """用于记录时间
        :rtype: Dict[str, float]"""
        return self.__getattribute__("_time")

    @time.setter
    def time(self, value):
        """:type value: Dict[str, float]"""
        self.__setattr__("_time", value)

    @property
    def request_data(self):
        """浏览器传入的data(已经经过重写)
        :rtype: Union[str, bytes, None]"""
        return self.__getattribute__("_request_data")

    @request_data.setter
    def request_data(self, value):
        """:type value: Union[str, bytes, None]"""
        self.__setattr__("_request_data", value)

    @property
    def request_data_encoding(self):
        """浏览器传入的data的编码
        :rtype: Union[str, None]"""
        return self.__getattribute__("_request_data_encoding")

    @request_data_encoding.setter
    def request_data_encoding(self, value):
        """:type value: Union[str, None]"""
        self.__setattr__("_request_data_encoding", value)

    @property
    def request_data_encoded(self):
        """:rtype: Union[bytes, None]"""
        if isinstance(self.request_data, str):
            return self.request_data.encode(encoding=self.request_data_encoding or 'utf-8')
        else:
            return self.request_data
