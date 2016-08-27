# coding=utf-8
import threading
import requests


class ZmirrorThreadLocal(threading.local):
    """
    由于Python内置thread-local对代码补全的提示非常不友好, 所以自己继承一个

    本类在 zmirror 中被实例化为变量 parse
    这个变量的重要性不亚于 request, 在 zmirror 各个部分都会用到
    其各个变量的含义如下:
    parse.start_time          处理请求开始的时间, unix 时间戳
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
         .cache_control       远程服务器响应的cache_control内容
         .remote_response     远程服务器的响应, requests.Response
         .temporary_domain_alias 用于纯文本域名替换, 见 `plain_replace_domain_alias` 选项

    """

    def __init__(self, **kw):
        self.__dict__.update(kw)

        # 初始化成空白值
        self.start_time = None
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
        self.temporary_domain_alias = ()

    @property
    def start_time(self):
        """
        处理请求开始的时间, unix 时间戳
        :rtype: Union[int, None]
        """
        return self.__getattribute__("_start_time")

    @start_time.setter
    def start_time(self, value):
        """:type value: Union[int, None]"""
        self.__setattr__("_start_time", value)

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
        :rtype: Union[list, tuple]
        """
        return self.__getattribute__("_temporary_domain_alias")

    @temporary_domain_alias.setter
    def temporary_domain_alias(self, value):
        """:type value: Union[list, tuple]"""
        self.__setattr__("_temporary_domain_alias", value)
