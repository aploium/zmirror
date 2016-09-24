# coding=utf-8
try:
    from typing import Union
except:
    pass
from flask import Response, Request
from zmirror.zmirror import ZmirrorThreadLocal

ZMIRROR_NCR_COOKIE_NAME = "zmirror_ncr"


def custom_prior_redirect_func(request, parse):
    """
    用于在 prior_request_redirect 阶段的自定义重定向

    若返回一个 flask.Response 对象, 则执行重定向, 直接返回这个 Response
    若返回None, 则不进行重定向

    不应该修改parse变量 (添加头和cookie除外)

    详见 `config_default.py` 中 `Custom Redirection` 部分
    ------------------------------

    对于本函数, 其功能是检查用户cookies中是否出现了 zmirror_ncr
      如果已出现, 则表示已经访问过了 https://www.google.com/ncr 进行了国别重定向避免.
        则不做任何事
      否则则需要重定向到 /ncr 进行一次请求, 来避免国别重定向

    由于国别重定向以后的语言会变成英语, 所以还需要将语言修改为简中
      修改方式是在 query string 中加入 hl=zh-CN
      本函数的另一个作用就是在 query string 中加入 hl=zh-CN

    所以, 新用户的请求是这样的:
      * 第一次请求--> www.google.com --zmirror重定向--> www.google.com/ncr
      --被google重定向--> www.google.com (此时看到的页面是英语的)

      * 第二次请求--> www.google.com --zmirror重定向--> www.google.com/?hl=zh-CN (此时看到的页面为中文)

      有一个缺点就是用户第一次请求看到的是英语界面, 从第二次请求开始, 看到的才是中文界面
      这是因为如果在ncr后如果直接请求 /?hl=zh-CN 的话, 很快/ncr就会失效, 而重定向到 .com.hk


    对于google镜像的国别重定向问题, 请看 issues#10
      https://github.com/aploium/zmirror/issues/10

    感谢 @licess 指出的这个问题

    :param request: flask request object
    :type request: Request
    :param parse: the zmirror parse variable
    :type parse: ZmirrorThreadLocal
    :rtype: Union[Response, None]
    """
    from urllib.parse import urlsplit, urlunsplit
    from flask import redirect

    zmirror_ncr = request.cookies.get(ZMIRROR_NCR_COOKIE_NAME)

    if parse.remote_path in ("/", "/webhp", "/search"):
        if zmirror_ncr == "y":
            # 如果在cookies中已经设置了zmirror的ncr标记 并且请求的是这三个path
            # 则将搜索语言修改为中文(通过在query string中添加 hl=zh-CN 来实现)
            if "hl=" in parse.remote_path_query:  # 如果已经指定了 hl= 则跳过
                return None

            else:
                # 否则通过重定向在 query string 中加入 hl=zh-CN
                sp = list(urlsplit(request.url))
                if sp[3] == "":
                    sp[3] = "hl=zh-CN"
                else:
                    sp[3] += "&hl=zh-CN"
                return redirect(urlunsplit(sp), code=307)

        elif zmirror_ncr == "prepared":
            parse.set_cookies(ZMIRROR_NCR_COOKIE_NAME, "y")

        else:
            # 仅当 prepared 以后的下一次访问 google首页才触发 /ncr 重定向
            #   ps: /webhp 等效于 /
            return redirect("/ncr", code=302)

    elif parse.remote_path == "/ncr":
        # 如果正在请求 /ncr , 则在cookie中设置 zmirror_ncr=y (不作重定向)
        # "y" 代表 yes
        parse.set_cookies(ZMIRROR_NCR_COOKIE_NAME, "prepared")  # TTL是一年
        return None

    else:
        # 其他情况什么都不做
        return None
