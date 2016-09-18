# coding=utf-8
"""
本模块为支持 `connection_keep_alive` 选项而存在
提供了一个线程安全的 keep-alive 链接池

requests的连接在每个session中是自动 keep-alive 的,
    在 `connection_keep_alive` 关闭时, 每次请求都会创建一个新的session,
        并发起一次新的请求, 则会带来相当大的连接开销(时间上)
    通过保持并复用 requests 的session, 可以极大地减少requests在请求远程服务器时的连接延迟

以前的版本是线程不安全, 当并发数大时会出现 ConnectionResetError
"""
from time import time
import requests
import threading

SESSION_TTL = 180  # 在清除过期session时, 会丢弃所有180秒未活动的session

# session池
pool = {
    "example.com": [
        # 每个域名下都有一堆session,
        # session的获取遵循 LIFO(后进先出) 原则,
        #    即优先获取最近使用过的 session
        # 这样可以增加 keep-alive 的存活几率
        {
            "domain": "example.com",
            "session": requests.Session(),
            "active": time(),
        },
    ],
}

locked_session = threading.local()  # 这是一个 thread-local 变量


def get_session(domain):
    """
    获取一个此域名的 keep-alive 的session
    :param domain: 域名
    :type domain: str
    :rtype: requests.Session
    """
    if domain not in pool:
        pool[domain] = []

    if not hasattr(locked_session, "session"):
        # 这个变量用于存储本线程中被锁定的session
        # 当一个session被拿出来使用时, 会从 pool 中被移除, 加入到下面这个变量中
        # 当线程结束后, 需要调用 release_lock() 来释放被锁定的session
        #    此时被锁定的session会重新进入session池
        locked_session.session = []

    if not pool[domain]:
        # 线程池空, 新建一个 session
        session = {
            "domain": domain,
            "session": requests.Session(),
        }
    else:
        # 从线程池中取出最近的一个
        session = pool[domain].pop()

    session["active"] = time()

    locked_session.session.append(session)

    return session["session"]


def release_lock():
    if not hasattr(locked_session, "session"):
        return
    for session in locked_session.session:  # type: dict
        pool[session["domain"]].append(session)


def clear(force_flush=False):
    if force_flush:
        pool.clear()
    else:
        for domain in pool.keys():
            pool[domain] = [s for s in pool[domain] if s["active"] > time() - SESSION_TTL]
