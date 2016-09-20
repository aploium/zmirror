# zmirror镜像配置文件
出于方便起见, zmirror内置了几个镜像的配置文件:    

## 使用方法
通用的使用方法为:  
1. 复制主配置文件到 zmirror 根目录(wsgi.py所在目录), 为 config.py  
2. 如果存在对应的 custom_func_镜像名.py, 则将其也复制到zmirror根目录, 为 custom_func.py  
3. 修改 config.py 中 `my_host_name` 为你自己的域名  
4. 如果运行环境在墙内, 请将 `is_use_proxy` 设置为True, 并在 `requests_proxies` 中填入一个墙外代理  
5. 运行`python3 wsgi.py`  
    　　**注意** 直接运行wsgi.py仅用于测试性运行, 部署请看 [Deploy](../README.md#Deploy)  

eg:
```bash
cp ./more_configs/config_youtube.py ./config.py
cp ./more_configs/custom_func_youtube.py ./custom_func.py
# modify config.py
python3 wsgi.py
```

## 配置文件详情
* **Google镜像** (整合**中文维基镜像**)
    * 同时支持PC/手机
    * google搜索与中文维基百科无缝结合
    * 大部分功能完全正常: google网页搜索/学术/图片/新闻/图书/视频(搜索)/财经/APP搜索/翻译/网页快照/...
    * 以下服务部分可用: gg地图(地图可看, 左边栏显示不正常)/G+(不能登录)
    * 目前暂时无法做到完美的登陆, 登录才可使用的功能无效
    * 不会被Google Ban掉  
        * 传统的Nginx反代镜像方案, 时间长了会被Google Ban掉, 或者弹图片验证码,   
            这是由于Nginx反代镜像非常简陋, 用户的许多请求无法被正确发回到Google服务器,  
            Google就会把真实的访问者当成是机器人.  
            
        * 而zmirror比较完善, 用户的请求能全部发回到Google服务器, 不会被当成机器人  

* **twitter镜像**
    * 支持PC站/手机  (两者需要以不同的域名部署, 详见配置)  
    * 几乎所有功能完整可用, 大部分视频可以播放  
* **instagram镜像**  
    * 所有功能完整可用, 包括视频  
* **Youtube镜像**  
    * 支持PC站/手机  (两者需要以不同的域名部署, 详见配置)
    * 视频播放、高清支持
    * 登陆支持、字幕支持
    * 小视频上传支持