# EasyWebsiteMirror
an http reverse proxy designed to automatically and completely mirror a website (such as google), support cache and CDN  
一个Python反向HTTP代理程序, 用于快速、简单地创建别的网站的镜像, 自带本地文件缓存、CDN支持  
比如国内可以访问的Google镜像/中文维基镜像/twitter镜像(功能完整) 请看`more_config_examples`文件夹下的配置文件  
  
  
`这篇Readme很老了....新添加的功能请看config.sample.py中的注释`  
  
注: 由于正处在开发阶段中，每个版本的config.py都很可能不向上兼容(向下也有可能不兼容,但是可能性比较小). 当切换到新版本后请务必更新config.py 

## Feature 特性
1. Completely mirror.  
  创建非常完整的镜像, 既支持古老的网站(比如内网网站), 也支持巨型的现代化的网站   
  以下是例子(样例配置文件中的)  
  - Google镜像(整合中文维基镜像)
    - 以下google服务完全可用:
      - google网页搜索/学术/图片/新闻/图书/视频(搜索)/财经/APP搜索/翻译/网页快照/...
      - google搜索与中文维基百科无缝结合
    - 以下服务部分可用:
      - gg地图(地图可看, 左边栏显示不正常)/G+(不能登录)
    - 以下服务暂不可用(因为目前google登陆还存在问题):
      - 所有需要登录的东西, docs之类的
  - twitter镜像(PC站/Mobile站)
    - 所有功能完整可用(暂时还没发现不能用的功能)
  - 需要访问demo站点的请联系我, 不在此公开
  
2. Mirror ANY website  
   镜像任意网站, 而不只是Google/Wiki/twitter, 而且功能都非常完整  
   程序被设计成通用的镜像, 可以镜像任意网站, 而不是常见的nginx/apache镜像规则一样只能用于google.  
   并且能很好地适应对现代化的、逻辑复杂、功能庞大的网站  
   (现在还在开发阶段, 虽然所有网站的绝大部分功能都可以开箱即用, 但是某些网站的某些功能仍然不完整, 正在不断改进)  

   附带的一个好处就是在一个网站上修复程序bug, 对所有网站的兼容性都能得到提升

3. (MIME-based) Local statistic file cache support (especially useful if we have low bandwidth or high latency)  
  (基于MIME)本地静态文件缓存支持(当镜像服务器与被镜像服务器之间带宽很小或延迟很大时非常有用)
  
4. CDN Support, hot statistic resource can serve by CDN, dramatically increase speed  
  CDN支持. 让热门静态资源走CDN, 极大提高用户访问速度(特别是使用国内CDN, 而镜像服务器在国外时)
  
5. Easy to config and deploy, highly automatic  
  非常容易配置和部署, 镜像一个网站只需要添加它的域名即可
  
6. Access control(IP, user-agent), visitor verification(question answer, or custom verification function)  
  访问控制(IP, user-agent)与用户验证(回答问题, 也支持写自定义的验证函数)

## Install and Usage
It only support python3  
first install python3  
    - (Debian/Ubuntu) `apt-get install python3`  
    - (CentOS/RHEL) `yum install python3`  
    - (Windows) go to [python's homepage](https://www.python.org/downloads/) and download python3.5 (or newer)  
  
1. install or upgrade flask requests and chardet package `python3 -m pip install -U flask requests chardet`  
2. Download and unzip this package  
3. copy `config_sample.py` to `config.py` (don't need to change it's content for now)  
4. Execute it: `python3 EasyWebsiteMirror.py`  
5. Open your browser and enter `http://127.0.0.1/`, you will see exactly the `www.kernel.org`, and you can click and browse around. everything of
 the `*.kernel.org` is withing the mirror.
6. Please see the config.py for more information, an google mirror config is also included.  
  
## Mirror A Website
Mirror a website is very simple.  

Just set the `target_domain` to it's domain, the `external_domains` to it's external domain and sub domains 
such as static resource domains (If it has)  
save and run, the program will do the other works!   

All detects and rewrites are completely AUTOMATICALLY  

`tips:` you can find a website's external domains by using the developer tools of your browser, it will log all network traffics for you  

## Performance Enchance
#### Local Cache
  Local file cache (along with 304 support) is implanted and enabled by default
  If cache hits, you will see an `X-Cache: FileHit` in the response header.
  Local cache will be deleted and cleaned once program exit.
  
#### CDN Support
If you have an CDN service (like qiniu(七牛), cloudflare, etc..), you are able to storge static resource in CDN domains.  
CDN will dramatically increase your clients' access speed if you have many of them  

Please config your CDN service's "source site" or "源站"(chinese) to your domain (same as the front my_host_name). And then add the CDN domain to the config `CDN_domains` section. Program support many CDN domains.
Oh, dont't forget to turn `enable_static_resource_CDN` to True (case senstive)

And, as you think, CDN rewrite is also completely automatically.
Only static resource (url ended with .jpg/.js/.css/etc..) would be cached to CDN.

If your CDN storge your file permanently (like qiniu), you can disable local cache to save space, but if your CDN is temporarily storge (like cloudflare), please keep local cache enabled.
  
## Custom Rewriter (advanced function)
You can write your own html rewriter to do more things. Server's response html will be pass to this function, you can do some rewrite.  

Notice: program will apply your rewriter before it's normal rewriter. So, what your rewriter got is exactly the same html from server. This may bring some advantage to you. you don't have to care or konw about the program's rewriter.  

You can see an example rewriter in th `custom_func.sample.py`, rename it to `custom_func.py` to apply.  
It will rewrite UBB image mark to html img tag  
`[upload=jpg]http://foo.bar/blah.jpg[/upload]` --> `<img src="http://foo.bar/blah.jpg"></img>` 

## Deploy To Server
(From flask offical)  
    You can use the builtin server during development, but you should use a full deployment option for production applications. (Do not use the builtin development server in production.)  
Please see flask's deploy guide: [http://flask.pocoo.org/docs/0.10/deploying/](http://flask.pocoo.org/docs/0.10/deploying/)  

