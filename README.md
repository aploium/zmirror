# EasyWebsiteMirror
an http reverse proxy designed to automatically and completely mirror a website (such as google), support cache and CDN  
一个Python反向HTTP代理程序, 用于快速、简单地创建别的网站的镜像, 自带本地文件缓存、CDN支持 比如国内可以访问的Google镜像(config.sample.py配置文件中有用于Google镜像的例子)  

## Install and Usage
It only support python3  
first install python3  
    - (Debian/Ubuntu) `apt-get install python3`  
    - (CentOS/RHEL) `yum install python3`  
    - (Windows) go to [python's homepage](https://www.python.org/downloads/) and download python3.5 (or newer)  
  
1. install or upgrade flask requests and chardet package `python3 -m pip install -U flask requests chardet`  
2. Download and unzip this package  
3. rename or copy `config.sample.py` to `config.py` (don't need to change it's content for now)  
4. Execute it: `python3 EasyWebsiteMirror.py`  
5. Open your browser and enter `http://localhost/`, you will see exactly the example.com, and you can click the "More information..." link of the page, you will be bring to `http://localhost/extdomains/www.iana.org/`  it's the auto url rewrite  
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
