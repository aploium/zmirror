# 给镜像添加CDN--使用七牛

在继续本教程之前, 假设你已经成功部署了zmirror镜像  
若尚未部署, 请使用[zmirror一键部署脚本](https://github.com/aploium/zmirror-onekey)进行部署  
[手动部署教程](https://github.com/aploium/zmirror/wiki/%E9%83%A8%E7%BD%B2%E6%94%AF%E6%8C%81HTTPS%E5%92%8CHTTP2.0%E7%9A%84%E9%95%9C%E5%83%8F)也有, 但是除非自动部署失败, 否则建议用自动部署脚本  

> **注意**  
> 在继续本教程前, 请务必先确认你的镜像已经部署成功, 并且可以正常使用  
> 否则添加CDN以后如果出现问题, 则难以确定是CDN导致的问题, 还是本身没有部署成功  

## 关于七牛的说明

七牛提供了优质, 而且功能健全的对象存储服务.  
身份验证以后提供免费的10GB存储和10GB免费月流量, 不验证的话只有1GB存储/1GB免费月流量  
本教程的CDN, 就是利用七牛存储的"回源"功能, 将静态资源按需存储到七牛中,  
然后当用户访问时, 从七牛中获取, 而不是从(一般是)国外的VPS中, 可以显著地提升性能  

## 步骤

1. **注册**

    如果不介意的话, 可以下面的邀请链接注册, 这样我会得到一些免费的流量奖励  
    https://portal.qiniu.com/signup?code=3l8ywttgbe6aa  

2. **新建一个对象存储**

    ![新建一个对象存储](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/1.png)  

3. **设置对象存储**
    
    ![设置对象存储](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/2.png)  
    名字随便取, 自己能分得清就行  
    `访问控制` 记得设置为公开  

4. **设置回源站**

    ![点开镜像存储选项](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/3.png)  
    
    ![设置镜像站URL](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/4.png)  
    
    在镜像源处设置自己的镜像站URL, 比如图中, 我的镜像站URL是`https://demo1.zmirrordemo.com/`  
    
    > **注意**
    > 如果是一键部署的, 或者是跟着教程部署的  
    > 请记得将镜像源的协议设置为 `https://` 而不是 `http://`  
    > 因为http会被强制重定向到https, 大大增加开销, 还会导致bug  
    
5. **创建一个HTTPS域名**
    
    ![设置镜像站URL](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/5.png)  

    退回到主界面, 然后点按钮, 创建一个HTTPS域名  
    中间会提示HTTPS域名的收费是HTTP的1.2倍, 忽略它就行, 因为有每月10GB免费流量, 足够用了  
    
    ![创建后的HTTPS域名](https://raw.githubusercontent.com/aploium/zmirror/wiki-pages/img/tutorial-add-cdn/6.png)  
    
    如图, 它给我分配的HTTPS域名是 `oc7fbsjwl.qnssl.com`  
    
    > **使用自己的HTTPS域名**
    > 七牛也支持使用自定义的HTTPS域名, 但是要求域名已经备案  
    > 一般来说, 用它分配那个域名就行了  
    
6. **测试一下镜像是否成功**

    至此为止, 七牛那边的设置已经ok了, `oc7fbsjwl.qnssl.com` 这个域名下面的所有东西都会被映射到我们的镜像站  
    
    可以执行 `curl https://oc7fbsjwl.qnssl.com/crossdomain.xml`  
    如果返回的是下面的东西:  
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
    <allow-access-from domain="*"/>
    <site-control permitted-cross-domain-policies="all"/>
    <allow-http-request-headers-from domain="*" headers="*" secure="false"/>
    </cross-domain-policy>
    ```
    就表示成功