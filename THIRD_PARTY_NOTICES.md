# 第三方组件

本项目不改变第三方组件的许可证。浏览器内核、静态适配资源、字体和WebView2属于原权利方；本仓库不对它们授予额外使用或分发权。使用相关组件须符合其原有许可。

Windows发行包保留Python、OpenSSL、Node.js、WebView2、Chromium/比特内核随附的声明和许可文件。Python依赖的具体版本见`requirements.txt`，许可文件保留于随包`site-packages`对应的`dist-info`目录中。

主要Python组件包括cryptography（Apache-2.0/BSD）、requests（Apache-2.0）、urllib3（MIT）、PySocks（BSD）、psutil（BSD）、pywebview（BSD）、pythonnet（MIT）、websocket-client（Apache-2.0）、certifi（MPL-2.0）、idna（BSD）及其依赖。以每个发行物附带的原始许可文本为准。

IP信息页直接访问[mpolden/echoip](https://github.com/mpolden/echoip)的官方服务[ifconfig.co](https://ifconfig.co/)，不内嵌该项目源代码。出口探测使用ipify等公共服务。

发布流程使用GitHub官方`actions/checkout`、`actions/upload-artifact`（MIT）。评估过`astral-sh/python-build-standalone`后，选择保留项目已有随包Python及标准ZIP打包，避免替换运行环境实现。候选源码在上传前使用gitleaks扫描；这些工具不属于产品运行依赖。
