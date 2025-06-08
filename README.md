# 🐟 XianYuApis - 闲鱼第三方API集成库

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Python Version](https://img.shields.io/badge/nodejs-18%2B-blue)](https://nodejs.org/zh-cn/)

**✨ 非官方闲鱼开放API接口封装库，通过网络请求操作所有的闲鱼操作，提供安全可靠的闲鱼平台功能访问能力。**
**⚠️ 注意：如有侵权联系作者删除。**


| 模块       | 已实现                                                                             |
|----------|---------------------------------------------------------------------------------|
| 闲鱼PC | ✅ 闲鱼所有http接口（sign参数解密）    |
| 闲鱼PC | ✅ 闲鱼websockets私信ws协议（接收发消息，sign+base64+protobuf协议）      |


## 🚀 一些成品
- https://github.com/shaxiu/XianyuAutoAgent




## 🌟 核心特性

- RESTful API + WebSocket 双通道
- 独立功能组件即插即用
- 基于`asyncio`的全异步架构🚀

## 🛠️ 快速开始
### ⛳运行环境
- Python 3.7+
- Node.js 18+

### 🎯安装依赖
```
pip install -r requirements.txt
npm install
```

### 🎨配置文件
复制cookie到代码中（注意！登录闲鱼后的cookie才是有效的，不登陆没有用，不然怎么知道给谁发消息）
本项目为逆向闲鱼提供可靠的api访问闲鱼能力，env文件作者忘了放了，下个版本放进去


### 🚀运行项目
```
python XianyuAutoAsync.py
```

### 🗝️注意事项
- XianyuAutoAsync.py中的代码是接收发消息的主入口，可以根据自己的需求进行修改
- XianyuApis.py中的代码包含了api接口的模板，sign参数已经解密，可以根据自己的需求进行修改，添加其他的接口


## 🧸额外说明
1. 感谢star⭐和follow📰！不时更新
2. 作者的联系方式在主页里，有问题可以随时联系我
3. 可以关注下作者的其他项目，欢迎 PR 和 issue
4. 感谢赞助！如果此项目对您有帮助，请作者喝一杯奶茶~~ （开心一整天😊😊）
5. thank you~~~

<div align="center">
  <img src="https://github.com/cv-cat/Spider_XHS/blob/master/author/wx_pay.png" width="400px" alt="微信赞赏码"> 
  <img src="https://github.com/cv-cat/Spider_XHS/blob/master/author/zfb_pay.jpg" width="400px" alt="支付宝收款码">
</div>


## 📈 Star 趋势
<a href="https://www.star-history.com/#cv-cat/XianYuApis&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=cv-cat/XianYuApis&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=cv-cat/XianYuApis&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=cv-cat/XianYuApis&type=Date" />
 </picture>
</a>
