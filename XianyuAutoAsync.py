import asyncio
import json
import time
import base64
import os
from loguru import logger
import websockets
from utils.xianyu_utils import (
    decrypt, generate_mid, generate_uuid, trans_cookies,
    generate_device_id, generate_sign
)
from config import (
    WEBSOCKET_URL, HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT,
    TOKEN_REFRESH_INTERVAL, TOKEN_RETRY_INTERVAL, config, COOKIES_STR,
    MANUAL_MODE, LOG_CONFIG, AUTO_REPLY, DEFAULT_HEADERS, WEBSOCKET_HEADERS,
    APP_CONFIG, API_ENDPOINTS
)
from utils.message_utils import format_message, format_system_message
from utils.ws_utils import WebSocketClient
import sys
import aiohttp

# 日志配置
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, f"xianyu_{time.strftime('%Y-%m-%d')}.log")
logger.remove()
logger.add(
    log_path,
    rotation=LOG_CONFIG.get('rotation', '1 day'),
    retention=LOG_CONFIG.get('retention', '7 days'),
    compression=LOG_CONFIG.get('compression', 'zip'),
    level=LOG_CONFIG.get('level', 'INFO'),
    format=LOG_CONFIG.get('format', '<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>'),
    encoding='utf-8',
    enqueue=True
)
logger.add(
    sys.stdout,
    level=LOG_CONFIG.get('level', 'INFO'),
    format=LOG_CONFIG.get('format', '<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>'),
    enqueue=True
)

class XianyuLive:
    def __init__(self, cookies_str=None):
        """初始化闲鱼直播类"""
        if not cookies_str:
            cookies_str = COOKIES_STR
        if not cookies_str:
            raise ValueError("未提供cookies，请在global_config.yml中配置COOKIES_STR或通过参数传入")
            
        self.cookies = trans_cookies(cookies_str)
        self.cookies_str = cookies_str  # 保存原始cookie字符串
        self.base_url = WEBSOCKET_URL
        self.myid = self.cookies['unb']
        self.device_id = generate_device_id(self.myid)
        
        # 心跳相关配置
        self.heartbeat_interval = HEARTBEAT_INTERVAL
        self.heartbeat_timeout = HEARTBEAT_TIMEOUT
        self.last_heartbeat_time = 0
        self.last_heartbeat_response = 0
        self.heartbeat_task = None
        self.ws = None
        
        # Token刷新相关配置
        self.token_refresh_interval = TOKEN_REFRESH_INTERVAL
        self.token_retry_interval = TOKEN_RETRY_INTERVAL
        self.last_token_refresh_time = 0
        self.current_token = None
        self.token_refresh_task = None
        self.connection_restart_flag = False  # 连接重启标志
        
        # 人工接管相关配置
        self.manual_mode_conversations = set()  # 存储处于人工接管模式的会话ID
        self.manual_mode_timeout = MANUAL_MODE.get('timeout', 3600)  # 人工接管超时时间，默认1小时
        self.manual_mode_timestamps = {}  # 记录进入人工模式的时间
        self.toggle_keywords = MANUAL_MODE.get('toggle_keywords', ['。'])  # 切换关键词
        self.session = None  # 用于API调用的aiohttp session

    def check_toggle_keywords(self, message):
        """检查消息是否包含切换关键词"""
        return any(keyword in message for keyword in self.toggle_keywords)

    def is_manual_mode(self, chat_id):
        """检查是否处于人工接管模式"""
        if chat_id in self.manual_mode_conversations:
            # 检查是否超时
            if time.time() - self.manual_mode_timestamps.get(chat_id, 0) > self.manual_mode_timeout:
                self.exit_manual_mode(chat_id)
                return False
            return True
        return False

    def enter_manual_mode(self, chat_id):
        """进入人工接管模式"""
        self.manual_mode_conversations.add(chat_id)
        self.manual_mode_timestamps[chat_id] = time.time()

    def exit_manual_mode(self, chat_id):
        """退出人工接管模式"""
        self.manual_mode_conversations.discard(chat_id)
        self.manual_mode_timestamps.pop(chat_id, None)

    def toggle_manual_mode(self, chat_id):
        """切换人工接管模式"""
        if self.is_manual_mode(chat_id):
            self.exit_manual_mode(chat_id)
            return False
        else:
            self.enter_manual_mode(chat_id)
            return True

    async def refresh_token(self):
        """刷新token"""
        try:
            logger.info("开始刷新token...")
            params = {
                'jsv': '2.7.2',
                'appKey': '34839810',
                't': str(int(time.time()) * 1000),
                'sign': '',
                'v': '1.0',
                'type': 'originaljson',
                'accountSite': 'xianyu',
                'dataType': 'json',
                'timeout': '20000',
                'api': 'mtop.taobao.idlemessage.pc.login.token',
                'sessionOption': 'AutoLoginOnly',
                'spm_cnt': 'a21ybx.im.0.0',
            }
            data_val = '{"appKey":"444e9908a51d1cb236a27862abc769c9","deviceId":"' + self.device_id + '"}'
            data = {
                'data': data_val,
            }
            
            # 获取token
            token = None
            if '_m_h5_tk' in self.cookies:
                token = self.cookies['_m_h5_tk'].split('_')[0]
            
            sign = generate_sign(params['t'], token, data_val)
            params['sign'] = sign
            
            # 发送请求
            headers = DEFAULT_HEADERS.copy()
            headers['cookie'] = self.cookies_str
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    API_ENDPOINTS.get('token'),
                    params=params,
                    data=data,
                    headers=headers
                ) as response:
                    res_json = await response.json()
                    
                    # 检查并更新Cookie
                    if 'set-cookie' in response.headers:
                        new_cookies = {}
                        for cookie in response.headers.getall('set-cookie', []):
                            if '=' in cookie:
                                name, value = cookie.split(';')[0].split('=', 1)
                                new_cookies[name.strip()] = value.strip()
                        
                        # 更新cookies
                        if new_cookies:
                            self.cookies.update(new_cookies)
                            # 生成新的cookie字符串
                            self.cookies_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                            # 更新配置文件
                            await self.update_config_cookies()
                            logger.debug("已更新Cookie到配置文件")
                    
                    if isinstance(res_json, dict):
                        ret_value = res_json.get('ret', [])
                        # 检查ret是否包含成功信息
                        if any('SUCCESS::调用成功' in ret for ret in ret_value):
                            if 'data' in res_json and 'accessToken' in res_json['data']:
                                new_token = res_json['data']['accessToken']
                                self.current_token = new_token
                                self.last_token_refresh_time = time.time()
                                logger.info("Token刷新成功")
                                return new_token
                            
                    logger.error(f"Token刷新失败: {res_json}")
                    return None
                    
        except Exception as e:
            logger.error(f"Token刷新异常: {str(e)}")
            return None

    async def update_config_cookies(self):
        """更新配置文件中的cookies"""
        try:
            import yaml
            from datetime import datetime
            config_path = 'global_config.yml'
            
            # 读取当前配置
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # 更新cookies和更新时间
            if 'COOKIES' not in config:
                config['COOKIES'] = {}
            config['COOKIES']['value'] = self.cookies_str
            config['COOKIES']['last_update_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 写回配置文件
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, allow_unicode=True)
                
            logger.debug("已更新Cookie到配置文件")
                
        except Exception as e:
            logger.error(f"更新配置文件失败: {str(e)}")

    async def token_refresh_loop(self):
        """Token刷新循环"""
        while True:
            try:
                current_time = time.time()
                if current_time - self.last_token_refresh_time >= self.token_refresh_interval:
                    logger.info("Token即将过期，准备刷新...")
                    new_token = await self.refresh_token()
                    if new_token:
                        logger.info("Token刷新成功，准备重新建立连接...")
                        self.connection_restart_flag = True
                        if self.ws:
                            await self.ws.close()
                        break
                    else:
                        logger.error("Token刷新失败，将在{}分钟后重试".format(self.token_retry_interval // 60))
                        await asyncio.sleep(self.token_retry_interval)
                        continue
                await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"Token刷新循环出错: {e}")
                await asyncio.sleep(60)

    async def create_chat(self, ws, toid, item_id='891198795482'):
        msg = {
            "lwp": "/r/SingleChatConversation/create",
            "headers": {
                "mid": generate_mid()
            },
            "body": [
                {
                    "pairFirst": f"{toid}@goofish",
                    "pairSecond": f"{self.myid}@goofish",
                    "bizType": "1",
                    "extension": {
                        "itemId": item_id
                    },
                    "ctx": {
                        "appVersion": "1.0",
                        "platform": "web"
                    }
                }
            ]
        }
        await ws.send(json.dumps(msg))

    async def send_msg(self, ws, cid, toid, text):
        text = {
            "contentType": 1,
            "text": {
                "text": text
            }
        }
        text_base64 = str(base64.b64encode(json.dumps(text).encode('utf-8')), 'utf-8')
        msg = {
            "lwp": "/r/MessageSend/sendByReceiverScope",
            "headers": {
                "mid": generate_mid()
            },
            "body": [
                {
                    "uuid": generate_uuid(),
                    "cid": f"{cid}@goofish",
                    "conversationType": 1,
                    "content": {
                        "contentType": 101,
                        "custom": {
                            "type": 1,
                            "data": text_base64
                        }
                    },
                    "redPointPolicy": 0,
                    "extension": {
                        "extJson": "{}"
                    },
                    "ctx": {
                        "appVersion": "1.0",
                        "platform": "web"
                    },
                    "mtags": {},
                    "msgReadStatusSetting": 1
                },
                {
                    "actualReceivers": [
                        f"{toid}@goofish",
                        f"{self.myid}@goofish"
                    ]
                }
            ]
        }
        await ws.send(json.dumps(msg))

    async def init(self, ws):
        # 如果没有token或者token过期，获取新token
        if not self.current_token or (time.time() - self.last_token_refresh_time) >= self.token_refresh_interval:
            logger.info("获取初始token...")
            await self.refresh_token()
        
        if not self.current_token:
            logger.error("无法获取有效token，初始化失败")
            raise Exception("Token获取失败")
            
        msg = {
            "lwp": "/reg",
            "headers": {
                "cache-header": "app-key token ua wv",
                "app-key": APP_CONFIG.get('app_key'),
                "token": self.current_token,
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 DingTalk(2.1.5) OS(Windows/10) Browser(Chrome/133.0.0.0) DingWeb/2.1.5 IMPaaS DingWeb/2.1.5",
                "dt": "j",
                "wv": "im:3,au:3,sy:6",
                "sync": "0,0;0;0;",
                "did": self.device_id,
                "mid": generate_mid()
            }
        }
        await ws.send(json.dumps(msg))
        await asyncio.sleep(1)
        current_time = int(time.time() * 1000)
        msg = {
            "lwp": "/r/SyncStatus/ackDiff",
            "headers": {"mid": generate_mid()},
            "body": [
                {
                    "pipeline": "sync",
                    "tooLong2Tag": "PNM,1",
                    "channel": "sync",
                    "topic": "sync",
                    "highPts": 0,
                    "pts": current_time * 1000,
                    "seq": 0,
                    "timestamp": current_time
                }
            ]
        }
        await ws.send(json.dumps(msg))
        logger.info('连接注册完成')

    async def send_heartbeat(self, ws):
        """发送心跳包"""
        msg = {
            "lwp": "/!",
            "headers": {
                "mid": generate_mid()
            }
        }
        await ws.send(json.dumps(msg))
        self.last_heartbeat_time = time.time()

    async def heartbeat_loop(self, ws):
        """心跳循环"""
        while True:
            try:
                await self.send_heartbeat(ws)
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"心跳发送失败: {e}")
                break

    async def handle_heartbeat_response(self, message_data):
        """处理心跳响应"""
        try:
            if message_data.get("code") == 200:
                self.last_heartbeat_response = time.time()
                logger.debug("心跳响应正常")
                return True
        except Exception as e:
            logger.error(f"处理心跳响应出错: {e}")
        return False

    async def send_msg_once(self, toid, item_id, text):
        headers = {
            "Cookie": self.cookies_str,
            "Host": "wss-goofish.dingtalk.com",
            "Connection": "Upgrade",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "Origin": "https://www.goofish.com",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9",
        }
        async with websockets.connect(
            self.base_url,
            additional_headers=headers
        ) as websocket:
            await self.init(websocket)
            await self.create_chat(websocket, toid, item_id)
            async for message in websocket:
                try:
                    logger.info(f"message: {message}")
                    message = json.loads(message)
                    cid = message["body"]["singleChatConversation"]["cid"]
                    cid = cid.split('@')[0]
                    await self.send_msg(websocket, cid, toid, text)
                    logger.info('send message')
                    return
                except Exception as e:
                    pass

    def is_chat_message(self, message):
        """判断是否为用户聊天消息"""
        try:
            return (
                isinstance(message, dict) 
                and "1" in message 
                and isinstance(message["1"], dict)
                and "10" in message["1"]
                and isinstance(message["1"]["10"], dict)
                and "reminderContent" in message["1"]["10"]
            )
        except Exception:
            return False

    def is_sync_package(self, message_data):
        """判断是否为同步包消息"""
        try:
            return (
                isinstance(message_data, dict)
                and "body" in message_data
                and "syncPushPackage" in message_data["body"]
                and "data" in message_data["body"]["syncPushPackage"]
                and len(message_data["body"]["syncPushPackage"]["data"]) > 0
            )
        except Exception:
            return False

    async def create_session(self):
        """创建aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        """关闭aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def get_api_reply(self, msg_time, user_url, send_user_id, send_user_name, item_id, send_message, chat_id):
        """调用API获取回复消息"""
        try:
            if not self.session:
                await self.create_session()

            api_config = AUTO_REPLY.get('api', {})
            timeout = aiohttp.ClientTimeout(total=api_config.get('timeout', 10))
            
            payload = {
                "msg_time": msg_time,
                "user_url": user_url,
                "send_user_id": send_user_id,
                "send_user_name": send_user_name,
                "item_id": item_id,
                "send_message": send_message,
                "chat_id": chat_id
            }
            
            async with self.session.post(
                api_config.get('url', 'http://localhost:8080/xianyu/reply'),
                json=payload,
                timeout=timeout
            ) as response:
                result = await response.json()
                
                # 将code转换为字符串进行比较，或者直接用数字比较
                if str(result.get('code')) == '200' or result.get('code') == 200:
                    send_msg = result.get('data', {}).get('send_msg')
                    if send_msg:
                        # 格式化消息中的占位符
                        return send_msg.format(
                            send_user_id=payload['send_user_id'],
                            send_user_name=payload['send_user_name'],
                            send_message=payload['send_message']
                        )
                    else:
                        logger.warning("API返回成功但无回复消息")
                        return None
                else:
                    logger.warning(f"API返回错误: {result.get('msg', '未知错误')}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.error("API调用超时")
            return None
        except Exception as e:
            logger.error(f"调用API出错: {str(e)}")
            return None

    async def handle_message(self, message_data, websocket):
        """处理所有类型的消息"""
        try:
            # 发送确认消息
            try:
                message = message_data
                ack = {
                    "code": 200,
                    "headers": {
                        "mid": message["headers"]["mid"] if "mid" in message["headers"] else generate_mid(),
                        "sid": message["headers"]["sid"] if "sid" in message["headers"] else '',
                    }
                }
                if 'app-key' in message["headers"]:
                    ack["headers"]["app-key"] = message["headers"]["app-key"]
                if 'ua' in message["headers"]:
                    ack["headers"]["ua"] = message["headers"]["ua"]
                if 'dt' in message["headers"]:
                    ack["headers"]["dt"] = message["headers"]["dt"]
                await websocket.send(json.dumps(ack))
            except Exception as e:
                pass

            # 如果不是同步包消息，直接返回
            if not self.is_sync_package(message_data):
                return

            # 获取并解密数据
            sync_data = message_data["body"]["syncPushPackage"]["data"][0]
            
            # 检查是否有必要的字段
            if "data" not in sync_data:
                logger.debug("同步包中无data字段")
                return

            # 解密数据
            try:
                data = sync_data["data"]
                try:
                    data = base64.b64decode(data).decode("utf-8")
                    data = json.loads(data)
                    # 处理未加密的消息（如系统提示等）
                    msg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    if isinstance(data, dict) and 'chatType' in data:
                        if 'operation' in data and 'content' in data['operation']:
                            content = data['operation']['content']
                            if 'sessionArouse' in content:
                                # 处理系统引导消息
                                logger.info(f"[{msg_time}] 【系统】小闲鱼智能提示:")
                                if 'arouseChatScriptInfo' in content['sessionArouse']:
                                    for qa in content['sessionArouse']['arouseChatScriptInfo']:
                                        logger.info(f"  - {qa['chatScrip']}")
                            elif 'contentType' in content:
                                # 其他类型的未加密消息
                                logger.debug(f"[{msg_time}] 【系统】其他类型消息: {content}")
                    return
                except Exception as e:
                    decrypted_data = decrypt(data)
                    message = json.loads(decrypted_data)
            except Exception as e:
                logger.error(f"消息解密失败: {e}")
                return

            # 处理订单状态消息
            try:
                msg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                if message['3']['redReminder'] == '等待买家付款':
                    user_id = message['1'].split('@')[0]
                    user_url = f'https://www.goofish.com/personal?userId={user_id}'
                    logger.info(f'[{msg_time}] 【系统】等待买家 {user_url} 付款')
                    return
                elif message['3']['redReminder'] == '交易关闭':
                    user_id = message['1'].split('@')[0]
                    user_url = f'https://www.goofish.com/personal?userId={user_id}'
                    logger.info(f'[{msg_time}] 【系统】买家 {user_url} 交易关闭')
                    return
                elif message['3']['redReminder'] == '等待卖家发货':
                    user_id = message['1'].split('@')[0]
                    user_url = f'https://www.goofish.com/personal?userId={user_id}'
                    logger.info(f'[{msg_time}] 【系统】交易成功 {user_url} 等待卖家发货')
                    return
            except:
                pass

            # 判断是否为聊天消息
            if not self.is_chat_message(message):
                logger.debug("非聊天消息")
                return

            # 处理聊天消息
            create_time = int(message["1"]["5"])
            send_user_name = message["1"]["10"].get("senderNick", message["1"]["10"]["reminderTitle"])
            send_user_id = message["1"]["10"]["senderUserId"]
            send_message = message["1"]["10"]["reminderContent"]
            
            # 获取商品ID和会话ID
            url_info = message["1"]["10"]["reminderUrl"]
            item_id = url_info.split("itemId=")[1].split("&")[0] if "itemId=" in url_info else None
            chat_id = message["1"]["2"].split('@')[0]

            # 格式化消息时间
            msg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(create_time/1000))

            # 检查是否需要切换人工接管模式
            if self.check_toggle_keywords(send_message):
                is_manual = self.toggle_manual_mode(chat_id)
                mode_str = "进入" if is_manual else "退出"
                logger.info(f"[{msg_time}] 【系统】用户: {send_user_name} 的会话 {chat_id} [商品id: {item_id}] {mode_str}人工接管模式")
                return

            # 判断消息方向
            if send_user_id == self.myid:
                logger.info(f"[{msg_time}] 【手动发出】 商品({item_id}): {send_message}")
                return
            else:
                logger.info(f"[{msg_time}] 【收到】用户: {send_user_name} (ID: {send_user_id}), 商品({item_id}): {send_message}")

            # 检查是否处于人工接管模式
            if self.is_manual_mode(chat_id):
                logger.info(f"[{msg_time}] 【系统】会话 {chat_id} 处于人工接管模式，不自动回复")
                return

            # 自动回复消息
            if not AUTO_REPLY.get('enabled', True):
                logger.info(f"[{msg_time}] 【系统】自动回复已禁用")
                return

            # 构造用户URL
            user_url = f'https://www.goofish.com/personal?userId={send_user_id}'
                
            reply = None
            # 判断是否启用API回复
            if AUTO_REPLY.get('api', {}).get('enabled', False):
                reply = await self.get_api_reply(
                    msg_time, user_url, send_user_id, send_user_name,
                    item_id, send_message, chat_id
                )
                if not reply:
                    logger.error(f"[{msg_time}] 【API调用失败】用户: {send_user_name} (ID: {send_user_id}), 商品({item_id}): {send_message}")
                
            # 如果API回复失败或未启用API，使用默认回复
            if not reply:
                reply = AUTO_REPLY.get('default_message', '收到您的消息').format(
                    send_user_id=send_user_id,
                    send_user_name=send_user_name,
                    send_message=send_message
                )
                
            await self.send_msg(websocket, chat_id, send_user_id, reply)
            # 记录发出的消息
            msg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            logger.info(f"[{msg_time}] 【{'API' if AUTO_REPLY.get('api', {}).get('enabled', False) else '默认'}发出】用户: {send_user_name} (ID: {send_user_id}), 商品({item_id}): {reply}")
            
        except Exception as e:
            logger.error(f"处理消息时发生错误: {str(e)}")
            logger.debug(f"原始消息: {message_data}")

    async def main(self):
        """主程序入口"""
        try:
            await self.create_session()  # 创建session
            while True:
                try:
                    headers = WEBSOCKET_HEADERS.copy()
                    headers['Cookie'] = self.cookies_str
                    
                    async with websockets.connect(
                        self.base_url,
                        additional_headers=headers
                    ) as websocket:
                        self.ws = websocket
                        await self.init(websocket)

                        # 启动心跳任务
                        self.heartbeat_task = asyncio.create_task(self.heartbeat_loop(websocket))
                        
                        # 启动token刷新任务
                        self.token_refresh_task = asyncio.create_task(self.token_refresh_loop())

                        async for message in websocket:
                            try:
                                message_data = json.loads(message)
                                
                                # 处理心跳响应
                                if await self.handle_heartbeat_response(message_data):
                                    continue
                                    
                                # 处理其他消息
                                await self.handle_message(message_data, websocket)
                                
                            except Exception as e:
                                logger.error(f"处理消息出错: {e}")
                                continue

                except Exception as e:
                    logger.error(f"WebSocket连接异常: {e}")
                    if self.heartbeat_task:
                        self.heartbeat_task.cancel()
                    if self.token_refresh_task:
                        self.token_refresh_task.cancel()
                    await asyncio.sleep(5)  # 等待5秒后重试
                    continue
        finally:
            await self.close_session()  # 确保关闭session

if __name__ == '__main__':
    cookies_str = os.getenv('COOKIES_STR')
    xianyuLive = XianyuLive(cookies_str)
    asyncio.run(xianyuLive.main())
