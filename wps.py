import requests
import json
import base64
import random
import string
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad
import os
import urllib.parse


# ==================== 配置区域 ====================
# 基础URL
BASE_URL = "https://personal-bus.wps.cn"

# 从环境变量读取敏感信息
USER_ID = os.environ.get("WPS_USER_ID", "")
WPS_SID = os.environ.get("WPS_SID", "")

# Bark 推送配置 - 从 GitHub Secrets 读取
BARK_KEY = os.environ.get("BARK_KEY", "")
BARK_URL = f"https://api.day.app/{BARK_KEY}" if BARK_KEY else ""

# 检查环境变量是否设置
if not USER_ID:
    print("⚠️ 警告: 环境变量 WPS_USER_ID 未设置")
if not WPS_SID:
    print("⚠️ 警告: 环境变量 WPS_SID 未设置")
if not BARK_KEY:
    print("⚠️ 警告: 环境变量 BARK_KEY 未设置，将不会推送通知")

# 拼接完整Cookie
COOKIE_STR = f"uid={USER_ID}; wps_sid={WPS_SID}"

# 请求头配置
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://personal-act.wps.cn",
    "Referer": "https://personal-act.wps.cn/rubik2/portal/HD2025031821201822/YM2025031821202008?cs_from=&position=pc_rwzx_wpss",
    "Cookie": COOKIE_STR
}
# =================================================


class SignInClient:
    def __init__(self, user_id):
        self.user_id = user_id
        self.base_url = BASE_URL
        self.rsa_public_key = None
        self.headers = HEADERS.copy()
        self.bark_url = BARK_URL
        self.bark_key = BARK_KEY
        # 确保 log 目录存在
        self._ensure_log_dir()
        # 初始化时删除旧的 wps.txt
        self._clear_log()
    
    def _ensure_log_dir(self):
        """确保 log 目录存在"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            log_dir = os.path.join(script_dir, "log")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
                print(f"✓ 已创建日志目录: {log_dir}")
        except Exception as e:
            print(f"⚠️ 创建日志目录失败: {e}")
    
    def _get_log_path(self, filename="wps.txt"):
        """获取日志文件的完整路径"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(script_dir, "log")
        return os.path.join(log_dir, filename)
    
    def _clear_log(self):
        """删除已存在的 wps.txt 文件"""
        try:
            log_file = self._get_log_path()
            if os.path.exists(log_file):
                os.remove(log_file)
                print(f"✓ 已删除旧的日志文件: {log_file}")
        except Exception as e:
            print(f"⚠️ 删除旧日志文件失败: {e}")
    
    def _send_bark_notification(self, message):
        """
        发送 Bark 推送通知
        message: 要推送的消息内容（不含时间戳）
        """
        # 如果未配置 Bark Key，跳过推送
        if not self.bark_key:
            print("ℹ️ Bark Key 未配置，跳过推送通知")
            return False
        
        try:
            # URL编码消息内容
            encoded_message = urllib.parse.quote(message, safe='')
            url = f"{self.bark_url}/WPS签到/{encoded_message}"
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("code") == 200:
                    print(f"✓ Bark推送成功")
                    return True
                else:
                    print(f"⚠️ Bark推送失败: {result}")
                    return False
            else:
                print(f"⚠️ Bark推送请求失败, 状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"⚠️ Bark推送异常: {e}")
            return False
    
    def get_platform(self):
        """平台编码，PC端返回8"""
        return 8
    
    def get_encrypt_key(self):
        """获取RSA公钥"""
        url = f"{self.base_url}/sign_in/v1/encrypt/key"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            result = response.json()
            
            if result.get("result") == "ok" and result.get("data"):
                public_key_pem = base64.b64decode(result["data"]).decode('utf-8')
                self.rsa_public_key = public_key_pem
                return True
            else:
                return False
                
        except Exception as e:
            return False
    
    def generate_aes_key(self):
        """生成32位AES密钥"""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=22))
        timestamp = str(int(time.time()))
        return random_part + timestamp
    
    def rsa_encrypt_aes_key(self, aes_key):
        """RSA加密AES密钥"""
        if not self.rsa_public_key:
            raise Exception("RSA公钥未获取")
        
        try:
            rsa_key = RSA.import_key(self.rsa_public_key)
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted = cipher.encrypt(aes_key.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise
    
    def aes_encrypt_data(self, data, aes_key):
        """AES加密数据"""
        try:
            json_data = json.dumps(data, separators=(',', ':'))
            data_bytes = json_data.encode('utf-8')
            
            key_bytes = aes_key.encode('utf-8')
            iv_bytes = aes_key[:16].encode('utf-8')
            
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            padded_data = pad(data_bytes, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise
    
    def write_log(self, msg, ext_msg=None):
        """
        写入签到日志到 log/wps.txt，并推送 Bark 通知
        """
        try:
            log_file = self._get_log_path()
            
            # 获取当前时间
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 构建日志内容（含时间戳，用于本地文件）
            if ext_msg:
                log_content = f"[{timestamp}] 签到状态：{msg}，原因：{ext_msg}\n"
            else:
                log_content = f"[{timestamp}] 签到状态：{msg}\n"
            
            # 构建推送内容（不含时间戳）
            if ext_msg:
                push_content = f"签到状态：{msg}，原因：{ext_msg}"
            else:
                push_content = f"签到状态：{msg}"
            
            # 写入本地文件（覆盖模式）
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(log_content)
            
            print(f"✓ 签到日志已写入: {log_file}")
            
            # 推送 Bark 通知
            self._send_bark_notification(push_content)
            
            return True
        except Exception as e:
            print(f"✗ 写入日志失败: {e}")
            return False
    
    def sign_in(self):
        """执行签到"""
        if not self.get_encrypt_key():
            error_msg = "获取RSA公钥失败"
            self.write_log(error_msg)
            return {"status": "error", "msg": error_msg}
        
        aes_key = self.generate_aes_key()
        
        plain_data = {
            "user_id": int(self.user_id),
            "platform": self.get_platform()
        }
        
        extra = self.aes_encrypt_data(plain_data, aes_key)
        token = self.rsa_encrypt_aes_key(aes_key)
        
        url = f"{self.base_url}/sign_in/v1/sign_in"
        
        body = {
            "encrypt": True,
            "extra": extra,
            "pay_origin": "pc_ucs_rwzx_sign"
        }
        
        headers = self.headers.copy()
        headers["token"] = token
        
        try:
            response = requests.post(url, headers=headers, json=body, timeout=30)
            result = response.json()
            
            # 提取关键信息
            status_code = response.status_code
            result_msg = result.get("msg", "")
            ext_msg = result.get("ext_msg", "")
            
            # 打印结果
            print(f"状态码: {status_code}")
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            # 写入日志并推送通知
            if ext_msg:
                self.write_log(result_msg, ext_msg)
            else:
                self.write_log(result_msg)
            
            return {
                "status_code": status_code,
                "result": result
            }
                
        except Exception as e:
            error_msg = str(e)
            self.write_log(f"签到异常: {error_msg}")
            return {"status": "error", "msg": error_msg}


def main():
    # 检查必要环境变量
    if not USER_ID or not WPS_SID:
        print("❌ 错误: 缺少必要的环境变量")
        print("请设置以下环境变量:")
        print("  - WPS_USER_ID: WPS用户ID")
        print("  - WPS_SID: WPS会话ID (wps_sid的值)")
        return
    
    client = SignInClient(USER_ID)
    response = client.sign_in()


if __name__ == "__main__":
    main()
