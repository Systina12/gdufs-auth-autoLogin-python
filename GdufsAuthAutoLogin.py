"""
GDUFS Auth Auto Login

Author: Systina12
GitHub: https://github.com/Systina12/gdufs-auth-autologin-python
Created: 2026-01
License: MIT

"""


import time
from requests import Session
from lxml import html
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class LoginError(Exception):
    pass

class GdufsAuthAutoLogin:
    def __init__(self,session:Session,username:str,password:str):
        self.authserver_url="https://authserver.gdufs.edu.cn"
        #方便日后应对换域名，新教务端看着就像匆忙上线的，谁知道以后呢
        self.login_url=self.authserver_url+r"/authserver/login"
        self.verify_ssl=True

        self.username = username
        self.password = password
        self.session = session
        self._init_session()

    def _init_session(self):
        #有些字段没必要，但是保持和浏览器一致
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Sec-Ch-Ua": r"\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\"",
            "Sec-Ch-Ua-Platform": "Windows",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        }
        self.session.headers.update(headers)
        #先获取一次cookie
        self.session.get(self.authserver_url,verify=self.verify_ssl)

    def _handle_captcha(self):
        #目前来说验证码不是必须的，可以直接submit表单，先写一遍占位
        captcha_url=self.authserver_url+r"/common/verifySliderCaptcha.htl"
        data={
            "canvasLength":340,
            "moveLength":65
        }

    def _get_param(self, text: str, param_id: str) -> str:
        tree = html.fromstring(text)

        # 只在登录表单 pwdFromId 内查找，有其他同id项，虽然内容实际相同但是以防万一
        elem = tree.xpath(
            f'//form[@id="pwdFromId"]//input[@id="{param_id}"]'
        )

        if not elem:
            raise LoginError(
                f"param '{param_id}' not found in form#pwdFromId"
            )

        value = elem[0].get("value")
        if value is None:
            raise LoginError(
                f"param '{param_id}' has no value attribute"
            )

        return value

    #从前端获取必要的参数
    def _get_event_id(self, text: str) -> str:
        return self._get_param(text, "_eventId")

    def _get_cllt(self, text: str) -> str:
        return self._get_param(text, "cllt")

    def _get_dllt(self, text: str) -> str:
        return self._get_param(text, "dllt")

    def _get_lt(self, text: str) -> str:
        return self._get_param(text, "lt")

    def _get_pwd_encrypt_salt(self, text: str) -> str:
        return self._get_param(text, "pwdEncryptSalt")

    def _get_execution(self, text: str) -> str:
        return self._get_param(text, "execution")

    def _get_timestamp(self) -> int:
        return int(time.time() * 1000)

    #实现js中的aes加密
    def _encrypt_password(self,password: str, salt: str) -> str:
        def random_string(length: int) -> str:
            AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
            return "".join(random.choice(AES_CHARS) for _ in range(length))

        # JS: randomString(64) + password
        plaintext = (random_string(64) + password).encode("utf-8")

        key = salt.encode("utf-8")
        iv = random_string(16).encode("utf-8")

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(ciphertext).decode("utf-8")

    def _pre_login_chain(self):
        #哪怕不做这个操作也可以直接硬编码 多因素浏览器指纹cookie，但是这里还是写了，以防万一
        #实际上sso是没有做这个cookie的动态下发的，而是硬编码了一个有效期到2094年的
        self.session.get(self.login_url,verify=self.verify_ssl)
        # combined_url=self.authserver_url+"/authserver/combinedLogin.do?type=weixin"
        # self.session.get(combined_url,verify=self.verify_ssl)
        tenant_url=self.authserver_url+"/authserver/tenant/info"
        self.session.get(tenant_url,verify=self.verify_ssl)
        bfp_url = self.authserver_url + f"/authserver/bfp/info?bfp=E6BB3635294256FEA4CCA29448B155A2&_={self._get_timestamp()}"
        self.session.get(bfp_url, verify=self.verify_ssl)
        need_captcha_url=self.authserver_url+f"/authserver/checkNeedCaptcha.htl?username={self.username}&_={self._get_timestamp()}"
        self.session.get(need_captcha_url,verify=self.verify_ssl)
        open_captcha_url=self.authserver_url+f"/authserver/common/openSliderCaptcha.htl?_={self._get_timestamp()}"
        self.session.get(open_captcha_url,verify=self.verify_ssl)
        #没什么大用但是保持一致
        self.session.cookies.set(
            name="org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE",
            value="zh_CN",
            domain="authserver.gdufs.edu.cn",
            path="/"
        )



    def login(self):
        self._pre_login_chain()
        response = self.session.get(self.login_url, verify=self.verify_ssl)
        text = response.text
        data = {
            "username": self.username,
            "password": (self._encrypt_password(self.password,self._get_pwd_encrypt_salt(text))),
            "captcha": '',
            "_eventId": self._get_event_id(text),
            "cllt": self._get_cllt(text),
            "dllt": self._get_dllt(text),
            "lt": self._get_lt(text),
            "execution": self._get_execution(text),
        }
        login_response=self.session.post(self.login_url,data=data,verify=self.verify_ssl)
        if login_response.status_code !=302:
            raise LoginError("LOGIN FAILED {}".format(login_response.status_code))