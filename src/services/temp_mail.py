"""
Temp-Mail 邮箱服务实现
基于自部署 Cloudflare Worker 临时邮箱服务
接口文档参见 plan/temp-mail.md
"""

import re
import time
import json
import logging
from typing import Optional, Dict, Any, List

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..core.http_client import HTTPClient, RequestConfig
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)


class TempMailService(BaseEmailService):
    """
    Temp-Mail 邮箱服务
    基于自部署 Cloudflare Worker 的临时邮箱，admin 模式管理邮箱
    不走代理，不使用 requests 库
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, name: Optional[str] = None):
        """
        初始化 TempMail 服务

        Args:
            config: 配置字典，支持以下键:
                - base_url: Worker 域名地址，如 https://mail.example.com (必需)
                - admin_password: Admin 密码，对应 x-admin-auth header (必需)
                - domain: 邮箱域名，如 example.com (必需)
                - enable_prefix: 是否启用前缀，默认 True
                - timeout: 请求超时时间，默认 30
                - max_retries: 最大重试次数，默认 3
            name: 服务名称
        """
        super().__init__(EmailServiceType.TEMP_MAIL, name)

        if config and 'domain' not in config and 'default_domain' in config:
            config['domain'] = config['default_domain']

        required_keys = ["base_url", "admin_password", "domain"]
        missing_keys = [key for key in required_keys if not (config or {}).get(key)]
        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        default_config = {
            "enable_prefix": True,
            "timeout": 30,
            "max_retries": 3,
        }
        self.config = {**default_config, **(config or {})}

        # 不走代理，proxy_url=None
        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(proxy_url=None, config=http_config)

        # 邮箱缓存：email -> {jwt, address}
        self._email_cache: Dict[str, Dict[str, Any]] = {}

    def _admin_headers(self) -> Dict[str, str]:
        """构造 admin 请求头"""
        return {
            "x-admin-auth": self.config["admin_password"],
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _make_request(self, method: str, path: str, **kwargs) -> Any:
        """
        发送请求并返回 JSON 数据

        Args:
            method: HTTP 方法
            path: 请求路径（以 / 开头）
            **kwargs: 传递给 http_client.request 的额外参数

        Returns:
            响应 JSON 数据

        Raises:
            EmailServiceError: 请求失败
        """
        base_url = str(self.config["base_url"]).rstrip("/")
        url = f"{base_url}{path}"

        # 合并默认 admin headers
        kwargs.setdefault("headers", {})
        for k, v in self._admin_headers().items():
            kwargs["headers"].setdefault(k, v)

        try:
            response = self.http_client.request(method, url, **kwargs)

            if response.status_code >= 400:
                error_msg = f"请求失败: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg = f"{error_msg} - {error_data}"
                except Exception:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                self.update_status(False, EmailServiceError(error_msg))
                raise EmailServiceError(error_msg)

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"raw_response": response.text}

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"请求失败: {method} {path} - {e}")

    def create_email(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        通过 admin API 创建临时邮箱

        Returns:
            包含邮箱信息的字典:
            - email: 邮箱地址
            - jwt: 用户级 JWT token
            - service_id: 同 email（用作标识）
        """
        import random
        import string

        # 生成随机邮箱名
        letters = ''.join(random.choices(string.ascii_lowercase, k=5))
        digits = ''.join(random.choices(string.digits, k=random.randint(1, 3)))
        suffix = ''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
        name = letters + digits + suffix

        domain = self.config["domain"]
        enable_prefix = self.config.get("enable_prefix", True)

        body = {
            "enablePrefix": enable_prefix,
            "name": name,
            "domain": domain,
        }

        try:
            response = self._make_request("POST", "/admin/new_address", json=body)

            address = response.get("address", "").strip()
            jwt = response.get("jwt", "").strip()

            if not address:
                raise EmailServiceError(f"API 返回数据不完整: {response}")

            email_info = {
                "email": address,
                "jwt": jwt,
                "service_id": address,
                "id": address,
                "created_at": time.time(),
            }

            # 缓存 jwt，供获取验证码时使用
            self._email_cache[address] = email_info

            logger.info(f"成功创建 TempMail 邮箱: {address}")
            self.update_status(True)
            return email_info

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"创建邮箱失败: {e}")

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        """
        从 TempMail 邮箱获取验证码

        Args:
            email: 邮箱地址
            email_id: 未使用，保留接口兼容
            timeout: 超时时间（秒）
            pattern: 验证码正则
            otp_sent_at: OTP 发送时间戳（暂未使用）

        Returns:
            验证码字符串，超时返回 None
        """
        logger.info(f"正在从 TempMail 邮箱 {email} 获取验证码...")

        start_time = time.time()
        seen_mail_ids: set = set()

        # 优先使用用户级 JWT，回退到 admin API
        cached = self._email_cache.get(email, {})
        jwt = cached.get("jwt")

        while time.time() - start_time < timeout:
            try:
                if jwt:
                    logger.info(f"使用用户 JWT 获取邮件列表: {email}")
                    response = self._make_request(
                        "GET",
                        "/api/mails",
                        params={"limit": 20, "offset": 0},
                        headers={"Authorization": f"Bearer {jwt}", "Content-Type": "application/json", "Accept": "application/json"},
                    )
                else:
                    logger.info(f"使用 Admin API 获取邮件列表: {email}")
                    response = self._make_request(
                        "GET",
                        "/admin/mails",
                        params={"limit": 20, "offset": 0, "address": email},
                        headers={"x-admin-auth": self.config["admin_password"], "Content-Type": "application/json", "Accept": "application/json"},
                    )

                # /user_api/mails 和 /admin/mails 返回格式相同: {"results": [...], "total": N}
                mails = response.get("results")
                if mails is None:
                    logger.info(f"API 响应中找不到 'results' 键: {response}")
                    time.sleep(3)
                    continue

                if not isinstance(mails, list):
                    logger.info(f"API 响应的 'results' 不是列表: {type(mails)}")
                    time.sleep(3)
                    continue

                for mail in mails:
                    mail_id = mail.get("id")
                    if not mail_id or mail_id in seen_mail_ids:
                        continue

                    seen_mail_ids.add(mail_id)

                    # 提取关键字段
                    sender = str(mail.get("source", "") or mail.get("from", "")).lower()
                    raw_content = str(mail.get("raw", ""))
                    
                    # 尝试从 raw 中提取 Subject (因为列表可能不带它)
                    subject = ""
                    subject_match = re.search(r"(?i)^Subject:\s*(.*)$", raw_content, re.MULTILINE)
                    if subject_match:
                        subject = subject_match.group(1).strip()
                    else:
                        subject = str(mail.get("subject", ""))

                    # 1. 优先从主题匹配 (这是最准的)
                    # OpenAI 主题通常是: Your ChatGPT code is 123456
                    code_in_subject = re.search(r"code is\s*(\d{6})", subject, re.I)
                    if code_in_subject:
                        code = code_in_subject.group(1)
                        logger.info(f"从邮件 [Subject] 成功提取到验证码: {code} (ID: {mail_id})")
                        self.update_status(True)
                        return code

                    # 2. 如果主题没匹配到，处理正文
                    body_text = str(mail.get("text", "") or mail.get("html", "") or "")
                    # 清理 HTML
                    body_clean = re.sub(r"<[^>]+>", " ", body_text + " " + raw_content)
                    
                    # 检查是否包含关键字，防止误杀
                    if "openai" not in sender and "openai" not in body_clean.lower():
                        continue

                    # 只在包含 "verification code" 或 "code to continue" 的上下文里匹配
                    # 以防误匹配到 raw 中的时间戳 ID
                    strict_match = re.search(r"(?:code\s*is|code\s*to\s*continue)[^\d]*(\d{6})", body_clean, re.I)
                    if not strict_match:
                        # 兜底：使用通用正则，但仅限 body 中间区域
                        strict_match = re.search(pattern, body_clean)

                    if strict_match:
                        code = strict_match.group(1)
                        logger.info(f"从邮件 [Body] 成功提取到验证码: {code} (ID: {mail_id})")
                        self.update_status(True)
                        return code
                    else:
                        logger.info(f"邮件 {mail_id} 疑似 OpenAI 验证码邮件，但未能提取出 6 位数字")

            except Exception as e:
                logger.info(f"获取验证码轮询波出错: {e}")

            time.sleep(3)

        logger.warning(f"等待 TempMail 验证码超时: {email}")
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        """
        列出所有缓存的邮箱

        Note:
            Temp-Mail (自部署) 目前返回缓存的邮箱
        """
        return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """
        删除邮箱

        Args:
            email_id: 邮箱服务中的 ID (对应邮箱地址)

        Returns:
            是否删除成功
        """
        # 从缓存中查找并移除
        if email_id in self._email_cache:
            self._email_cache.pop(email_id, None)
            logger.info(f"从缓存中移除 TempMail 邮箱: {email_id}")
            return True

        # 如果 service_id 不是 email，尝试遍历查找
        email_to_delete = None
        for email, info in self._email_cache.items():
            if info.get("service_id") == email_id or info.get("id") == email_id:
                email_to_delete = email
                break

        if email_to_delete:
            self._email_cache.pop(email_to_delete, None)
            logger.info(f"从缓存中移除 TempMail 邮箱: {email_to_delete}")
            return True

        return False

    def check_health(self) -> bool:
        """检查服务健康状态"""
        try:
            self._make_request(
                "GET",
                "/admin/mails",
                params={"limit": 1, "offset": 0},
            )
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"TempMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False
