"""
Instagram Mobile API Registrar v1.0
Отправляет запросы как официальное приложение Instagram для Android
(не через браузер, а через нативное API)
"""

import json
import time
import random
import uuid
import hashlib
import hmac
import base64
import urllib.parse
from typing import Dict, Optional, Tuple

try:
    from curl_cffi import requests as curl_requests
    from curl_cffi.requests import Session as CurlSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ══════════════════════════════════════════════════════════════════════════════
#  MOBILE APP FINGERPRINT - Генерация отпечатка устройства Android
# ══════════════════════════════════════════════════════════════════════════════

class MobileDeviceFingerprint:
    """Генерирует реалистичный отпечаток Android устройства для Instagram API"""
    
    # Версии Instagram APK
    INSTAGRAM_VERSIONS = [
        "318.0.0.31.110",
        "317.0.0.28.109",
        "316.0.0.25.108",
        "315.0.0.22.107",
        "314.0.0.19.106",
    ]
    
    ANDROID_VERSIONS = ["12", "13", "14", "15"]
    ANDROID_SDK = {"12": "31", "13": "33", "14": "34", "15": "35"}
    
    # Реальные модели устройств
    DEVICES = [
        {"manufacturer": "Samsung", "model": "SM-G998B", "device": "galaxy_s21_ultra"},
        {"manufacturer": "Samsung", "model": "SM-G991B", "device": "galaxy_s21"},
        {"manufacturer": "Samsung", "model": "SM-A528B", "device": "galaxy_a52"},
        {"manufacturer": "Google", "model": "Pixel 6", "device": "oriole"},
        {"manufacturer": "Google", "model": "Pixel 7", "device": "panther"},
        {"manufacturer": "Google", "model": "Pixel 8", "device": "shiba"},
        {"manufacturer": "Xiaomi", "model": "2201123G", "device": "diting"},
        {"manufacturer": "OnePlus", "model": "CPH2447", "device": "oneplus_nord_3"},
    ]
    
    DPI_VALUES = [420, 480, 560, 640]
    RESOLUTIONS = [
        (1440, 3200),
        (1080, 2400),
        (1080, 2340),
        (1170, 2532),
    ]
    
    def __init__(self):
        device_info = random.choice(self.DEVICES)
        self.manufacturer = device_info["manufacturer"]
        self.model = device_info["model"]
        self.device = device_info["device"]
        
        self.android_version = random.choice(self.ANDROID_VERSIONS)
        self.android_sdk = self.ANDROID_SDK[self.android_version]
        
        self.instagram_version = random.choice(self.INSTAGRAM_VERSIONS)
        self.instagram_version_code = str(random.randint(350000000, 380000000))
        
        # Генерация уникальных идентификаторов устройства
        self.uuid = str(uuid.uuid4())
        self.phone_id = str(uuid.uuid4())
        self.advertising_id = str(uuid.uuid4())
        self.device_id = self._generate_device_id()
        self.request_id = str(uuid.uuid4())
        self.client_session_id = str(uuid.uuid4())
        
        # Аппаратные характеристики
        self.dpi = random.choice(self.DPI_VALUES)
        resolution = random.choice(self.RESOLUTIONS)
        self.screen_width = resolution[0]
        self.screen_height = resolution[1]
        
        # Язык и регион
        self.locale = "en_US"
        self.timezone_offset = random.choice([-300, -240, -360, -480, 0, -60])
        
    def _generate_device_id(self) -> str:
        """Генерирует Android device ID в формате 'android-xxxxxxxx'"""
        return f"android-{uuid.uuid4().hex[:16]}"
    
    @property
    def user_agent(self) -> str:
        """User-Agent официального приложения Instagram"""
        return (
            f"Instagram {self.instagram_version} "
            f"Android ({self.android_version}/{self.android_sdk}; "
            f"{self.dpi}dpi; {self.screen_width}x{self.screen_height}; "
            f"{self.manufacturer}; {self.model}; {self.device}; "
            f"en_US; {self.instagram_version_code})"
        )
    
    def get_signature_key(self) -> bytes:
        """Ключ для подписи запросов (HMAC-SHA256)"""
        # Статический ключ из приложения Instagram
        return b"5706f2a1597f4b191fb6c46a8b7a0a3e"
    
    def generate_sig_hash(self, data: str) -> str:
        """Генерирует подпись запроса"""
        signature = hmac.new(self.get_signature_key(), data.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    def get_headers(self, include_sig: bool = False, sig_data: str = None) -> Dict:
        """Заголовки для запросов к Instagram Mobile API"""
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US",
            "Accept-Encoding": "gzip, deflate",
            "X-IG-App-ID": "567067343352427",
            "X-IG-App-Locale": self.locale,
            "X-IG-Device-Locale": self.locale,
            "X-IG-Mapped-Locale": self.locale,
            "X-IG-Device-ID": self.device_id,
            "X-IG-Phone-ID": self.phone_id,
            "X-IG-UUID": self.uuid,
            "X-IG-Advertising-ID": self.advertising_id,
            "X-IG-Request-ID": self.request_id,
            "X-IG-Client-Session-ID": self.client_session_id,
            "X-IG-Capabilities": "3brFvxw=",
            "X-IG-Connection-Type": "WIFI",
            "X-IG-Connection-Speed": f"{random.randint(1000, 5000)}kbps",
            "X-IG-Bandwidth-SpeedKbps": f"{random.randint(2000, 8000)}.000",
            "X-IG-Bandwidth-TotalBytes-B": str(random.randint(1000000, 5000000)),
            "X-IG-Bandwidth-TotalTime-MS": str(random.randint(1000, 5000)),
            "X-IG-Android-ID": f"android-{self.uuid.hex[:16]}",
            "X-FB-HTTP-Engine": "Liger",
            "Host": "i.instagram.com",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
        
        if include_sig and sig_data:
            headers["X-IG-Signature"] = self.generate_sig_hash(sig_data)
        
        return headers


# ══════════════════════════════════════════════════════════════════════════════
#  MOBILE API SESSION - Сессия для работы с Instagram Mobile API
# ══════════════════════════════════════════════════════════════════════════════

class InstagramMobileSession:
    """Сессия для отправки запросов к Instagram Mobile API"""
    
    BASE_URL = "https://i.instagram.com"
    API_V1 = f"{BASE_URL}/api/v1"
    
    def __init__(self, proxy: Optional[str] = None, timeout: int = 30):
        self.proxy = proxy
        self.timeout = timeout
        self.fingerprint = MobileDeviceFingerprint()
        self.session = self._create_session()
        self.cookies = {}
        self.csrf_token = None
        self.device_id = self.fingerprint.device_id
        self.phone_id = self.fingerprint.phone_id
        self.uuid = self.fingerprint.uuid
        
    def _create_session(self):
        """Создает HTTP сессию с поддержкой прокси"""
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        
        if CURL_CFFI_AVAILABLE:
            try:
                sess = CurlSession(impersonate="chrome131", proxies=proxies, timeout=self.timeout)
                sess.max_redirects = 10
                return sess
            except Exception:
                pass
        
        # Fallback на requests
        sess = requests.Session()
        sess.proxies.update(proxies) if proxies else None
        retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        sess.mount("https://", adapter)
        return sess
    
    def _prepare_data(self, data: Dict) -> str:
        """Подготавливает данные для отправки (urlencoded + подпись)"""
        encoded = urllib.parse.urlencode(data)
        sig_hash = self.fingerprint.generate_sig_hash(encoded)
        return f"signed_body={sig_hash}.{encoded}"
    
    def _get_headers(self, include_sig: bool = False, sig_data: str = None) -> Dict:
        """Получает заголовки с актуальными cookies"""
        headers = self.fingerprint.get_headers(include_sig, sig_data)
        if self.csrf_token:
            headers["X-CSRFToken"] = self.csrf_token
        return headers
    
    def get(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """GET запрос к API"""
        url = f"{self.API_V1}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            # Извлечение CSRF токена из cookies
            if 'csrftoken' in response.cookies:
                self.csrf_token = response.cookies['csrftoken']
                self.cookies['csrftoken'] = self.csrf_token
            
            return response.json()
        except Exception as e:
            print(f"[!] GET error: {e}")
            return None
    
    def post(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """POST запрос к API с подписью"""
        url = f"{self.API_V1}/{endpoint.lstrip('/')}"
        prepared_data = self._prepare_data(data)
        headers = self._get_headers(include_sig=True, sig_data=prepared_data.split('.', 1)[1] if '.' in prepared_data else prepared_data)
        
        try:
            response = self.session.post(url, headers=headers, data=prepared_data, timeout=self.timeout)
            response.raise_for_status()
            
            # Извлечение CSRF токена
            if 'csrftoken' in response.cookies:
                self.csrf_token = response.cookies['csrftoken']
                self.cookies['csrftoken'] = self.csrf_token
            
            return response.json()
        except Exception as e:
            print(f"[!] POST error: {e}")
            return None
    
    def close(self):
        """Закрывает сессию"""
        self.session.close()


# ══════════════════════════════════════════════════════════════════════════════
#  MOBILE REGISTRAR - Регистрация через Instagram Mobile API
# ══════════════════════════════════════════════════════════════════════════════

class InstagramMobileRegistrar:
    """Регистрация аккаунтов через Instagram Mobile API"""
    
    def __init__(self, proxy: Optional[str] = None, timeout: int = 30):
        self.session = InstagramMobileSession(proxy, timeout)
        self.fp = self.session.fingerprint
        self.log = print
        
    def check_email(self, email: str) -> Dict:
        """Проверка доступности email"""
        data = {
            "email": email,
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_uid": "0",
            "_csrftoken": self.session.csrf_token or "missing",
        }
        
        result = self.session.post("accounts/check_email/", data)
        if result:
            self.log(f"[+] Проверка email: {result.get('status', 'unknown')}")
        return result or {}
    
    def check_username(self, username: str) -> Dict:
        """Проверка доступности username"""
        data = {
            "username": username,
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_uid": "0",
            "_csrftoken": self.session.csrf_token or "missing",
        }
        
        result = self.session.post("users/check_username/", data)
        if result:
            self.log(f"[+] Проверка username: {result.get('status', 'unknown')}")
        return result or {}
    
    def register_account(self, email: str, username: str, password: str, 
                        first_name: str = "", day: int = 1, month: int = 1, year: int = 2000) -> Dict:
        """Регистрация нового аккаунта"""
        data = {
            "email": email,
            "username": username,
            "password": password,
            "first_name": first_name,
            "day": str(day),
            "month": str(month),
            "year": str(year),
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_uid": "0",
            "_csrftoken": self.session.csrf_token or "missing",
            "force_sign_up_code": "",
            "waterfall_id": str(uuid.uuid4()),
            "one_tap_opt_in": True,
        }
        
        self.log(f"[*] Регистрация: {username} / {email}")
        result = self.session.post("accounts/create/", data)
        
        if result:
            status = result.get("status", "unknown")
            if status == "ok" and "account_created" in result:
                self.log(f"[✓] Аккаунт успешно создан!")
                if "logged_in_user" in result:
                    user = result["logged_in_user"]
                    self.log(f"    User ID: {user.get('pk')}")
                    self.log(f"    Username: {user.get('username')}")
            else:
                errors = result.get("errors", {})
                if errors:
                    self.log(f"[!] Ошибки: {json.dumps(errors, ensure_ascii=False)}")
        
        return result or {}
    
    def send_verification_code(self, email: str) -> Dict:
        """Отправка кода подтверждения на email"""
        data = {
            "email": email,
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_csrftoken": self.session.csrf_token or "missing",
        }
        
        result = self.session.post("accounts/send_verify_email/", data)
        if result:
            self.log(f"[+] Код отправлен: {result.get('status', 'unknown')}")
        return result or {}
    
    def verify_code(self, email: str, code: str) -> Dict:
        """Подтверждение кода из email"""
        data = {
            "email": email,
            "code": code,
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_csrftoken": self.session.csrf_token or "missing",
        }
        
        result = self.session.post("accounts/verify_code/", data)
        if result:
            self.log(f"[+] Код подтвержден: {result.get('status', 'unknown')}")
        return result or {}
    
    def login(self, username: str, password: str) -> Dict:
        """Вход в аккаунт"""
        data = {
            "username": username,
            "password": password,
            "phone_id": self.fp.phone_id,
            "device_id": self.fp.device_id,
            "uuid": self.fp.uuid,
            "_uuid": self.fp.uuid,
            "_csrftoken": self.session.csrf_token or "missing",
            "adid": self.fp.advertising_id,
            "guid": self.fp.uuid,
            "login_attempt_count": "0",
        }
        
        self.log(f"[*] Вход: {username}")
        result = self.session.post("accounts/login/", data)
        
        if result:
            status = result.get("status", "unknown")
            if status == "ok" and "logged_in_user" in result:
                self.log(f"[✓] Успешный вход!")
                user = result["logged_in_user"]
                self.log(f"    User ID: {user.get('pk')}")
        
        return result or {}
    
    def close(self):
        """Закрытие сессии"""
        self.session.close()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST / DEMO
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("Instagram Mobile API Registrar - Тестирование")
    print("=" * 70)
    
    # Создание сессии
    registrar = InstagramMobileRegistrar(proxy=None, timeout=30)
    
    # Информация об устройстве
    fp = registrar.fp
    print(f"\n[Device Info]")
    print(f"  Model: {fp.manufacturer} {fp.model}")
    print(f"  Android: {fp.android_version} (SDK {fp.android_sdk})")
    print(f"  Instagram: {fp.instagram_version}")
    print(f"  Device ID: {fp.device_id}")
    print(f"  Phone ID: {fp.phone_id}")
    print(f"  UUID: {fp.uuid}")
    print(f"\n  User-Agent:\n  {fp.user_agent}")
    
    # Пример проверки email (не выполняется без реальных данных)
    print("\n[Example Usage]")
    print("  registrar.check_email('test@example.com')")
    print("  registrar.check_username('myusername')")
    print("  registrar.register_account(email, username, password, ...)")
    print("  registrar.send_verification_code(email)")
    print("  registrar.verify_code(email, code)")
    
    registrar.close()
    print("\n[✓] Тест завершен")
