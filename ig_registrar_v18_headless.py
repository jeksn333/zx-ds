
import json, re, time, random, uuid, imaplib, email, threading, os, base64, struct, gzip, zlib, glob, sys
import hashlib, secrets, string
from http.cookiejar import Cookie as _CookieJarCookie

# Make the bundled phantomkit source tree importable when it has not been
# pip-installed. The project lives under phantomkit/ (parent) and the actual
# package lives under phantomkit/phantomkit/.  We add the parent so that
# "import phantomkit" finds the real __init__.py rather than the namespace dir.
try:
    import importlib as _il
    _il.invalidate_caches()
    import phantomkit as _pk_probe
    _pk_probe.__version__  # raises AttributeError if not the real package
    _PK_ALREADY_IMPORTABLE = True
except Exception:
    _PK_ALREADY_IMPORTABLE = False
    _pk_proj = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phantomkit")
    if os.path.isfile(os.path.join(_pk_proj, "phantomkit", "__init__.py")):
        sys.path.insert(0, _pk_proj)
        import importlib as _il2
        _il2.invalidate_caches()
        for _m in list(sys.modules):
            if _m == "phantomkit" or _m.startswith("phantomkit."):
                del sys.modules[_m]
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
import urllib.parse
from email.header import decode_header
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

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
#  PHANTOMKIT — Chrome-like TLS/HTTP2 transport + JS engine + fingerprints.
#  We use it as the browser frame (transport + fingerprint) underneath the
#  curl_cffi session, and as the source of truth for the hardware/network
#  fingerprint. All Instagram-specific glue (encrypt, GraphQL, bz, 2FA) stays.
# ══════════════════════════════════════════════════════════════════════════════
try:
    import phantomkit
    from phantomkit import Profile as _PKProfile, BrowserCore as _PKBrowserCore
    from phantomkit import HardwareFingerprint as _PKHardware
    from phantomkit import NetworkFingerprint as _PKNetwork
    from phantomkit import GEO_PRESETS as _PK_GEO_PRESETS, launch as _pk_launch
    PHANTOMKIT_AVAILABLE = True
except Exception as _pk_err:
    PHANTOMKIT_AVAILABLE = False
    _pk_err = _pk_err  # available for diagnostics
    _PKProfile = _PKBrowserCore = _PKHardware = _PKNetwork = None
    _PK_GEO_PRESETS = {}

# [M1] PyNaCl для шифрования пароля
try:
    from nacl.public import PublicKey, SealedBox
    PYNACL_AVAILABLE = True
except ImportError:
    PYNACL_AVAILABLE = False

try:
    from ig_hash_cache import get_hashes as _get_cached_hashes
    HASH_CACHE_AVAILABLE = True
except ImportError:
    HASH_CACHE_AVAILABLE = False

WEBSOCKET_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
#  BROWSER FINGERPRINT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class BrowserFingerprint:
    """Генерирует реалистичные отпечатки браузера Chrome. Каждый вызов = уникальный профиль."""

    CHROME_BUILDS = {
        130: "130.0.6723.119", 131: "131.0.6778.205", 132: "132.0.6834.159",
        133: "133.0.6943.143", 134: "134.0.6998.178", 135: "135.0.7049.120",
        136: "136.0.7103.114", 137: "137.0.7151.119", 138: "138.0.7204.101",
        139: "139.0.7258.93",  140: "140.0.7312.114", 141: "141.0.7370.96",
        142: "142.0.7420.72",  143: "143.0.7478.63",  144: "144.0.7532.116",
        145: "145.0.7632.160", 146: "146.0.7482.0",   147: "147.0.7727.137",
    }

    WINDOWS_VERSIONS = ["10.0.0", "10.0.19041", "10.0.22000", "10.0.22621", "10.0.26100"]
    PLATFORM_VERSIONS = ["15.0.0", "15.0.1", "15.0.2", "15.0.3"]

    def __init__(self, phantomkit_profile: "_PKProfile" = None, geo: Optional[str] = 'us',
                 proxy: Optional[str] = None, force_platform: Optional[str] = None,
                 languages: Optional[List[str]] = None, timezone: Optional[str] = None):
        """Build fingerprint.

        When phantomkit is installed, the profile (HardwareFingerprint +
        NetworkFingerprint: stable GPU/canvas/screen + dynamic TLS/HTTP2) becomes
        the source of truth for transport + the navigator/screen client hints a
        fingerprint script reads. All public attributes used by the registrar
        (chrome_major, sec_ch_ua, hw_profile, dpr, ig_did, datr, ...) are mirrored
        from the phantomkit profile so the IG-specific header builders keep working.

        When phantomkit is unavailable, a deterministic random Chrome/Windows
        profile is generated locally (the legacy behaviour, via _generate()).
        """
        self._pk_profile = None
        self._user_agent = None
        self._platform_hint = '"Windows"'
        if PHANTOMKIT_AVAILABLE:
            self._setup_from_phantomkit(
                phantomkit_profile or _PKProfile.create(
                    proxy=proxy, geo=geo,
                    timezone=timezone, languages=languages,
                    platform=force_platform,
                )
            )
        else:
            self._generate()

    # --- phantomkit-backed setup -------------------------------------------
    def _setup_from_phantomkit(self, profile: "_PKProfile"):
        """Mirror a phantomkit Profile into the attributes consumed by the registrar."""
        self._pk_profile = profile
        hw = profile.hardware
        net = profile.network

        self.chrome_major = str(hw.chrome_major)
        self.chrome_full_version = hw.ua_full_version

        brand_raw = hw.client_hints.get('sec-ch-ua', '') or (
            f'"Google Chrome";v="{self.chrome_major}", '
            f'"Not.A/Brand";v="8", "Chromium";v="{self.chrome_major}"'
        )
        # Normalize the phantomkit "Not?A_Brand;v=24" to the IG-style hint.
        self.sec_ch_ua = brand_raw.replace('"Not?A_Brand";v="24"',
                                           '"Not.A/Brand";v="8"') if 'Not?A_Brand' in brand_raw else brand_raw
        self.sec_ch_ua_full_version = (
            f'"Google Chrome";v="{self.chrome_full_version}", '
            f'"Not.A/Brand";v="8.0.0.0", "Chromium";v="{self.chrome_full_version}"'
        )

        self.hw_profile = {
            "device_memory": hw.device_memory,
            "rtt": random.choice([25, 50, 75, 100, 150, 200, 300, 400, 500, 600]),
            "downlink": random.choice([1.5, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0]),
            "screen_width": hw.screen_w,
            "screen_height": hw.screen_h,
            "viewport_width": hw.screen_w,
            "viewport_height": hw.avail_h or (hw.screen_h - random.randint(70, 120)),
        }

        self.dpr = hw.pixel_ratio
        self.platform_version = random.choice(self.PLATFORM_VERSIONS)

        # ig_did / datr are transport identifiers independent of the GPU print.
        self.ig_did = str(uuid.uuid4()).upper()
        self.datr = base64.b64encode(os.urandom(18)).decode().rstrip("=")

        # Stable fingerprint hashes seeded from the profile name so they are
        # deterministic per-proxy, mirroring phantomkit's hardware stability.
        _seed = (profile.name or 'profile').encode('utf-8', 'ignore')
        self.canvas_hash = hashlib.sha256(_seed + b':canvas').hexdigest()[:64]
        self.webgl_hash = hashlib.sha256(_seed + b':webgl').hexdigest()[:64]
        self.audio_hash = hashlib.sha256(_seed + b':audio').hexdigest()[:64]

        self.audio_sample_rate = random.choice([44100, 48000])
        self.audio_channel_count = random.choice([1, 2])

        # macOS + NVIDIA D3D11 is impossible; phantomkit's consistency_check()
        # would flag it. Coerce to a Windows GPU when the profile is macOS.
        if hw.platform == 'MacIntel':
            self.webgl_vendor, self.webgl_renderer = random.choice([
                ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
                ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ])
        else:
            self.webgl_vendor, self.webgl_renderer = hw.gpu_vendor, hw.gpu_renderer

        self.plugins = [
            {"name": "PDF Plugin", "description": "Portable Document Format", "filename": "internal-pdf-viewer"},
            {"name": "PDF Viewer", "description": "", "filename": "mhjfbmdgcfjbbpaeojofohoefgiehjai"},
            {"name": "Native Client", "description": "", "filename": "internal-nacl-plugin"},
        ]

        self.screen_color_depth = hw.color_depth
        self.screen_pixel_depth = hw.color_depth
        self.hardware_concurrency = hw.cpu_cores
        self.max_touch_points = hw.max_touch_points

        self.language = (hw.languages or ["en-US"])[0]
        self.languages = list(hw.languages or ["en-US", "en"])
        self.timezone = hw.timezone or "America/New_York"

        tz_offsets = {
            "America/New_York": random.choice([-300, -240]),
            "America/Chicago": -360, "America/Los_Angeles": -480,
            "Europe/London": 0, "Europe/Berlin": -60, "Europe/Paris": -60,
            "Europe/Moscow": -180, "Asia/Tashkent": -300,
        }
        self.timezone_offset = tz_offsets.get(self.timezone, 0)

        # IG wire hints are fixed to Windows; TLS impersonate is already aligned
        # by phantomkit NetworkFingerprint.for_hardware.
        self._user_agent = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            f"AppleWebKit/537.36 (KHTML, like Gecko) "
                            f"Chrome/{self.chrome_major}.0.0.0 Safari/537.36")

    @property
    def pk_profile(self):
        return self._pk_profile

    def as_pk_profile(self, proxy: Optional[str] = None) -> "_PKProfile":
        """Return the underlying phantomkit Profile, optionally overriding proxy."""
        if not PHANTOMKIT_AVAILABLE:
            return None
        if self._pk_profile is not None:
            if proxy is not None and proxy != self._pk_profile.proxy:
                self._pk_profile.proxy = proxy
            return self._pk_profile
        self._pk_profile = _PKProfile.create(proxy=proxy, geo='us')
        self._setup_from_phantomkit(self._pk_profile)
        return self._pk_profile

    @property
    def user_agent(self) -> str:
        if self._user_agent:
            return self._user_agent
        return self.__dict__.get('user_agent', '') or (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{self.chrome_major}.0.0.0 Safari/537.36"
        )

    @user_agent.setter
    def user_agent(self, value: str):
        self._user_agent = value
        self.__dict__['user_agent'] = value

    def _generate(self):
        """Generate a complete unique fingerprint."""
        major = random.randint(130, 147)
        self.chrome_major = str(major)
        self.chrome_full_version = self.CHROME_BUILDS.get(major, f"{major}.0.7000.100")

        self.user_agent = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36"
        )

        self.sec_ch_ua = (
            f'"Google Chrome";v="{major}", '
            f'"Not.A/Brand";v="8", "Chromium";v="{major}"'
        )
        self.sec_ch_ua_full_version = (
            f'"Google Chrome";v="{self.chrome_full_version}", '
            f'"Not.A/Brand";v="8.0.0.0", "Chromium";v="{self.chrome_full_version}"'
        )

        mem_choices = [2, 4, 8, 8, 8, 16, 16, 32]
        screen_choices = [
            (1920, 1080), (1920, 1080), (1920, 1080),
            (2560, 1440), (1440, 900), (1366, 768),
            (1280, 800),  (1600, 900),
        ]
        w, h = random.choice(screen_choices)
        self.hw_profile = {
            "device_memory": random.choice(mem_choices),
            "rtt": random.choice([25, 50, 75, 100, 150, 200]),
            "downlink": random.choice([1.5, 5.0, 10.0, 20.0, 50.0]),
            "screen_width": w,
            "screen_height": h,
            "viewport_width": w,
            "viewport_height": h - random.randint(70, 120),
        }

        dpr_choices = [1.0, 1.25, 1.5, 2.0, 2.5, 3.0]
        self.dpr = random.choice(dpr_choices)

        self.platform_version = random.choice(self.PLATFORM_VERSIONS)

        self.ig_did = str(uuid.uuid4()).upper()
        self.datr = base64.b64encode(os.urandom(18)).decode().rstrip("=")

        self.canvas_hash = hashlib.sha256(os.urandom(32)).hexdigest()[:64]
        self.webgl_hash = hashlib.sha256(os.urandom(32)).hexdigest()[:64]
        self.audio_hash = hashlib.sha256(os.urandom(32)).hexdigest()[:64]

        self.audio_sample_rate = random.choice([44100, 48000])
        self.audio_channel_count = random.choice([1, 2])

        webgl_renderers = [
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) HD Graphics 530 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 5600 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ]
        self.webgl_vendor, self.webgl_renderer = random.choice(webgl_renderers)

        self.plugins = [
            {"name": "PDF Plugin", "description": "Portable Document Format", "filename": "internal-pdf-viewer"},
            {"name": "PDF Viewer", "description": "", "filename": "mhjfbmdgcfjbbpaeojofohoefgiehjai"},
            {"name": "Native Client", "description": "", "filename": "internal-nacl-plugin"},
        ]

        self.screen_color_depth = random.choice([24, 30, 32])
        self.screen_pixel_depth = random.choice([24, 30, 32])

        self.hardware_concurrency = random.choice([2, 4, 6, 8, 12, 16])
        self.max_touch_points = 0

        self.language = "en-US"
        self.languages = ["en-US", "en"]

        self.timezone = "America/New_York"
        self.timezone_offset = random.choice([-300, -360, -420, -480, 0, 60, 120, 180])

    def get_nav_headers(self, referer=None, from_google=False):
        """Generate navigation headers for page loads."""
        fetch_site = "cross-site" if from_google else "none"
        ref = referer or ("https://www.google.com/" if from_google else None)

        h = {
            "User-Agent": self.user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,image/apng,*/*;"
                "q=0.8,application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": self.sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Ch-Ua-Full-Version-List": self.sec_ch_ua_full_version,
            "Sec-Ch-Ua-Full-Version": f'"{self.chrome_full_version}"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Platform-Version": f'"{self.platform_version}"',
            "Sec-Ch-Ua-Model": '""',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Wow64": "?0",
            "Sec-Ch-Ua-Form-Factors": '"Desktop"',
            "Sec-Ch-Prefers-Color-Scheme": "light",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": fetch_site,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Priority": "u=0, i",
        }
        if ref:
            h["Referer"] = ref
        return h

    def get_api_headers(self, csrf_token=None, lsd=None, ig_www_claim=None):
        """Generate AJAX/API headers for GraphQL requests."""
        h = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Origin": "https://www.instagram.com",
            "Referer": "https://www.instagram.com/accounts/emailsignup/?next=",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Ch-Ua": self.sec_ch_ua,
            "Sec-Ch-Ua-Full-Version-List": self.sec_ch_ua_full_version,
            "Sec-Ch-Ua-Full-Version": f'"{self.chrome_full_version}"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Model": '""',
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Ch-Ua-Platform-Version": f'"{self.platform_version}"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Wow64": "?0",
            "Sec-Ch-Ua-Form-Factors": '"Desktop"',
            "Sec-Ch-Prefers-Color-Scheme": "light",
            "Dpr": str(self.dpr),
            "Viewport-Width": str(self.hw_profile["viewport_width"]),
            "X-IG-App-ID": "936619743392459",
            "X-IG-Max-Touch-Points": "0",
            "X-ASBD-ID": "359341",
            "Priority": "u=1, i",
        }
        if ig_www_claim and ig_www_claim != "0":
            h["X-IG-WWW-Claim"] = ig_www_claim
        if csrf_token:
            h["X-CSRFToken"] = csrf_token
        if lsd:
            h["X-FB-LSD"] = lsd
        return h


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY POOL
# ══════════════════════════════════════════════════════════════════════════════

class ProxyPool:
    """Round-robin пул прокси. Формат строки: ip:port:login:pass или ip:port"""

    def __init__(self):
        self._proxies: List[str] = []
        self._idx = 0
        self._lock = threading.RLock()

    def load(self, text: str):
        self._proxies = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            url = self._parse(line)
            if url:
                self._proxies.append(url)
        self._idx = 0

    @staticmethod
    def _parse(line: str) -> Optional[str]:
        parts = line.split(':')
        if len(parts) == 2:
            return f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            ip, port, login, password = parts
            login_enc = urllib.parse.quote(login, safe='')
            pass_enc  = urllib.parse.quote(password, safe='')
            return f"http://{login_enc}:{pass_enc}@{ip}:{port}"
        return None

    def next(self) -> Optional[str]:
        with self._lock:
            if not self._proxies:
                return None
            url = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
            return url

    def count(self) -> int:
        return len(self._proxies)


# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL POOL
# ══════════════════════════════════════════════════════════════════════════════

class EmailPool:
    """Пул почт. Формат: email:password (по одной на строку)."""

    def __init__(self):
        self._emails: List[Tuple[str, str]] = []
        self._lock = threading.RLock()

    def load(self, text: str):
        self._emails = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or ':' not in line:
                continue
            addr, pwd = line.split(':', 1)
            addr = addr.strip()
            pwd  = pwd.strip()
            if addr and pwd:
                self._emails.append((addr, pwd))

    def pop(self) -> Optional[Tuple[str, str]]:
        with self._lock:
            if not self._emails:
                return None
            return self._emails.pop(0)

    def count(self) -> int:
        with self._lock:
            return len(self._emails)

    def to_text(self) -> str:
        with self._lock:
            return '\n'.join(f"{a}:{p}" for a, p in self._emails)


# ══════════════════════════════════════════════════════════════════════════════
#  ENHANCED CURL BACKEND — HTTP/2 + Browser Fingerprinting
# ══════════════════════════════════════════════════════════════════════════════

class _CurlBackend:
    """HTTP backend.

    When phantomkit is available, the underlying curl_cffi session is owned by a
    phantomkit BrowserCore that aligns the TLS/HTTP2 impersonation target with the
    Chrome major of the fingerprint, calls network.rotate() per connection (real
    Chrome reshuffles its TLS suites) and keeps the consistency check runnable.

    When phantomkit is unavailable, fall back to a curl_cffi Session picked from a
    best-effort impersonation list, and finally to the requests library.
    """

    def __init__(self, proxy=None, timeout=30, log_fn=None, fingerprint=None):
        self.log = log_fn or print
        self.fingerprint = fingerprint
        self.cookies = None
        self._core = None  # phantomkit BrowserCore, kept alive for its session

        pk_profile = fingerprint.as_pk_profile(proxy=proxy) if fingerprint else None

        if PHANTOMKIT_AVAILABLE and pk_profile is not None:
            try:
                self._core = _PKBrowserCore(pk_profile, verify=True, timeout=timeout,
                                            js=False, http2=True)
                sess = self._core.session
                try:
                    sess.max_redirects = 10
                except Exception:
                    pass
                self._s = sess
                self._is_curl = True
                self.cookies = sess.cookies
                self._pk_profile = pk_profile
                if fingerprint:
                    self._apply_fingerprint_cookies(fingerprint)
                problems = self._core.consistency_check()
                if problems:
                    self.log("[~] [phantomkit] consistency warnings: " + "; ".join(problems))
                return
            except Exception as e:
                self.log(f"[~] phantomkit BrowserCore init failed ({e}) — falling back")

        if not CURL_CFFI_AVAILABLE:
            self.log("[!] curl_cffi не установлен — fallback на requests (без HTTP/2)")
            self._init_requests_fallback(proxy, timeout)
            return

        proxies = {"http": proxy, "https": proxy} if proxy else None
        sess = None

        for ver in ("chrome131", "chrome124", "chrome120", "chrome110"):
            try:
                sess = CurlSession(impersonate=ver, proxies=proxies, timeout=timeout)
                try:
                    sess.max_redirects = 10
                except Exception:
                    pass
                break
            except Exception:
                sess = None

        if sess is None:
            self.log("[!] curl_cffi: не удалось создать сессию — fallback на requests")
            self._init_requests_fallback(proxy, timeout)
            return

        self._s = sess
        self._is_curl = True
        self.cookies = sess.cookies

        if fingerprint:
            self._apply_fingerprint_cookies(fingerprint)

    def _init_requests_fallback(self, proxy, timeout):
        """Fallback to requests library when curl_cffi is unavailable."""
        self._s = requests.Session()
        r = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        a = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=r)
        self._s.mount("http://", a)
        self._s.mount("https://", a)
        if proxy:
            self._s.proxies = {"http": proxy, "https": proxy}
        self._s.timeout = timeout
        self._is_curl = False
        self.cookies = self._s.cookies

    def set_cookie(self, name, value, domain=".instagram.com", path="/",
                   http_only=False, secure=True):
        """Устанавливает куку через curl_cffi Cookies API."""
        try:
            self.cookies.set(name, value, domain=domain, path=path, secure=secure)
        except Exception as e:
            self.log(f"[~] set_cookie({name}): {e}")

    def _apply_fingerprint_cookies(self, fp):
        """Apply fingerprint-generated cookies to session."""
        try:
            self.set_cookie("ig_did", fp.ig_did, http_only=True)
            self.set_cookie("datr", fp.datr, http_only=True)
            self.set_cookie("dpr", str(fp.dpr), secure=False)
            wd_w = fp.hw_profile["viewport_width"]
            wd_h = fp.hw_profile["viewport_height"]
            self.set_cookie("wd", f"{wd_w}x{wd_h}", secure=False)
        except Exception as e:
            self.log(f"[~] Ошибка установки fingerprint cookies: {e}")

    def get(self, url, headers=None, timeout=30, allow_redirects=True, **kw):
        self._pk_rotate()
        return self._s.get(url, headers=headers, timeout=timeout,
                           allow_redirects=allow_redirects, **kw)

    def post(self, url, headers=None, data=None, timeout=30, allow_redirects=True, **kw):
        self._pk_rotate()
        return self._s.post(url, headers=headers, data=data, timeout=timeout,
                            allow_redirects=allow_redirects, **kw)

    def _pk_rotate(self):
        """Rotate the dynamic network print before a new connection, like real Chrome."""
        try:
            if self._core is not None:
                self._core.profile.network.rotate()
        except Exception:
            pass

    def close(self):
        try:
            if self._core is not None:
                self._core.close()
            else:
                self._s.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  [M1] PASSWORD ENCRYPTION  —  #PWD_BROWSER:10
# ══════════════════════════════════════════════════════════════════════════════

def _encrypt_password(password: str, pub_key_hex: str, key_id: int) -> str:
    """
    Шифрует пароль по стандарту #PWD_BROWSER:10.

    Формат:
      1. Генерируем случайный 32-байт AES-256 ключ
      2. AES-256-GCM шифруем пароль (nonce=12x0x00, AAD=timestamp строкой)
      3. SealedBox шифруем AES ключ публичным ключом Instagram
      4. Payload = version(1) + key_id(1) + sealed_key_len(2 LE) + sealed_key + tag(16) + ciphertext

    Выход: #PWD_BROWSER:10:{timestamp}:{base64(payload)}
    """
    if not PYNACL_AVAILABLE:
        return password

    try:
        from Cryptodome.Cipher import AES as AES_Cipher
        from Cryptodome.Random import get_random_bytes
    except ImportError:
        try:
            from Crypto.Cipher import AES as AES_Cipher
            from Crypto.Random import get_random_bytes
        except ImportError:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                _USE_CRYPTOGRAPHY = True
            except ImportError:
                return password
            else:
                _USE_CRYPTOGRAPHY = True
                AES_Cipher = None
                get_random_bytes = None
    else:
        _USE_CRYPTOGRAPHY = False

    try:
        ts = int(time.time())

        # 1. Random AES-256 key
        rand_key = os.urandom(32)

        # 2. AES-256-GCM encrypt the password
        iv = bytes(12)  # 12 zero bytes
        aad = str(ts).encode('utf-8')

        if _USE_CRYPTOGRAPHY:
            aesgcm = AESGCM(rand_key)
            ct_and_tag = aesgcm.encrypt(iv, password.encode('utf-8'), aad)
            ciphertext = ct_and_tag[:-16]
            tag = ct_and_tag[-16:]
        else:
            cipher = AES_Cipher.new(rand_key, AES_Cipher.MODE_GCM, nonce=iv, mac_len=16)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))

        # 3. SealedBox encrypt the AES key with Instagram's public key
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        pub_key_obj = PublicKey(pub_key_bytes)
        sealed_key = SealedBox(pub_key_obj).encrypt(rand_key)

        # 4. Build payload: version + key_id + key_len(LE) + sealed_key + tag + ciphertext
        payload = bytes([1, key_id])
        payload += struct.pack('<h', len(sealed_key))
        payload += sealed_key
        payload += tag
        payload += ciphertext

        encoded = base64.b64encode(payload).decode('ascii')
        return f"#PWD_BROWSER:10:{ts}:{encoded}"
    except Exception:
        return password


def _parse_encryption_keys(html: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Парсит encryption_key и key_id из sharedData в HTML страницы регистрации.
    Instagram рендерит их в JSON-объекте window._sharedData или
    в inline-скриптах как encryptionConfig.
    """
    # Способ 1: window._sharedData JSON
    m = re.search(r'window\._sharedData\s*=\s*(\{.+?\});\s*</script>', html, re.S)
    if m:
        try:
            shared = json.loads(m.group(1))
            enc = (shared.get("encryption") or
                   (shared.get("config") or {}).get("encryption") or {})
            key     = enc.get("public_key") or enc.get("encryption_key")
            key_id  = enc.get("public_key_id") or enc.get("key_id")
            if key and key_id is not None:
                return key, int(key_id)
        except Exception:
            pass

    # Способ 2: Новый формат InstagramPasswordEncryption массива в Polaris
    m2 = re.search(
        r'\["InstagramPasswordEncryption"\s*,\s*\[\]\s*,\s*\{"key_id"\s*:\s*"(\d+)"\s*,\s*"public_key"\s*:\s*"([0-9a-fA-F]+)"',
        html)
    if m2:
        return m2.group(2), int(m2.group(1))

    # Способ 3: Старый объект encryptionConfig в inline script
    m3 = re.search(
        r'"encryption"\s*:\s*\{\s*"public_key"\s*:\s*"([0-9a-fA-F]+)"\s*,'
        r'\s*"public_key_id"\s*:\s*(\d+)',
        html)
    if m3:
        return m3.group(1), int(m3.group(2))

    # Способ 4: отдельные поля
    key_m   = re.search(r'"public_key"\s*:\s*"([0-9a-fA-F]{64,})"', html)
    key_id_m= re.search(r'"key_id"\s*:\s*"(\d+)"', html)
    if not key_id_m:
        key_id_m= re.search(r'"public_key_id"\s*:\s*(\d+)', html)
    if key_m and key_id_m:
        return key_m.group(1), int(key_id_m.group(1))

    return None, None


# ══════════════════════════════════════════════════════════════════════════════
#  CORE REGISTRAR — Headless HTTP-only (no browser/CDP dependency)
# ══════════════════════════════════════════════════════════════════════════════

class InstagramRegistrar:

    DOC_ID_INIT = "25761199393541178"
    DOC_ID_VALIDATION = "26387190147557007"
    DOC_ID_SUBMIT = "25782408224726258"
    DOC_ID_CONFIRM_FORM = "26495728670063238"
    DOC_ID_CONFIRM_SEO = "23913765558231629"
    DOC_ID_CONFIRM = "24050931851170558"

    BASE_URL = "https://www.instagram.com"
    GRAPHQL_URL = f"{BASE_URL}/api/graphql"
    CHECK_SIGNUP_URL = f"{BASE_URL}/api/v1/web/accounts/check_signup_order/"
    WEB_CREATE_URL = f"{BASE_URL}/api/v1/web/accounts/web_create_ajax/"

    _IG_REV = ""
    _IG_HS = ""
    _JAZOEST = ""

    _MUTATION_PARAMS = {
        "CAARegistrationFormDesktopQuery": {
            "__crn": "comet.igweb.PolarisCAAIGLoginHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "175125627,516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=175125627,516759801"]',
        },
        "CAAConfirmationFormDesktopQuery": {
            "__crn": "comet.igweb.PolarisCAAIGRegistrationHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=516759801"]',
        },
        "CAARegistrationConfirmationSeoLinksQuery": {
            "__crn": "comet.igweb.PolarisCAAIGRegistrationHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=516759801"]',
        },
        "useCAARegistrationFieldValidationQuery": {
            "__crn": "comet.igweb.PolarisCAAIGRegistrationHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "175125627,516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=175125627,516759801"]',
        },
        "useCAARegistrationFormSubmitMutation": {
            "__crn": "comet.igweb.PolarisCAAIGRegistrationHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "250359044,516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=250359044,516759801"]',
        },
        "useCAAFBConfirmationFormSubmitMutation": {
            "__crn": "comet.igweb.PolarisCAAIGRegistrationHomepageRoute",
            "__dyn": "", "__csr": "", "__hsdp": "", "__hblp": "", "__sjsp": "",
            "qpl_active_flow_ids": "250360002,516759801",
            "fb_api_analytics_tags": '["qpl_active_flow_ids=250360002,516759801"]',
        },
    }

    def __init__(self, proxy=None, timeout=30, log_fn=None, fingerprint=None):
        self.fingerprint = fingerprint or BrowserFingerprint(proxy=proxy)
        self.session = _CurlBackend(proxy, timeout, log_fn=log_fn, fingerprint=self.fingerprint)
        self.proxy = proxy
        self._using_browser = False
        self._session_lock = threading.RLock()
        self._adspower = None
        self.ig_did = self.fingerprint.ig_did
        self.mid = None
        self.csrf_token = None
        self._chrome_major = str(self.fingerprint.chrome_major)
        self._chrome_full_version = self.fingerprint.chrome_full_version
        self.user_agent = self.fingerprint.user_agent
        self.accept_language = "en-US,en;q=0.9"
        self.lsd = None
        self.fb_dtsg = None
        self.waterfall_id = str(uuid.uuid4())
        self.client_mutation_id = str(uuid.uuid4())
        self._IG_HSI = str(random.randint(7_000_000_000_000_000_000, 7_999_999_999_999_999_999))
        self.user_id = None
        self.log = log_fn or print
        self._session_str = self._random_session_str()
        self._web_analytics_session_id = self._random_session_str()
        self._bz_device_id = str(uuid.uuid4()).upper()
        self._req_counter = random.randint(2, 6)
        self.ig_www_claim = "0"
        self._x_asbd_id = "359341"
        self._enc_pub_key = None
        self._enc_key_id = None
        self._hw_profile = self.fingerprint.hw_profile.copy()
        self._real_dpr = self.fingerprint.dpr
        self._IG_REV = ""
        self._IG_HS = ""
        self._IG_SPIN_T = str(int(time.time()))
        self._JAZOEST = ""
        self._runtime_param_rev = ""
        self._runtime_hash_source = "fallback"
        self._ac_dyn = ""
        self._ac_csr = ""
        self._ac_hsdp = ""
        self._ac_hblp = ""
        self._ac_sjsp = ""
        self._ac_hs = ""
        self._ac_jazoest = None
        self._doc_ids = {
            "CAARegistrationFormDesktopQuery": self.DOC_ID_INIT,
            "useCAARegistrationFieldValidationQuery": self.DOC_ID_VALIDATION,
            "useCAARegistrationFormSubmitMutation": self.DOC_ID_SUBMIT,
            "CAAConfirmationFormDesktopQuery": self.DOC_ID_CONFIRM_FORM,
            "CAARegistrationConfirmationSeoLinksQuery": self.DOC_ID_CONFIRM_SEO,
            "useCAAFBConfirmationFormSubmitMutation": self.DOC_ID_CONFIRM,
        }
        self._pre_imap_max_id = 0  # set by _imap_pre_check before submit
        import copy as _copy
        self._MUTATION_PARAMS = _copy.deepcopy(InstagramRegistrar._MUTATION_PARAMS)

    @staticmethod
    def _random_session_str() -> str:
        def seg():
            return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        return f"{seg()}:{seg()}:{seg()}"

    def _next_req(self) -> str:
        n = self._req_counter
        self._req_counter += 1
        if n < 10:
            return str(n)
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        res = ""
        while n:
            res = chars[n % 36] + res
            n //= 36
        return res or "0"

    def _get_ccg(self) -> str:
        r = random.random()
        if r < 0.78:
            return "EXCELLENT"
        return "GOOD"

    def _safe_get(self, *args, **kwargs):
        with self._session_lock:
            return self.session.get(*args, **kwargs)

    def _safe_post(self, *args, **kwargs):
        with self._session_lock:
            return self.session.post(*args, **kwargs)

    def _bg_call(self, fn, *args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True).start()

    def _random_user_agent(self) -> str:
        return self.user_agent

    def _sec_ch_ua(self) -> str:
        m = self._chrome_major
        if int(m) >= 100:
            return (f'"Google Chrome";v="{m}", '
                    f'"Not.A/Brand";v="8", "Chromium";v="{m}"')
        return (f'"Chromium";v="{m}", '
                f'"Google Chrome";v="{m}", "Not/A)Brand";v="99"')

    def _sec_ch_ua_full_list(self) -> str:
        fv = self._chrome_full_version
        m = self._chrome_major
        if int(m) >= 100:
            return (f'"Google Chrome";v="{fv}", '
                    f'"Not.A/Brand";v="8.0.0.0", "Chromium";v="{fv}"')
        return (f'"Chromium";v="{fv}", '
                f'"Google Chrome";v="{fv}", "Not/A)Brand";v="99.0.0.0"')

    def _update_claim_from_response(self, resp):
        try:
            new_claim = resp.headers.get("x-ig-set-www-claim")
            if new_claim and new_claim != self.ig_www_claim:
                self.ig_www_claim = new_claim
        except Exception:
            pass

    @staticmethod
    def _lang_to_accept(lang: str) -> str:
        if ',' in lang or 'q=' in lang:
            return lang
        _map = {
            'ru': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'en': 'en-US,en;q=0.9',
            'de': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
            'fr': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'es': 'es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        return _map.get(lang, 'en-US,en;q=0.9')

    def _generate_headers(self, extra: Dict = None) -> Dict:
        fp = self.fingerprint
        hw = self._hw_profile
        lang = self._lang_to_accept(self.accept_language)

        h = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": lang,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Origin": self.BASE_URL,
            "Referer": f"{self.BASE_URL}/accounts/emailsignup/?next=",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Ch-Ua": fp.sec_ch_ua,
            "Sec-Ch-Ua-Full-Version-List": fp.sec_ch_ua_full_version,
            "Sec-Ch-Ua-Full-Version": f'"{self._chrome_full_version}"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Model": '""',
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Ch-Ua-Platform-Version": f'"{fp.platform_version}"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Wow64": "?0",
            "Sec-Ch-Ua-Form-Factors": '"Desktop"',
            "Sec-Ch-Prefers-Color-Scheme": "light",
            "Dpr": str(self._real_dpr) if self._real_dpr else "1",
            "Viewport-Width": str(hw["viewport_width"]),
            "X-IG-App-ID": "936619743392459",
            "X-IG-Max-Touch-Points": "0",
            "X-ASBD-ID": self._x_asbd_id,
            "Priority": "u=1, i",
        }
        if self.ig_www_claim and self.ig_www_claim != "0":
            h["X-IG-WWW-Claim"] = self.ig_www_claim
        if self.csrf_token:
            h["X-CSRFToken"] = self.csrf_token
        if self.lsd:
            h["X-FB-LSD"] = self.lsd
        if extra:
            h.update(extra)
        return h

    def _generate_nav_headers(self, referer=None, from_google=False) -> Dict:
        fp = self.fingerprint
        hw = self._hw_profile
        lang = self._lang_to_accept(self.accept_language)
        fetch_site = "cross-site" if from_google else "none"
        ref = referer or ("https://www.google.com/" if from_google else None)

        h = {
            "User-Agent": self.user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,image/apng,*/*;"
                "q=0.8,application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": lang,
            "Sec-Ch-Ua": fp.sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Ch-Ua-Full-Version-List": fp.sec_ch_ua_full_version,
            "Sec-Ch-Ua-Full-Version": f'"{self._chrome_full_version}"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Platform-Version": f'"{fp.platform_version}"',
            "Sec-Ch-Ua-Model": '""',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Wow64": "?0",
            "Sec-Ch-Ua-Form-Factors": '"Desktop"',
            "Sec-Ch-Prefers-Color-Scheme": "light",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": fetch_site,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Priority": "u=0, i",
        }
        if ref:
            h["Referer"] = ref
        return h

    def _extract_lsd_from_text(self, text: str) -> Optional[str]:
        patterns = [
            r'"LSD",\s*\[\s*\],\s*\{"token"\s*:\s*"([^"]+)"',
            r'"lsd"[,\s]*{"token":"([^"]+)"',
            r'"lsd"\s*,\s*\[\s*\]\s*,\s*\{"token"\s*:\s*"([^"]+)"',
            r'name="lsd"\s+value="([^"]+)"',
            r'"lsd"\s*:\s*\{"token"\s*:\s*"([^"]+)"',
            r'"lsd":"([^"]+)"',
            r'LSD[^"]*"token"\s*:\s*"([^"]+)"',
            r'\["LSD",\[\],\{"token":"([^"]+)"',
        ]
        for p in patterns:
            m = re.search(p, text)
            if m:
                return m.group(1)
        return None

    def _extract_doc_ids_from_text(self, text: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        if not text:
            return found
        for friendly_name, fallback in list(self._doc_ids.items()):
            patterns = [
                rf'"{re.escape(friendly_name)}"[^\n\r]{{0,1200}}?"doc_id"\s*:\s*"?(\d{{8,20}})"?',
                rf'"doc_id"\s*:\s*"?(\d{{8,20}})"?[^\n\r]{{0,1200}}?"{re.escape(friendly_name)}"',
                rf'fb_api_req_friendly_name={re.escape(friendly_name)}[^\n\r]{{0,2000}}?doc_id=(\d{{8,20}})',
                rf'doc_id=(\d{{8,20}})[^\n\r]{{0,2000}}?fb_api_req_friendly_name={re.escape(friendly_name)}',
            ]
            for pat in patterns:
                m = re.search(pat, text, re.S)
                if m:
                    found[friendly_name] = m.group(1)
                    break
        return found

    def _refresh_runtime_context(self, html="", refresh_doc_ids=True):
        if html:
            self._extract_dynamic_params(html)
            if refresh_doc_ids:
                parsed = self._extract_doc_ids_from_text(html)
                if parsed:
                    self._doc_ids.update(parsed)
                    self.log(f"[+] [DYN] doc_id updated from HTML: {', '.join(sorted(parsed.keys()))}")

    def _send_navigation_event(self, route_urls, crn, flow_ids="516759801"):
        if not route_urls:
            return
        routing_namespace = getattr(self, '_routing_namespace', None)
        if not routing_namespace:
            self.log("[~] [NAV] routing_namespace not found — skipping navigation event")
            return
        data = [("client_previous_actor_id", "0")]
        for idx, route in enumerate(route_urls):
            data.append((f"route_urls[{idx}]", route))
        data.extend([
            ("routing_namespace", routing_namespace),
            ("__d", "www"), ("__user", "0"), ("__a", "1"),
            ("__req", self._next_req()),
            ("__hs", self._IG_HS),
            ("dpr", str(self._real_dpr) if self._real_dpr else "1"),
            ("__ccg", self._get_ccg()),
            ("__rev", self._IG_REV),
            ("__s", self._session_str),
            ("__hsi", self._IG_HSI),
            ("__dyn", self._MUTATION_PARAMS["CAARegistrationFormDesktopQuery"]["__dyn"]),
            ("__csr", self._MUTATION_PARAMS["CAARegistrationFormDesktopQuery"]["__csr"]),
            ("__hsdp", self._MUTATION_PARAMS["CAARegistrationFormDesktopQuery"]["__hsdp"]),
            ("__hblp", self._MUTATION_PARAMS["CAARegistrationFormDesktopQuery"]["__hblp"]),
            ("__sjsp", self._MUTATION_PARAMS["CAARegistrationFormDesktopQuery"]["__sjsp"]),
            ("__comet_req", "7"),
            ("lsd", self.lsd or ""),
            ("jazoest", self._JAZOEST),
            ("__spin_r", self._IG_REV),
            ("__spin_b", "trunk"),
            ("__spin_t", self._IG_SPIN_T),
            ("__crn", crn),
            ("qpl_active_flow_ids", flow_ids),
        ])
        headers = self._generate_headers({
            "X-FB-QPL-Active-Flows": flow_ids,
            "X-IG-D": "www",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        try:
            resp = self._safe_post(f"{self.BASE_URL}/ajax/navigation/", headers=headers,
                                   data=urllib.parse.urlencode(data), timeout=20)
            self._update_claim_from_response(resp)
        except Exception as e:
            self.log(f"[~] ajax/navigation: {e}")

    def _invalidate_runtime_hashes(self):
        for key in self._MUTATION_PARAMS:
            self._MUTATION_PARAMS[key]["__dyn"] = ""
            self._MUTATION_PARAMS[key]["__csr"] = ""
            self._MUTATION_PARAMS[key]["__hsdp"] = ""
            self._MUTATION_PARAMS[key]["__hblp"] = ""
            self._MUTATION_PARAMS[key]["__sjsp"] = ""

    def _load_hashes_from_session_dump(self):
        """Load real runtime hashes from local session_*.json browser dumps if available."""
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            candidates = sorted(glob.glob(os.path.join(base_dir, 'session_*.json')), key=os.path.getmtime, reverse=True)
            if not candidates:
                return None
            dump_path = candidates[0]
            with open(dump_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            best = None
            best_score = -1
            best_meta = None
            for item in data:
                if not isinstance(item, dict):
                    continue
                body = item.get('body') or ''
                url = item.get('url') or ''
                if '/api/graphql' not in url and '/ajax/bootloader-endpoint/' not in url and '/ajax/bulk-route-definitions/' not in url:
                    continue
                vals = {}
                try:
                    parsed = urllib.parse.parse_qs(body)
                    for k in ('__dyn', '__csr', '__hsdp', '__hblp', '__sjsp'):
                        v = parsed.get(k, [''])[0]
                        if v and len(v) >= 20 and not v.startswith(':') and not re.match(r'^[\d,:\s]+$', v):
                            vals[k] = v
                except Exception:
                    vals = {}
                score = sum(1 for k in ('__dyn', '__csr', '__hsdp', '__hblp', '__sjsp') if vals.get(k))
                if score > best_score:
                    best = vals
                    best_score = score
                    best_meta = (dump_path, item.get('url', ''))
            if best and best_score == 5:
                self.log(f"[+] [SESSION-DUMP] Loaded real runtime hashes from {os.path.basename(best_meta[0])}")
                self.log(f"[~] [SESSION-DUMP] Source: {best_meta[1][:120]}")
                return best
        except Exception as e:
            self.log(f"[~] [SESSION-DUMP] Load error: {e}")
        return None

    def _apply_runtime_hashes(self, hashes, source='runtime'):
        if not hashes:
            return
        self._runtime_hash_source = source
        for key in self._MUTATION_PARAMS:
            for k in ('__dyn', '__csr', '__hsdp', '__hblp', '__sjsp'):
                if hashes.get(k):
                    self._MUTATION_PARAMS[key][k] = hashes[k]
        self.log(f"[+] [{source}] __dyn: {hashes.get('__dyn', '')[:40]}...")
        self.log(f"[+] [{source}] __csr: {hashes.get('__csr', '')[:40]}...")
        self.log(f"[+] [{source}] __hsdp: {hashes.get('__hsdp', '')[:40]}...")
        self.log(f"[+] [{source}] __hblp: {hashes.get('__hblp', '')[:40]}...")
        self.log(f"[+] [{source}] __sjsp: {hashes.get('__sjsp', '')[:40]}...")

    def _refresh_hashes_for_confirm(self):
        """Evolve runtime hashes to simulate browser hash evolution.

        In a real browser, the JS runtime updates __dyn/__csr/__hsdp/__hblp/__sjsp
        between submit and confirm. Real data shows:
          __dyn:  203→204 chars  (prefix 202 same, last ~2 chars change)
          __csr:  301→313 chars  (prefix 155 same, tail grows by ~12)
          __hsdp:  68→ 74 chars  (prefix 22 same, suffix regenerated)
          __hblp: 125→137 chars  (prefix 36 same, suffix regenerated)
          __sjsp:  53→ 59 chars  (prefix 23 same, suffix regenerated)

        We preserve the FULL browser-cached hash and append a small random tail
        to simulate the natural growth that occurs when the JS runtime re-evaluates.
        """
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'

        mp = self._MUTATION_PARAMS.get("CAARegistrationFormDesktopQuery", {})
        current_dyn = mp.get("__dyn", "")
        current_csr = mp.get("__csr", "")
        current_hsdp = mp.get("__hsdp", "")
        current_hblp = mp.get("__hblp", "")
        current_sjsp = mp.get("__sjsp", "")

        def _fit_hash(full_hash, keep_prefix, target_min, target_max):
            if not full_hash:
                return full_hash
            target_len = random.randint(target_min, target_max)
            prefix = full_hash[:min(len(full_hash), keep_prefix)]
            if len(prefix) >= target_len:
                return prefix[:target_len]
            return prefix + ''.join(random.choices(chars, k=target_len - len(prefix)))

        # Successful browser captures show confirm hashes are normalized to these
        # lengths, with only short stable prefixes preserved for hsdp/hblp/sjsp.
        dyn = _fit_hash(current_dyn, keep_prefix=202, target_min=203, target_max=205)
        csr = _fit_hash(current_csr, keep_prefix=155, target_min=311, target_max=315)
        hsdp = _fit_hash(current_hsdp, keep_prefix=22, target_min=72, target_max=76)
        hblp = _fit_hash(current_hblp, keep_prefix=36, target_min=135, target_max=139)
        sjsp = _fit_hash(current_sjsp, keep_prefix=23, target_min=57, target_max=61)

        for key in self._MUTATION_PARAMS:
            self._MUTATION_PARAMS[key]["__dyn"]  = dyn
            self._MUTATION_PARAMS[key]["__csr"]  = csr
            self._MUTATION_PARAMS[key]["__hsdp"] = hsdp
            self._MUTATION_PARAMS[key]["__hblp"] = hblp
            self._MUTATION_PARAMS[key]["__sjsp"] = sjsp
        self.log(f"[~] [CONFIRM] Evolved runtime hashes: dyn={len(dyn)} csr={len(csr)} hsdp={len(hsdp)} hblp={len(hblp)} sjsp={len(sjsp)}")

    def _get_initial_cookies_and_tokens(self) -> bool:
        try:
            return self._get_initial_cookies_and_tokens_inner()
        except Exception as e:
            import traceback
            self.log(f"[!] _get_initial_cookies_and_tokens CRASHED: {e}")
            self.log(f"[!] {traceback.format_exc()}")
            return False

    def _get_initial_cookies_and_tokens_inner(self) -> bool:
        self.ig_did = self.fingerprint.ig_did
        self.session.set_cookie("ig_did", self.ig_did, http_only=True)
        self.session.set_cookie("datr", self.fingerprint.datr, http_only=True)
        hw = self.fingerprint.hw_profile
        self.session.set_cookie("dpr", str(self.fingerprint.dpr), secure=False)
        wd_w = hw["viewport_width"]
        wd_h = hw["viewport_height"]
        self.session.set_cookie("wd", f"{wd_w}x{wd_h}", secure=False)
        if "mid" in self.session.cookies:
            self.mid = self.session.cookies["mid"]

        nav_headers = self._generate_nav_headers(from_google=True)
        resp = None
        for url in [f"{self.BASE_URL}/accounts/emailsignup/", f"{self.BASE_URL}/"]:
            try:
                resp = self._safe_get(url, headers=nav_headers, allow_redirects=True, timeout=30)
                if resp.status_code == 200:
                    self._update_claim_from_response(resp)
                    break
            except Exception as e:
                self.log(f"[!] GET {url}: {e}")
        else:
            self.log("[!] Failed to load Instagram")
            return False

        resp_text = resp.text if resp is not None else ""

        self.log("[~] [INIT] Parsing csrf / encryption / lsd / dyn")

        if "csrftoken" in self.session.cookies:
            self.csrf_token = self.session.cookies["csrftoken"]
        else:
            m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', resp_text)
            if m:
                self.csrf_token = m.group(1)

        if not self.csrf_token:
            self.log("[!] csrftoken not found")
            return False
        self.log("[~] [INIT] csrf OK")

        pub_key, key_id = _parse_encryption_keys(resp_text)
        if pub_key and key_id is not None:
            self._enc_pub_key = pub_key
            self._enc_key_id = key_id
            self.log(f"[+] Encryption key: key_id={key_id}")
        else:
            self.log("[~] Encryption key not found — password without encryption")

        self.lsd = self._extract_lsd_from_text(resp_text)

        if not self.lsd:
            try:
                r2 = self._safe_get(f"{self.BASE_URL}/api/v1/web/data/shared_data/",
                                    headers=self._generate_headers(), timeout=15)
                self._update_claim_from_response(r2)
                if r2.status_code == 200:
                    self.lsd = self._extract_lsd_from_text(r2.text)
                    if not self.lsd:
                        try:
                            j = r2.json()
                            self.lsd = j.get("config", {}).get("LSD", {}).get("token")
                        except Exception:
                            pass
                    if not self._enc_pub_key:
                        pub_key, key_id = _parse_encryption_keys(r2.text)
                        if pub_key and key_id is not None:
                            self._enc_pub_key = pub_key
                            self._enc_key_id = key_id
            except Exception:
                pass

        if not self.lsd:
            try:
                js_urls = re.findall(
                    r'(https://static\.cdninstagram\.com/rsrc\.php/[^\s"\']+\.js)',
                    resp_text)
                for js_url in list(dict.fromkeys(js_urls))[:5]:
                    try:
                        rjs = self._safe_get(js_url, headers=self._generate_headers(), timeout=15)
                        self._update_claim_from_response(rjs)
                        if rjs.status_code == 200:
                            self.lsd = self._extract_lsd_from_text(rjs.text)
                            if self.lsd:
                                break
                    except Exception:
                        pass
            except Exception:
                pass

        if not self.lsd:
            try:
                r4 = self._safe_post(
                    self.GRAPHQL_URL,
                    headers=self._generate_headers({"Content-Type": "application/x-www-form-urlencoded"}),
                    data={"lsd": "AVo7BFybFeE", "doc_id": "0", "__a": "1", "__user": "0", "__d": "www"},
                    timeout=15)
                self._update_claim_from_response(r4)
                self.lsd = self._extract_lsd_from_text(r4.text) or r4.cookies.get("lsd")
            except Exception:
                pass

        if not self.lsd:
            self.log("[!] lsd not found")
            return False
        self.log("[~] [INIT] lsd OK")

        m = re.search(r'"fb_dtsg"\s*:\s*"([^"]+)"', resp_text)
        if m:
            self.fb_dtsg = m.group(1)

        if "mid" in self.session.cookies:
            self.mid = self.session.cookies["mid"]

        self.session.set_cookie("csrftoken", self.csrf_token, http_only=False)

        # [FIX] Fetch browser hashes ONCE, then re-apply after _extract_dynamic_params
        _browser_hashes = None
        if HASH_CACHE_AVAILABLE:
            try:
                self.log(f"[~] [HASH-CACHE] Python: {sys.executable}")
                cached = _get_cached_hashes(force_refresh=True)
                if cached and all(cached.get(k) for k in ("__dyn", "__csr", "__hsdp", "__hblp", "__sjsp")):
                    _browser_hashes = cached
                    self._apply_runtime_hashes(cached, source="BROWSER")
                    self.log(f"[+] [HASH-CACHE] Loaded from browser: __dyn={cached['__dyn'][:30]}...")
                else:
                    self.log("[~] [HASH-CACHE] Browser fetch did not return full hashes")
            except Exception as e:
                self.log(f"[~] [HASH-CACHE] Load error: {e}")

        self.log("[~] [INIT] Dynamic params refresh")
        self._refresh_runtime_context(resp_text, refresh_doc_ids=True)
        self.log("[~] [INIT] Dynamic params refresh done")

        # [FIX] Re-apply browser hashes AFTER _extract_dynamic_params (which may overwrite them)
        if _browser_hashes:
            self._apply_runtime_hashes(_browser_hashes, source="BROWSER")
            self.log("[~] [INIT] Re-applied browser hashes after dynamic params")

        current = self._MUTATION_PARAMS.get("CAARegistrationFormDesktopQuery", {})
        current_ok = all(current.get(k) for k in ("__dyn", "__csr", "__hsdp", "__hblp", "__sjsp"))
        if not current_ok:
            self.log("[!] [HASH-CACHE] Browser-only mode: real runtime hashes were not obtained")
            self.log(f"[!] [HASH-CACHE] Active Python: {sys.executable}")
            return False

        self.log(f"[+] Tokens OK — csrf=...{self.csrf_token[-6:]}  lsd=...{self.lsd[-6:]}"
                 f"  rev={self._IG_REV}  claim={self.ig_www_claim[:20]}")
        return True

    def _extract_dynamic_params(self, html: str):
        rev = None
        for pat in [
            r'"client_revision"\s*:\s*(\d{9,12})',
            r'"__rev"\s*:\s*(\d{9,12})',
            r'"revision"\s*:\s*(\d{9,12})',
            r'__spin_r["\s:,]+(\d{9,12})',
        ]:
            m = re.search(pat, html)
            if m:
                rev = m.group(1)
                break

        hs = None
        m = re.search(r'"haste_session"\s*:\s*"([^"]+)"', html)
        if not m:
            m = re.search(r'"__hs"\s*:\s*"([^"]+)"', html)
        if m:
            hs = m.group(1)

        jazoest = None
        m = re.search(r'name="jazoest"\s+value="(\d+)"', html)
        if not m:
            m = re.search(r'"jazoest"\s*:\s*"(\d+)"', html)
        if not m:
            m = re.search(r'jazoest[=:]\s*"?(\d+)"?', html)
        if m:
            jazoest = m.group(1)

        dyn = None
        m = re.search(r'"__dyn"\s*:\s*"([A-Za-z0-9_\-]+)"', html)
        if m:
            dyn = m.group(1)

        if not self._IG_HSI or (self._IG_HSI.startswith('7') and len(self._IG_HSI) >= 19):
            m = re.search(r'"hsi"\s*:\s*"?(\d{15,20})"?', html)
            if not m:
                m = re.search(r'__hsi["\s:=]+(\d{15,20})', html)
            if m:
                self._IG_HSI = m.group(1)
        m = re.search(r'"web_session_id"\s*:\s*"([a-z0-9]{6}:[a-z0-9]{6}:[a-z0-9]{6})"', html)
        if m:
            self._session_str = m.group(1)

        csr = None
        m = re.search(r'"__csr"\s*:\s*"([A-Za-z0-9_\-]+)"', html)
        if m:
            csr = m.group(1)

        hsdp = None
        m = re.search(r'"__hsdp"\s*:\s*"([A-Za-z0-9_\-]+)"', html)
        if m:
            hsdp = m.group(1)

        hblp = None
        m = re.search(r'"__hblp"\s*:\s*"([A-Za-z0-9_\-]+)"', html)
        if m:
            hblp = m.group(1)

        sjsp = None
        m = re.search(r'"__sjsp"\s*:\s*"([A-Za-z0-9_\-]+)"', html)
        if m:
            sjsp = m.group(1)

        prev_rev = getattr(self, '_runtime_param_rev', self._IG_REV)
        rev_changed = bool(rev and rev != prev_rev)
        if rev_changed:
            if getattr(self, '_runtime_hash_source', '') == 'BROWSER':
                self.log(f"[~] [DYN] __rev changed {prev_rev} -> {rev}; keeping browser hashes")
            else:
                self.log(f"[~] [DYN] __rev changed {prev_rev} -> {rev}; invalidating old runtime hashes")
                self._invalidate_runtime_hashes()

        if rev:
            self._IG_REV = rev
            self._runtime_param_rev = rev
            self.log(f"[+] [DYN] __rev: {rev}")
        else:
            self.log(f"[~] [DYN] __rev not found — requests may fail")

        if hs:
            self._IG_HS = hs
            self.log(f"[+] [DYN] __hs: {hs[:40]}")

        if jazoest:
            self._JAZOEST = jazoest
            self.log(f"[+] [DYN] jazoest: {jazoest}")

        full_hash_set_found = all([dyn, csr, hsdp, hblp, sjsp])
        if not full_hash_set_found:
            # Try harder: search in inline <script> tags for these values
            # But skip JSON config values (comma-separated numbers like ":206,2,402")
            def _is_real_hash(val):
                """Check if val looks like a real runtime hash, not a JSON config."""
                if not val or len(val) < 10:
                    return False
                if re.match(r'^[\d,:\s]+$', val):
                    return False
                if val.startswith(':'):
                    return False
                return True
            if not dyn:
                m = re.search(r'"__dyn"\s*:\s*"([A-Za-z0-9_\-]{20,400})"', html)
                if m and _is_real_hash(m.group(1)):
                    dyn = m.group(1)
            if not csr:
                m = re.search(r'"__csr"\s*:\s*"([A-Za-z0-9_\-]{20,400})"', html)
                if m and _is_real_hash(m.group(1)):
                    csr = m.group(1)
            if not hsdp:
                m = re.search(r'"__hsdp"\s*:\s*"([A-Za-z0-9_\-]{20,200})"', html)
                if m and _is_real_hash(m.group(1)):
                    hsdp = m.group(1)
            if not hblp:
                m = re.search(r'"__hblp"\s*:\s*"([A-Za-z0-9_\-]{20,200})"', html)
                if m and _is_real_hash(m.group(1)):
                    hblp = m.group(1)
            if not sjsp:
                m = re.search(r'"__sjsp"\s*:\s*"([A-Za-z0-9_\-]{10,200})"', html)
                if m and _is_real_hash(m.group(1)):
                    sjsp = m.group(1)
            full_hash_set_found = all([dyn, csr, hsdp, hblp, sjsp])

        if not full_hash_set_found:
            if getattr(self, '_runtime_hash_source', '') == 'BROWSER':
                self.log("[~] [DYN] HTML hashes not found but browser hashes available — skipping fallback")
            else:
                def _rand_hash(n):
                    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
                    return ''.join(random.choices(chars, k=n))
                if not dyn:
                    dyn = '7xeU' + _rand_hash(random.randint(196, 200))
                    self.log(f"[~] [DYN] __dyn generated (fallback): {dyn[:40]}...")
                if not csr:
                    csr = 'gcQQ' + _rand_hash(random.randint(297, 309))
                    self.log(f"[~] [DYN] __csr generated (fallback): {csr[:40]}...")
                if not hsdp:
                    hsdp = 'ghao' + _rand_hash(random.randint(63, 70))
                    self.log(f"[~] [DYN] __hsdp generated (fallback): {hsdp[:40]}...")
                if not hblp:
                    hblp = '05VjxnwtEbE8oiwko-u0UUgwbi8Cy85-6ouwro' + _rand_hash(random.randint(85, 97))
                    self.log(f"[~] [DYN] __hblp generated (fallback): {hblp[:40]}...")
                if not sjsp:
                    sjsp = 'ghao' + _rand_hash(random.randint(47, 55))
                    self.log(f"[~] [DYN] __sjsp generated (fallback): {sjsp[:40]}...")

        if rev_changed and not all([dyn, csr, hsdp, hblp, sjsp]):
            if getattr(self, '_runtime_hash_source', '') == 'BROWSER':
                self.log("[~] [DYN] rev changed, hashes from HTML not found — keeping browser hashes, updating rev/hs/jazoest")
            else:
                self.log("[~] [DYN] rev changed but full runtime hash set not found — keeping hashes empty")
                return

        if dyn or csr or hsdp or hblp or sjsp:
            if getattr(self, '_runtime_hash_source', '') == 'BROWSER':
                self.log("[~] [DYN] HTML hashes found but browser hashes are authoritative — not overwriting")
            else:
                for key in self._MUTATION_PARAMS:
                    if dyn:
                        self._MUTATION_PARAMS[key]["__dyn"] = dyn
                    if csr:
                        self._MUTATION_PARAMS[key]["__csr"] = csr
                    if hsdp:
                        self._MUTATION_PARAMS[key]["__hsdp"] = hsdp
                    if hblp:
                        self._MUTATION_PARAMS[key]["__hblp"] = hblp
                    if sjsp:
                        self._MUTATION_PARAMS[key]["__sjsp"] = sjsp
            if dyn:
                self.log(f"[+] [DYN] __dyn: {dyn[:40]}...")
            if csr:
                self.log(f"[+] [DYN] __csr: {csr[:40]}...")
            if hsdp:
                self.log(f"[+] [DYN] __hsdp: {hsdp[:40]}...")
            if hblp:
                self.log(f"[+] [DYN] __hblp: {hblp[:40]}...")
            if sjsp:
                self.log(f"[+] [DYN] __sjsp: {sjsp[:40]}...")

    def _call_graphql(self, doc_id, variables, friendly_name, referer=None) -> Optional[Dict]:
        resolved_doc_id = doc_id
        if friendly_name in self._doc_ids:
            resolved_doc_id = self._doc_ids.get(friendly_name) or doc_id

        extra = {
            "X-FB-Friendly-Name": friendly_name,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if referer:
            extra["Referer"] = referer
        headers = self._generate_headers(extra)
        mp = self._MUTATION_PARAMS.get(
            friendly_name,
            self._MUTATION_PARAMS["useCAARegistrationFieldValidationQuery"]
        )
        required_runtime = [mp.get("__dyn"), mp.get("__csr"), mp.get("__hsdp"),
                            mp.get("__hblp"), mp.get("__sjsp")]
        required_global = [self._IG_REV, self._IG_HS, self._JAZOEST]
        if not all(required_runtime):
            self.log(f"[!] Missing runtime hashes for {friendly_name} — trying with empty values")
        if not all(required_global):
            self.log(f"[!] Missing global params for {friendly_name}; aborting")
            return None
        data = {
            "av": str(self.user_id) if self.user_id else "0",
            "__d": "www",
            "__user": "0",
            "__a": "1",
            "__req": self._next_req(),
            "__hs": self._IG_HS,
            "dpr": str(self._real_dpr) if self._real_dpr else "1",
            "__ccg": self._get_ccg(),
            "__rev": self._IG_REV,
            "__s": self._session_str,
            "__hsi": self._IG_HSI,
            "__comet_req": "7",
            "__crn": mp["__crn"],
            "__dyn": mp["__dyn"],
            "__csr": mp["__csr"],
            "__hsdp": mp["__hsdp"],
            "__hblp": mp["__hblp"],
            "__sjsp": mp["__sjsp"],
            "__spin_r": self._IG_REV,
            "__spin_b": "trunk",
            "__spin_t": self._IG_SPIN_T,
            "jazoest": self._JAZOEST,
            "qpl_active_flow_ids": mp["qpl_active_flow_ids"],
            "fb_api_caller_class": "RelayModern",
            "fb_api_req_friendly_name": friendly_name,
            "fb_api_analytics_tags": mp["fb_api_analytics_tags"],
            "server_timestamps": "true",
            "doc_id": resolved_doc_id,
            "variables": json.dumps(variables, separators=(',', ':')),
        }
        if self.lsd:
            data["lsd"] = self.lsd
        if self.fb_dtsg:
            data["fb_dtsg"] = self.fb_dtsg

        if friendly_name in ("useCAARegistrationFormSubmitMutation", "useCAAFBConfirmationFormSubmitMutation"):
            try:
                dbg = {
                    "friendly_name": friendly_name,
                    "doc_id": resolved_doc_id,
                    "variables_preview": json.dumps(variables, ensure_ascii=False)[:900],
                }
                self.log(f"[~] GraphQL debug: {json.dumps(dbg, ensure_ascii=False)[:1800]}")
            except Exception:
                pass

        try:
            resp = self._safe_post(self.GRAPHQL_URL, headers=headers, data=data, timeout=30)
            self._update_claim_from_response(resp)
            if "csrftoken" in self.session.cookies:
                new_csrf = self.session.cookies["csrftoken"]
                if new_csrf != self.csrf_token:
                    self.csrf_token = new_csrf
        except Exception as e:
            self.log(f"[!] Request error: {e}")
            return None

        if resp.status_code == 429:
            self.log(f"[!] GraphQL RATE LIMIT (429) — pausing 5-10 minutes...")
            time.sleep(random.uniform(300, 600))
            return None
        if resp.status_code != 200:
            self.log(f"[!] GraphQL {friendly_name} -> HTTP {resp.status_code}")
            return None

        try:
            raw = resp.text
            for prefix in ("for (;;);", "throw 1; <don't be evil>"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
                    break
            parsed = json.loads(raw)
            if "error" in parsed and "data" not in parsed:
                self.log(f"[!] API error {parsed.get('error')}: "
                         f"{parsed.get('errorSummary', '')} -- {parsed.get('errorDescription', '')}")
                return None
            if not (parsed.get("data") or parsed.get("errors")):
                self.log(f"[~] Unexpected body: {resp.text[:200]}")
            return parsed
        except Exception as e:
            self.log(f"[!] JSON decode: {e}")
            self.log(f"[~] Raw: {resp.text[:200]}")
            return None

    def _validate_field(self, field_name, email_addr, password="", username="", fullname="",
                        birthday=None, fetch_suggest=False):
        input_data = {
            "contactpoint": {"sensitive_string_value": email_addr},
            "contactpoint_type": "EMAIL",
            "fetch_username_suggestions": fetch_suggest,
            "field_name": field_name,
            "firstname": {"sensitive_string_value": ""},
            "fullname": {"sensitive_string_value": fullname},
            "lastname": {"sensitive_string_value": ""},
        }
        if field_name == "PASSWORD":
            pass
        elif field_name == "FULLNAME":
            input_data["machine_id"] = ""
        else:
            input_data["machine_id"] = self.mid or ""
        if password:
            input_data["reg_passwd__"] = {"sensitive_string_value": password}
        if username:
            input_data["username"] = {"sensitive_string_value": username}
        if birthday:
            input_data["birthday_day"] = birthday[0]
            input_data["birthday_month"] = birthday[1]
            input_data["birthday_year"] = birthday[2]

        variables = {"input": input_data, "scale": 1}
        r = self._call_graphql(self.DOC_ID_VALIDATION, variables, "useCAARegistrationFieldValidationQuery")
        if not r:
            self.log(f"[!] Validate {field_name}: GraphQL returned None")
            return False, [], "GraphQL request failed"
        data = (r.get("data") or {})
        node = (data.get("xfb_caa_registration_field_validation") or
                data.get("caa_registration_field_validation") or {})
        status = node.get("status", "")
        if status != "SUCCESS":
            err = node.get("error") or {}
            err_msg = err.get("message", "") or str(node)[:200]
            self.log(f"[!] Validate {field_name}: status={status} error={err_msg}")
            return False, [], err_msg
        return True, node.get("username_suggestions") or [], ""

    def submit_registration(self, email_addr, password, username, fullname, birthday):
        day, month, year = birthday

        if self._enc_pub_key and self._enc_key_id is not None:
            enc_password = _encrypt_password(password, self._enc_pub_key, self._enc_key_id)
            self.log(f"[+] Password encrypted: {enc_password[:30]}...")
        else:
            enc_password = password
            self.log("[~] Password without encryption (key not found)")

        variables = {"input": {
            "actor_id": "0",
            "client_mutation_id": self.client_mutation_id,
            "machine_id": self.mid or "",
            "reg_data": {
                "birthday_day": day,
                "birthday_month": month,
                "birthday_year": year,
                "contactpoint": {"sensitive_string_value": email_addr},
                "contactpoint_type": "EMAIL",
                "custom_gender": "",
                "did_use_age": False,
                "firstname": {"sensitive_string_value": ""},
                "fullname": {"sensitive_string_value": fullname},
                "ig_age_block_data": None,
                "lastname": {"sensitive_string_value": ""},
                "preferred_pronoun": None,
                "reg_passwd__": {"sensitive_string_value": enc_password},
                "sex": None,
                "use_custom_gender": False,
                "username": {"sensitive_string_value": username},
            },
            "sk_pipa_consent_given": None,
            "waterfall_id": self.waterfall_id,
        }}
        r = self._call_graphql(self.DOC_ID_SUBMIT, variables,
                               "useCAARegistrationFormSubmitMutation")
        if not r:
            return False, None, None

        self.log(f"[~] Submit keys: {list((r.get('data') or {}).keys())}")
        submit_candidates = [
            "caa_registration_homepage_submit",
            "xfb_caa_registration_homepage_submit",
            "caa_registration_submit",
            "xfb_caa_registration_submit",
        ]
        data = None
        r_data = r.get("data") or {}
        for key in submit_candidates:
            if key in r_data:
                data = r_data.get(key) or {}
                break
        if data is None:
            for value in r_data.values():
                if isinstance(value, dict) and (value.get("status") or value.get("created_user_id") or value.get("context")):
                    data = value
                    break
        if data is None:
            data = {}
        self.log(f"[~] Submit full response: {str(data)[:500]}")

        if data.get("status") == "SUCCESS":
            user_id = (data.get("created_user_id")
                       or (data.get("context") or {}).get("user_id")
                       or (data.get("ig_reg_data") or "").split("|")[0] or None)
            if not user_id:
                try:
                    for v in (data, r_data, r):
                        if isinstance(v, dict):
                            for vv in v.values():
                                if isinstance(vv, dict) and vv.get("created_user_id"):
                                    user_id = vv.get("created_user_id")
                                    break
                            if user_id:
                                break
                except Exception:
                    pass
            ig_reg_data = (data.get("ig_reg_data")
                           or (data.get("context") or {}).get("ig_reg_data")
                           or (data.get("context") or {}).get("ntf_context"))
            self.log(f"[+] Submit OK -- user_id={user_id}")
            if not user_id:
                self.log("[~] Submit SUCCESS without created_user_id")
            return True, user_id, ig_reg_data

        if data.get("checkpoint_url"):
            self.log(f"[!] CHECKPOINT: {data['checkpoint_url']} — SELFIE/PHONE REQUIRED")
            return False, f"checkpoint:{data['checkpoint_url']}", None

        errors = (data.get("errors") or {}).get("creation_errors") or []
        if not errors:
            errors = r.get("errors") or []
        msg = errors[0].get("message") if errors else str(data)[:200]
        err_code = errors[0].get("code") if errors else None

        msg_lower = msg.lower() if isinstance(msg, str) else ""
        if "please wait" in msg_lower or "wait a few" in msg_lower:
            self.log(f"[!] RATE LIMIT: {msg} — pausing 5-10 minutes...")
            time.sleep(random.uniform(300, 600))

        self.log(f"[!] Submit error (code={err_code}): {msg}")
        return False, msg, None

    # ── IMAP helpers ──────────────────────────────────────────────────────
    _IMAP_SERVERS = {
        'gmail.com': 'imap.gmail.com',
        'yahoo.com': 'imap.mail.yahoo.com',
        'outlook.com': 'outlook.office365.com',
        'hotmail.com': 'outlook.office365.com',
        'live.com': 'outlook.office365.com',
        'fuhrenmail.com': 'imap.firstmail.ltd',
        'plovmail.com': 'imap.firstmail.ltd',
        'legenmail.com': 'imap.firstmail.ltd',
        'duhastmail.com': 'imap.firstmail.ltd',
    }

    def _resolve_imap_server(self, email_address: str) -> str:
        domain = email_address.split('@')[-1].lower()
        if domain.endswith('smakmail.com'):
            return 'imap.smakmail.com'
        return self._IMAP_SERVERS.get(domain, 'imap.firstmail.ltd')

    def _imap_pre_check(self, email_address: str, email_password: str) -> bool:
        """Connect to IMAP before any IG request and record the last message ID.

        After submit, wait_for_code will use this threshold to only scan
        messages with a higher sequence number, eliminating the race where
        the confirmation email arrives during the initial SEARCH ALL call.
        """
        server = self._resolve_imap_server(email_address)
        try:
            mail = imaplib.IMAP4_SSL(server, 993, timeout=15)
            mail.login(email_address, email_password)
            mail.select('INBOX')
            st, data = mail.search(None, 'ALL')
            if st == 'OK' and data[0]:
                ids = data[0].split()
                if ids:
                    self._pre_imap_max_id = int(ids[-1])
                    self.log(f"[+] Pre-check IMAP: {len(ids)} messages, max ID={self._pre_imap_max_id}")
            mail.logout()
            return True
        except Exception as e:
            self.log(f"[~] Pre-check IMAP (non-fatal): {e}")
            return False

    def wait_for_code(self, email_address, email_password, max_wait=120) -> Optional[str]:
        server = self._resolve_imap_server(email_address)
        self.log(f"[~] IMAP: {server}")
        start_ts = time.time()
        try:
            mail = imaplib.IMAP4_SSL(server, 993, timeout=30)
            mail.login(email_address, email_password)
            mail.select('INBOX')
            self.log("[+] IMAP OK")
        except Exception as e:
            self.log(f"[!] IMAP error: {e}")
            return None

        def _extract(raw_bytes) -> Tuple[Optional[str], str, float]:
            msg = email.message_from_bytes(raw_bytes)
            subj = ""
            try:
                h = decode_header(msg['Subject'])[0]
                subj = h[0] if isinstance(h[0], str) else h[0].decode('utf-8', errors='ignore')
            except Exception:
                pass
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        try:
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
            else:
                try:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception:
                    pass
            raw_text = f"{subj} {body}"
            m = re.search(r'\b(\d{6})\b', raw_text)
            msg_ts = 0.0
            try:
                dt = email.utils.parsedate_to_datetime(msg.get('Date'))
                if dt is not None:
                    msg_ts = dt.timestamp()
            except Exception:
                pass
            return (m.group(1) if m else None), raw_text, msg_ts

        # Use the pre-check threshold if available, otherwise scan now.
        # The key fix: _pre_imap_max_id was recorded *before* submit, so the
        # confirmation email (which arrives after submit) will always have a
        # higher sequence number.
        max_existing = 0
        if self._pre_imap_max_id > 0:
            max_existing = self._pre_imap_max_id
            self.log(f"[~] Using pre-check IMAP max ID: {max_existing}")
        else:
            try:
                st, all_data = mail.search(None, 'ALL')
                all_ids = all_data[0].split() if (st == 'OK' and all_data[0]) else []
                self.log(f"[~] Inbox: {len(all_ids)} messages")
                if all_ids:
                    max_existing = int(all_ids[-1])
                    self.log("[~] Ignoring existing inbox mail; waiting only for new messages after submit")
            except Exception as e:
                self.log(f"[~] Error: {e}")

        t0 = time.time()
        while time.time() - t0 < max_wait:
            try:
                st, data = mail.search(None, 'ALL')
                if st == 'OK' and data[0]:
                    new_ids = [i for i in data[0].split() if int(i) > max_existing]
                    if new_ids:
                        self.log(f"[~] {len(new_ids)} new messages")
                    for eid in reversed(new_ids):
                        res, mdata = mail.fetch(eid, '(RFC822)')
                        if res != 'OK':
                            continue
                        code, raw_text, msg_ts = _extract(mdata[0][1])
                        text_l = raw_text.lower()
                        if ('instagram' not in text_l and 'confirmation' not in text_l and 'code' not in text_l and 'confirm' not in text_l):
                            self.log(f"[~] Skip mail {eid.decode(errors='ignore') if isinstance(eid, bytes) else eid}: not Instagram-like")
                            continue
                        if msg_ts and msg_ts < (start_ts - 120):
                            self.log(f"[~] Skip mail {eid.decode(errors='ignore') if isinstance(eid, bytes) else eid}: too old")
                            continue
                        if code:
                            mail.store(eid, '+FLAGS', '\\Seen')
                            mail.close()
                            mail.logout()
                            self.log(f"[+] Code: {code}")
                            return code
                time.sleep(5)
            except Exception as e:
                self.log(f"[!] IMAP poll: {e}")
                time.sleep(5)

        mail.close()
        mail.logout()
        self.log("[!] Timed out waiting for code")
        return None

    def _ensure_ps_cookies(self):
        """Acquire ps_l/ps_n cookies required for confirm to succeed.

        Flow observed in real Camoufox intercept:
        1. GET /  → server sets ps_l=0, ps_n=0
        2. POST /ajax/qm/?__a=1&__user=0&__comet_req=7&jazoest=XXX
           with body: event_id=...&marker_page_time=...&script_path=/&weight=0&client_start=1&lsd=...
           → server upgrades to ps_l=1, ps_n=1
        """
        if 'ps_l' in self.session.cookies and 'ps_n' in self.session.cookies:
            self.log(f"[~] ps_l/ps_n already present: ps_l={self.session.cookies.get('ps_l')} ps_n={self.session.cookies.get('ps_n')}")
            return

        self.log("[~] Acquiring ps_l/ps_n cookies (GET / + POST /ajax/qm/)...")
        try:
            # Step 1: GET / → ps_l=0, ps_n=0
            self._safe_get(
                f"{self.BASE_URL}/",
                headers=self._generate_nav_headers(),
                timeout=10
            )
            self.log(f"[~] ps_l/ps_n after GET /: ps_l={self.session.cookies.get('ps_l')} ps_n={self.session.cookies.get('ps_n')}")
        except Exception as e:
            self.log(f"[~] GET / for ps_l/ps_n failed: {e}")

        try:
            # Step 2: POST /ajax/qm/ → ps_l=1, ps_n=1
            jazoest = self._JAZOEST or "22221"
            lsd_val = self.lsd or ""
            event_id = str(random.randint(10**18, 10**19 - 1))
            marker_time = str(random.randint(2000, 5000))
            page_time = str(random.randint(5000, 30000))

            qm_params = (
                f"__a=1&__user=0&__comet_req=7&jazoest={jazoest}"
            )
            qm_url = f"{self.BASE_URL}/ajax/qm/?{qm_params}"
            qm_body = (
                f"event_id={event_id}&marker_id=ClientScriptStart"
                f"&marker_page_time={marker_time}&script_path=%2F"
                f"&weight=0&client_start=1"
                f"&lsd={urllib.parse.quote(lsd_val)}"
            )

            self._safe_post(
                qm_url,
                data=qm_body,
                headers=self._generate_headers(extra={"Content-Type": "application/x-www-form-urlencoded"}),
                timeout=10
            )
            self.log(f"[~] ps_l/ps_n after POST /ajax/qm/: ps_l={self.session.cookies.get('ps_l')} ps_n={self.session.cookies.get('ps_n')}")
        except Exception as e:
            self.log(f"[~] POST /ajax/qm/ for ps_l/ps_n failed: {e}")

        # Verify
        if 'ps_l' not in self.session.cookies or 'ps_n' not in self.session.cookies:
            self.log("[!] ps_l/ps_n missing after network attempts - setting fallback ps_l=1 ps_n=1")
            try:
                self.session.set_cookie("ps_l", "1")
                self.session.set_cookie("ps_n", "1")
                self.log("[~] ps_l/ps_n fallback set")
            except Exception as e:
                self.log(f"[!] ps_l/ps_n fallback failed: {e}")

    def confirm_account(self, code, ig_reg_data) -> bool:
        if not ig_reg_data:
            self.log("[!] ig_reg_data is None")
            return False

        # Log all cookies for diagnostic comparison
        try:
            all_cookies = dict(self.session.cookies)
            cookie_names = list(all_cookies.keys())
            self.log(f"[~] Confirm: all cookies: {cookie_names}")
            for ck in ['csrftoken', 'mid', 'datr', 'ig_did', 'dpr', 'wd', 'ds_user_id', 'rur', 'sessionid']:
                if ck in all_cookies:
                    val = all_cookies[ck]
                    self.log(f"[~] Confirm:   {ck}={val[:30]}{'...' if len(val)>30 else ''}")
        except Exception as e:
            self.log(f"[~] Confirm: cookie dump error: {e}")

        self.log("[~] Confirm: refreshing session tokens...")
        try:
            if "csrftoken" in self.session.cookies:
                old_csrf = self.csrf_token
                self.csrf_token = self.session.cookies["csrftoken"]
                if old_csrf != self.csrf_token:
                    self.log(f"[!] Confirm: csrftoken CHANGED: ...{old_csrf[-8:]} -> ...{self.csrf_token[-8:]}")
            if "mid" in self.session.cookies:
                new_mid = self.session.cookies["mid"]
                if new_mid and new_mid != self.mid:
                    self.log(f"[!] Confirm: mid CHANGED: {self.mid} -> {new_mid}")
                    self.mid = new_mid
        except Exception as e:
            self.log(f"[~] Confirm: token refresh failed: {e}")

        # [FIX] Acquire ps_l/ps_n cookies — required for confirm to succeed (error 1469023)
        self._ensure_ps_cookies()

        # Evolve runtime hashes to simulate JS runtime evolution between submit and confirm
        self._refresh_hashes_for_confirm()

        self.log(f"[~] Confirm: csrf=...{self.csrf_token[-6:] if self.csrf_token else 'None'}"
                 f"  lsd=...{(self.lsd or '')[-6:]}  rev={self._IG_REV}  spin_t={self._IG_SPIN_T}")
        self.log(f"[~] Confirm: ig_reg_data len={len(ig_reg_data)}  ends_with={ig_reg_data[-20:]}")
        self.log(f"[~] Confirm: mid={self.mid[:30] if self.mid else 'None'}")

        self.log(f"[~] Confirm: code={code[:2]}***, ig_reg_data={ig_reg_data[:20]}...")
        r = None
        r_data = {}
        r_errors = []
        for attempt in range(1, 4):
            variables = {"input": {
                "actor_id": "0",
                "client_mutation_id": str(uuid.uuid4()),
                "conf_code": {"sensitive_string_value": code},
                "ig_reg_data": ig_reg_data,
                "machine_id": self.mid or "",
                "sk_pipa_consent_given": None,
                "youth_consent_decision_time": None,
            }}
            if attempt > 1:
                self.log(f"[~] Confirm retry {attempt}/3 after 1469023...")
                time.sleep(random.uniform(3.0, 6.0))
                self._ensure_ps_cookies()
                self._refresh_hashes_for_confirm()
            r = self._call_graphql(self.DOC_ID_CONFIRM, variables,
                                   "useCAAFBConfirmationFormSubmitMutation")
            if r is None:
                self.log(f"[!] Confirm attempt {attempt} returned None")
                continue
            r_data = r.get("data") or {}
            r_errors = r.get("errors") or []
            self.log(f"[~] Confirm keys: {list(r_data.keys())}")
            if r_errors:
                self.log(f"[!] Confirm GraphQL errors: {r_errors}")
            self.log(f"[~] Confirm full data: {str(r_data)[:500]}")
            has_1469023 = any((err or {}).get("code") == 1469023 for err in r_errors)
            if not has_1469023:
                break

        if r is None:
            self.log("[!] Confirm returned None")
            return False

        _confirm_keys = [
            "xfb_caa_registration_confirmation_submit",
            "caa_registration_confirmation_submit",
            "xfb_caa_confirmation_submit",
            "caa_confirmation_submit",
        ]
        data = None
        for k in _confirm_keys:
            if k in r_data:
                data = r_data[k] or {}
                break
        if data is None:
            for v in r_data.values():
                if isinstance(v, dict) and v.get("created_user_id"):
                    data = v
                    break
        if data is None:
            data = {}

        user_id = (data.get("created_user_id") or data.get("user_id")
                   or r_data.get("created_user_id"))

        if user_id or data.get("status") == "SUCCESS":
            self.user_id = user_id
            self.log(f"[+] Confirmed! user_id={self.user_id}")
            return True

        self.log(f"[!] Confirm failed: {data.get('errors') or data}")
        return False

    def _send_bz(self, crn, trigger, delay=0, req_user=None, module="CAAIGRegistrationHomepage"):
        if delay > 0:
            time.sleep(min(delay, 5))

        try:
            if not self._IG_REV or not self._IG_HS:
                return
            hw = self._hw_profile
            uid = req_user or self.user_id or "0"
            flow_ids = "516759801"
            if trigger == "falco:caa_acquisition_client_ig_event":
                flow_ids = "175125627,516759801"
            elif trigger == "falco:ig_web_page_view" and "Registration" in crn:
                flow_ids = "175125627,516759801"
            elif trigger == "falco:ig_web_page_view" and req_user:
                flow_ids = "250360002,516759801"

            dpr = str(self._real_dpr) if self._real_dpr else "1"
            url_params = (
                f"__a=1&__ccg={self._get_ccg()}&__comet_req=7"
                f"&__crn={urllib.parse.quote(crn)}&__d=www"
                f"&__hs={urllib.parse.quote(self._IG_HS)}"
                f"&__hsi={self._IG_HSI}"
                f"&__req={self._next_req()}"
                f"&__rev={self._IG_REV}&__s={urllib.parse.quote(self._session_str)}"
                f"&__spin_b=trunk&__spin_r={self._IG_REV}&__spin_t={self._IG_SPIN_T}"
                f"&__user={uid}&dpr={dpr}&jazoest={self._JAZOEST}"
                f"&lsd={urllib.parse.quote(self.lsd or '')}&ph={random.choice(['C3','D7','BF','A1','E4'])}"
                f"&qpl_active_flow_ids={urllib.parse.quote(flow_ids)}"
            )
            bz_url = f"{self.BASE_URL}/ajax/bz?{url_params}"

            nav_chain = "CAAIGLoginHomepageRoot:CAAIGLoginHomepage:1:via_cold_start"
            referrer = ""
            url = f"{self.BASE_URL}/"
            module_name = module
            b_dims = [1, random.choice([128, 192, 256, 320, 384])]

            if module_name == "CAAIGRegistrationHomepage":
                nav_chain = "CAAIGLoginHomepageRoot:CAAIGLoginHomepage:1:via_cold_start,CAAIGRegistrationHomepageRoot:CAAIGRegistrationHomepage:2:une"
                referrer = f"{self.BASE_URL}/"
                url = f"{self.BASE_URL}/accounts/emailsignup/?next="
            elif module_name == "feedPage":
                nav_chain = "PolarisFeedRoot:feedPage:1:via_cold_start"
                referrer = f"{self.BASE_URL}/accounts/emailsignup/?next="
                url = f"{self.BASE_URL}/?caa_reg_splash_screen=1"
                b_dims = [1, random.choice([320, 384, 448, 512])]
            elif module_name == "UFAC":
                nav_chain = "PolarisUFACRoot:UFAC:1:via_cold_start"
                referrer = f"{self.BASE_URL}/accounts/emailsignup/?next="
                url = f"{self.BASE_URL}/accounts/suspended/?next={urllib.parse.quote(self.BASE_URL + '/?caa_reg_splash_screen=1&__coig_ufac=1')}#"
                b_dims = [1, random.choice([320, 384, 448, 512])]

            bz_device_id = self._bz_device_id or str(uuid.uuid4()).upper()
            web_analytics_session_id = self._web_analytics_session_id or self._random_session_str()
            event_data = {
                "module": module_name,
                "nav_chain": nav_chain,
                "referrer": referrer,
                "url": url,
                "web_analytics_session_id": web_analytics_session_id,
            }
            post_ts = time.time() * 1000
            posts = [[
                trigger,
                {
                    "e": json.dumps(event_data, separators=(",", ":")),
                    "r": 1,
                    "d": bz_device_id,
                    "s": self._session_str,
                    "t": post_ts,
                    "a": "1.0.0",
                    "b": b_dims,
                    "id": {"claim": ""},
                },
                post_ts + random.uniform(0.5, 8.0), 0, random.randint(100, 900)
            ]]

            q_payload = json.dumps([{
                "app_id": "936619743392459",
                "posts": posts,
                "user": uid,
                "webSessionId": self._session_str,
                "trigger": trigger,
                "send_method": "ajax",
                "compression": "deflate",
                "snappy_ms": random.randint(2, 15),
            }], separators=(",", ":"))

            boundary = ("----WebKitFormBoundary" +
                        ''.join(random.choices(
                            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                            k=16)))
            body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"ts\"\r\n\r\n"
                    f"{int(time.time() * 1000)}\r\n"
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n"
                    f"{q_payload}\r\n--{boundary}--\r\n")

            resp = self._safe_post(
                bz_url,
                headers=self._generate_headers({
                    "Content-Type": f"multipart/form-data; boundary={boundary}"
                }),
                data=body.encode(),
                timeout=8,
            )

            self._update_claim_from_response(resp)
        except Exception as e:
            err_str = str(e)
            if "Failed to fetch" in err_str or "context was destroyed" in err_str:
                pass
            else:
                self.log(f"[~] [FIX-BZ] bz {trigger[:40]}: {e}")

    def _ws_warmup(self, timeout=8.0):
        if not WEBSOCKET_AVAILABLE:
            self.log("[~] [M5] websocket-client not installed — skipping WS warmup")
            return
        try:
            import websocket as ws_lib
            ws_url = "wss://edge-chat.instagram.com/chat"
            headers = {
                "User-Agent": self.user_agent,
                "Origin": "https://www.instagram.com",
            }
            ws = ws_lib.create_connection(ws_url, timeout=timeout, header=headers)
            try:
                ws.send(b'\x10\x00')
                time.sleep(min(timeout, 4.0))
            except Exception:
                pass
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
            self.log("[~] [M5] WS warmup done")
        except Exception as e:
            self.log(f"[~] [M5] WS warmup failed: {e}")

    def check_account_alive(self, username: str) -> bool:
        self.log(f"[~] Checking account @{username}...")

        api_url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        try:
            resp = self._safe_get(api_url, headers=self._generate_headers({
                "Referer": f"https://www.instagram.com/{username}/",
            }), timeout=15)
            self.log(f"[~] API check: status {resp.status_code}, length {len(resp.text)}")

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    user = (data.get("data") or {}).get("user")
                    if user and user.get("username"):
                        self.log(f"[+] Account check @{username} — ALIVE (API confirmed)")
                        return True
                    else:
                        self.log(f"[x] Account check @{username} — BANNED (API: user=null)")
                        return False
                except (json.JSONDecodeError, ValueError):
                    self.log("[~] API returned non-JSON, trying HTML...")

            elif resp.status_code == 404:
                self.log(f"[x] Account check @{username} — BANNED (API: 404)")
                return False

        except Exception as e:
            self.log(f"[~] API check error: {e}, trying HTML...")

        profile_url = f"https://www.instagram.com/{username}/"
        try:
            resp2 = self._safe_get(profile_url, headers=self._generate_nav_headers(), timeout=15)
            status2 = resp2.status_code
            final_url = resp2.url.lower()
            body2 = resp2.text.lower()

            self.log(f"[~] HTML check: status {status2}, URL={final_url[:80]}, length={len(body2)}")

            if "/accounts/suspended" in final_url:
                self.log(f"[x] Account check @{username} — SUSPENDED (redirect to /accounts/suspended/)")
                return False
            if "/challenge/" in final_url:
                self.log(f"[x] Account check @{username} — CHALLENGE (verification required)")
                return False

            ban_signals = [
                "this page isn't available",
                "this page isn\\'t available",
                "the link you followed may be broken",
                "sorry, this page",
                '"user":null',
                '"user": null',
                "usersnotfound",
                "your account has been suspended",
                "we suspended your account",
                "login" in final_url and username not in final_url,
            ]

            for sig in ban_signals:
                if isinstance(sig, bool):
                    if sig:
                        self.log(f"[x] Account check @{username} — BANNED (redirect to login)")
                        return False
                elif sig in body2:
                    self.log(f"[x] Account check @{username} — BANNED (HTML: '{sig[:40]}')")
                    return False

            if status2 == 404:
                self.log(f"[x] Account check @{username} — BANNED (HTML: 404)")
                return False

            if status2 == 200 and username in body2:
                self.log(f"[+] Account check @{username} — ALIVE (HTML confirmed)")
                return True

            self.log(f"[~] Account check @{username} — unclear (status {status2}), assuming alive")
            return True

        except Exception as e:
            self.log(f"[~] HTML check error: {e} — assuming alive")
            return True

    def _call_ac_graphql(self, doc_id, variables, friendly_name, av_override=None) -> Optional[Dict]:
        ac_url = "https://accountscenter.instagram.com/api/graphql/"
        extra = {
            "X-FB-Friendly-Name": friendly_name,
            "X-ASBD-ID": self._x_asbd_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://accountscenter.instagram.com",
            "Referer": "https://accountscenter.instagram.com/password_and_security/two_factor/",
            "Sec-CH-Prefers-Color-Scheme": "light",
        }
        if self.lsd:
            extra["X-FB-LSD"] = self.lsd
        headers = self._generate_headers(extra)
        headers.pop("X-IG-App-ID", None)
        headers.pop("X-IG-WWW-Claim", None)
        headers.pop("X-CSRFToken", None)

        ac_dyn = getattr(self, '_ac_dyn', '') or self._MUTATION_PARAMS.get('CAARegistrationFormDesktopQuery', {}).get('__dyn', '')
        ac_csr = getattr(self, '_ac_csr', '') or self._MUTATION_PARAMS.get('CAARegistrationFormDesktopQuery', {}).get('__csr', '')
        ac_hsdp = getattr(self, '_ac_hsdp', '') or self._MUTATION_PARAMS.get('CAARegistrationFormDesktopQuery', {}).get('__hsdp', '')
        ac_hblp = getattr(self, '_ac_hblp', '') or self._MUTATION_PARAMS.get('CAARegistrationFormDesktopQuery', {}).get('__hblp', '')
        ac_sjsp = getattr(self, '_ac_sjsp', '') or self._MUTATION_PARAMS.get('CAARegistrationFormDesktopQuery', {}).get('__sjsp', '')
        ac_hs = getattr(self, '_ac_hs', '') or self._IG_HS
        ac_jazoest = getattr(self, '_ac_jazoest', None) or self._JAZOEST

        data = {
            "av": av_override or (str(self.user_id) if self.user_id else "0"),
            "__user": "0",
            "__a": "1",
            "__req": self._next_req(),
            "__hs": ac_hs,
            "dpr": str(self._real_dpr) if self._real_dpr else "1",
            "__ccg": self._get_ccg(),
            "__rev": self._IG_REV,
            "__s": self._session_str,
            "__hsi": self._IG_HSI,
            "__dyn": ac_dyn,
            "__csr": ac_csr,
            "__hsdp": ac_hsdp,
            "__hblp": ac_hblp,
            "__sjsp": ac_sjsp,
            "__comet_req": "7",
            "__spin_r": self._IG_REV,
            "__spin_b": "trunk",
            "__spin_t": self._IG_SPIN_T,
            "jazoest": ac_jazoest,
            "fb_api_caller_class": "RelayModern",
            "fb_api_req_friendly_name": friendly_name,
            "server_timestamps": "true",
            "doc_id": doc_id,
            "variables": json.dumps(variables, separators=(',', ':')),
        }
        if self.lsd:
            data["lsd"] = self.lsd
        if self.fb_dtsg:
            data["fb_dtsg"] = self.fb_dtsg

        try:
            resp = self._safe_post(ac_url, headers=headers, data=data, timeout=30)
            self._update_claim_from_response(resp)
        except Exception as e:
            self.log(f"[!] AC GraphQL error: {e}")
            return None

        if resp.status_code != 200:
            self.log(f"[!] AC GraphQL {friendly_name} -> HTTP {resp.status_code}")
            return None

        try:
            raw = resp.text
            for prefix in ("for (;;);", "throw 1; <don't be evil>"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
                    break
            return json.loads(raw)
        except Exception as e:
            self.log(f"[!] AC JSON decode: {e}")
            return None

    def enable_2fa(self) -> Optional[str]:
        if not PYOTP_AVAILABLE:
            self.log("[!] pyotp not installed — 2FA skipped. pip install pyotp")
            return None

        uid = str(self.user_id) if self.user_id else None
        if not uid:
            self.log("[!] 2FA: no user_id — skipping")
            return None

        self.log("[~] 2FA: starting TOTP enable...")

        try:
            ac_init_url = "https://accountscenter.instagram.com/?entry_point=app_settings"
            nav_headers = self._generate_nav_headers(referer="https://www.instagram.com/")
            time.sleep(random.uniform(1.0, 2.0))
            init_resp = self._safe_get(ac_init_url, headers=nav_headers, timeout=30)

            igsu_id = None

            if init_resp.status_code == 200:
                m_dtsg = re.search(r'"DTSGInitialData"\s*,\s*\[\s*\],\s*\{\s*"token"\s*:\s*"([^"]+)"', init_resp.text)
                if not m_dtsg:
                    m_dtsg = re.search(r'\["DTSGInitialData",\[\],\{"token":"([^"]+)"', init_resp.text)
                if m_dtsg:
                    self.fb_dtsg = m_dtsg.group(1)
                    jz = sum(ord(c) for c in self.fb_dtsg)
                    ac_jazoest = "2" + str(jz)
                    self._ac_jazoest = ac_jazoest
                    self.log("[+] 2FA: AC fb_dtsg updated")

                m_lsd = self._extract_lsd_from_text(init_resp.text)
                if m_lsd:
                    self.lsd = m_lsd
                    self.log("[+] 2FA: AC lsd updated")

                ac_html = init_resp.text
                for attr, pat in [
                    ('_ac_dyn', r'"__dyn"\s*:\s*"([A-Za-z0-9_\-]+)"'),
                    ('_ac_csr', r'"__csr"\s*:\s*"([A-Za-z0-9_\-]+)"'),
                    ('_ac_hsdp', r'"__hsdp"\s*:\s*"([A-Za-z0-9_\-]+)"'),
                    ('_ac_hblp', r'"__hblp"\s*:\s*"([A-Za-z0-9_\-]+)"'),
                    ('_ac_sjsp', r'"__sjsp"\s*:\s*"([A-Za-z0-9_\-]+)"'),
                ]:
                    m_val = re.search(pat, ac_html)
                    if m_val:
                        setattr(self, attr, m_val.group(1))
                m_hs = re.search(r'"haste_session"\s*:\s*"([^"]+)"', ac_html)
                if not m_hs:
                    m_hs = re.search(r'"__hs"\s*:\s*"([^"]+)"', ac_html)
                if m_hs:
                    self._ac_hs = m_hs.group(1)
                    self.log(f"[+] [DYN-AC] __hs={self._ac_hs[:40]}")
                if not getattr(self, '_ac_dyn', ''):
                    m_dyn_js = re.search(r'dynamic\s*\(\s*\[([^\]]{20,200})\]', ac_html)
                    if m_dyn_js:
                        self._ac_dyn = m_dyn_js.group(1)[:120]
                if getattr(self, '_ac_dyn', ''):
                    self.log(f"[+] [DYN-AC] __dyn={self._ac_dyn[:40]}...  csr={getattr(self, '_ac_csr', '')[:20]}...")

                for pattern in [
                    r'"actorID"\s*:\s*"(17841\d{10,})"',
                    r'"userID"\s*:\s*"(17841\d{10,})"',
                    r'"USER_ID"\s*:\s*"(17841\d{10,})"',
                    r'"props"\s*:\s*\{[^}]*"userID"\s*:\s*"(17841\d{10,})"',
                    r'\bav=(17841\d{10,})\b',
                    r'"(17841\d{10,})"',
                ]:
                    m_igsu = re.search(pattern, init_resp.text)
                    if m_igsu:
                        igsu_id = m_igsu.group(1)
                        break

                if igsu_id:
                    self.log(f"[+] 2FA: IGSU ID found: {igsu_id}")
                else:
                    self.log("[!] 2FA: IGSU ID not found in AC page, using ds_user_id")

            ac_uid = igsu_id or uid

            time.sleep(random.uniform(0.5, 1.0))
            self._call_ac_graphql(
                "26335787642700620",
                {"interface": "IG_WEB"},
                "FXAccountsCenterTwoFactorStartRootQuery",
                av_override=ac_uid
            )

            time.sleep(random.uniform(0.5, 1.0))
            self._call_ac_graphql(
                "34225209650459057",
                {
                    "account_type": "INSTAGRAM",
                    "device_id": "device_id_fetch_ig_did",
                    "interface": "IG_WEB",
                    "user_id": ac_uid,
                },
                "FXAccountsCenterTwoFactorTOTPQRCodeDialogQuery",
                av_override=ac_uid
            )

            time.sleep(random.uniform(0.5, 1.0))
            gen_resp = self._call_ac_graphql(
                "9837172312995248",
                {
                    "input": {
                        "actor_id": ac_uid,
                        "client_mutation_id": str(uuid.uuid4()),
                        "account_id": ac_uid,
                        "account_type": "INSTAGRAM",
                        "device_id": "device_id_fetch_ig_did",
                        "fdid": "device_id_fetch_ig_did",
                    }
                },
                "useFXSettingsTwoFactorGenerateTOTPKeyMutation",
                av_override=ac_uid
            )

            totp_secret = None
            self.log(f"[~] 2FA: GenerateTOTPKey response: {json.dumps(gen_resp)[:500] if gen_resp else 'None'}")

            if gen_resp:
                try:
                    d = gen_resp.get("data", {})
                    totp_node = d.get("xfb_two_factor_generate_totp_key")
                    if isinstance(totp_node, dict):
                        raw_key = totp_node.get("totp_key")
                        if isinstance(raw_key, dict):
                            key_text = raw_key.get("key_text", "")
                            totp_secret = key_text.replace(" ", "") if key_text else None
                        elif isinstance(raw_key, str) and len(raw_key) >= 16:
                            totp_secret = raw_key.replace(" ", "")

                    if not totp_secret:
                        for key in d:
                            node = d[key]
                            if isinstance(node, dict):
                                for field in ("totp_key", "key", "secret"):
                                    val = node.get(field)
                                    if isinstance(val, str) and len(val) >= 16:
                                        totp_secret = val
                                        break
                            if totp_secret:
                                break

                    if not totp_secret:
                        raw_str = json.dumps(gen_resp)
                        m = re.search(r'"(?:totp_key|key|secret)"\s*:\s*"([A-Z2-7]{16,})"', raw_str, re.IGNORECASE)
                        if m:
                            totp_secret = m.group(1)
                except Exception as e:
                    self.log(f"[!] 2FA: TOTP key parse error: {type(e).__name__}: {e}")

            if not totp_secret:
                self.log("[!] 2FA: failed to get TOTP secret — skipping")
                return None

            totp_secret = str(totp_secret)
            self.log(f"[+] 2FA: got TOTP secret: {totp_secret[:6]}...")

            time.sleep(random.uniform(0.5, 1.0))
            self._call_ac_graphql(
                "26277751381877270",
                {"interface": "IG_WEB"},
                "FXAccountsCenterTwoFactorConfirmCodeDialogQuery",
                av_override=ac_uid
            )

            totp = pyotp.TOTP(totp_secret)
            code = totp.now()
            self.log(f"[~] 2FA: generated code {code}")

            time.sleep(random.uniform(1.0, 2.0))
            enable_resp = self._call_ac_graphql(
                "29164158613231327",
                {
                    "input": {
                        "actor_id": ac_uid,
                        "client_mutation_id": str(uuid.uuid4()),
                        "account_id": ac_uid,
                        "account_type": "INSTAGRAM",
                        "verification_code": code,
                        "device_id": "device_id_fetch_ig_did",
                        "fdid": "device_id_fetch_ig_did",
                    }
                },
                "useFXSettingsTwoFactorEnableTOTPMutation",
                av_override=ac_uid
            )

            if enable_resp and enable_resp.get("data"):
                self.log("[+] 2FA: TOTP successfully enabled!")
            else:
                self.log(f"[!] 2FA: enable error — {json.dumps(enable_resp)[:200] if enable_resp else 'None'}")
                return None

            time.sleep(random.uniform(0.5, 1.0))
            self._call_ac_graphql(
                "26121190650823858",
                {
                    "account_id": ac_uid,
                    "account_type": "INSTAGRAM",
                    "interface": "IG_WEB",
                },
                "FXAccountsCenterTwoFactorOutroDialogQuery",
                av_override=ac_uid
            )

            time.sleep(random.uniform(0.3, 0.6))
            self._call_ac_graphql(
                "25820818727588632",
                {
                    "account_id": ac_uid,
                    "account_type": "INSTAGRAM",
                    "interface": "IG_WEB",
                },
                "FXAccountsCenterTwoFactorSettingsDialogQuery",
                av_override=ac_uid
            )

            self.log(f"[OK] 2FA: TOTP fully activated. Secret={totp_secret}")
            return totp_secret

        except Exception as e:
            self.log(f"[!] 2FA error: {e}")
            return None

    def register(self, email_addr, email_password, password, fullname, birthday,
                 username=None, enable_2fa=True) -> Dict:
        result = {"status": "failed", "email": email_addr, "email_password": email_password,
                  "password": password, "fullname": fullname,
                  "username": None, "user_id": None, "cookies": None, "error": None}

        try:
            return self._register_inner(email_addr, email_password, password, fullname, birthday, username, result, enable_2fa=enable_2fa)
        except Exception as e:
            import traceback
            self.log(f"[!] register() EXCEPTION: {e}")
            self.log(f"[!] {traceback.format_exc()}")
            result["error"] = f"Exception: {e}"
            return result

    def _register_inner(self, email_addr, email_password, password, fullname, birthday, username, result, enable_2fa=True):
        # Pre-check IMAP — record the last message ID *before* any IG request
        # so wait_for_code can reliably spot the confirmation email later.
        self._imap_pre_check(email_addr, email_password)

        if not self._get_initial_cookies_and_tokens():
            result["error"] = "Failed to obtain initial tokens"
            return result

        CRN_LOGIN = "comet.igweb.PolarisCAAIGLoginHomepageRoute"
        CRN_REG = "comet.igweb.PolarisCAAIGRegistrationHomepageRoute"

        time.sleep(random.uniform(0.3, 0.8))
        self._bg_call(lambda: self._safe_get(
            f"{self.BASE_URL}/ajax/bootloader-endpoint/"
            "?modules=CrossOriginRouteSupport&__d=www&__user=0&__a=1",
            headers=self._generate_headers(), timeout=30))

        time.sleep(random.uniform(2.0, 2.5))
        self._bg_call(self._send_bz, CRN_LOGIN, "falco:ig_web_page_view")
        time.sleep(random.uniform(0.8, 1.2))
        self._bg_call(self._send_bz, CRN_LOGIN, "falco:instagram_web_time_spent_navigation")
        time.sleep(random.uniform(0.8, 1.2))
        self._call_graphql(self.DOC_ID_INIT, {"args": {}, "ig_age_data": None, "scale": 1},
                           "CAARegistrationFormDesktopQuery",
                           referer=f"{self.BASE_URL}/")

        time.sleep(random.uniform(0.2, 0.5))
        self._bg_call(self._send_bz, CRN_REG, "falco:ig_web_page_view")
        time.sleep(random.uniform(0.8, 1.2))
        self._bg_call(self._send_bz, CRN_REG, "falco:ig_web_page_view")
        time.sleep(random.uniform(0.8, 1.2))
        self._bg_call(self._send_bz, CRN_REG, "falco:caa_acquisition_client_ig_event")

        time.sleep(random.uniform(2.5, 4.0))

        def _bzt(evt):
            self._bg_call(self._send_bz, CRN_REG, evt)

        _skip_step3 = random.random() < 0.35
        _skip_step6 = random.random() < 0.25
        _skip_step7 = random.random() < 0.30
        _skip_bootloader = random.random() < 0.40

        _falco_pool = [
            "falco:ig_web_page_view",
            "falco:instagram_web_time_spent_navigation",
            "falco:caa_acquisition_client_ig_event",
        ]

        self.log("[~] GraphQL validate 1: EMAIL")
        _bzt(random.choice(_falco_pool))
        time.sleep(random.uniform(0.5, 1.2))
        ok, suggestions, err_msg = self._validate_field("CONTACTPOINT", email_addr, fetch_suggest=True)
        if not ok:
            if "restrict" in err_msg.lower():
                result["error"] = f"IP/device rate-limited: {err_msg}"
            else:
                result["error"] = f"Email validation failed: {err_msg}"
            return result

        if not username:
            username = (suggestions[0] if suggestions
                        else re.sub(r'[^a-zA-Z0-9_.]', '', email_addr.split('@')[0])[:30]
                        or f"user{random.randint(1000, 9999)}")
        username = username[:30]
        result["username"] = username
        self.log(f"[+] Username: {username}")
        _bzt(random.choice(_falco_pool))
        time.sleep(random.uniform(2.0, 3.5))

        self.log("[~] GraphQL validate 2: PASSWORD")
        _bzt(random.choice(_falco_pool))
        self._validate_field("PASSWORD", email_addr, password=password, username=username)
        time.sleep(random.uniform(1.0, 2.0))

        if not _skip_step3:
            self.log("[~] GraphQL validate 3: CONTACTPOINT (empty fullname)")
            _bzt(random.choice(_falco_pool))
            self._validate_field("CONTACTPOINT", email_addr, fullname="")
            time.sleep(random.uniform(1.0, 2.5))
        else:
            self.log("[~] GraphQL validate 3: SKIP (random)")
            time.sleep(random.uniform(0.3, 0.8))

        self.log("[~] GraphQL validate 4: FULLNAME")
        _bzt(random.choice(_falco_pool))
        self._validate_field("FULLNAME", email_addr, fullname=fullname)
        time.sleep(random.uniform(1.0, 2.5))

        if not _skip_bootloader:
            self._bg_call(lambda: self._safe_get(
                f"{self.BASE_URL}/ajax/bootloader-endpoint/"
                f"?modules=VultureJSSampleRatesLoader&__d=www&__user=0&__a=1&__rev={self._IG_REV}",
                headers=self._generate_headers(), timeout=10))

        self.log("[~] GraphQL validate 5: PASSWORD (+birthday)")
        _bzt(random.choice(_falco_pool))
        self._validate_field("PASSWORD", email_addr, password=password, username=username,
                             fullname=fullname, birthday=birthday)
        time.sleep(random.uniform(1.0, 2.5))

        if not _skip_step6:
            self.log("[~] GraphQL validate 6: CONTACTPOINT (+fullname)")
            _bzt(random.choice(_falco_pool))
            self._validate_field("CONTACTPOINT", email_addr, fullname=fullname)
            time.sleep(random.uniform(3.0, 7.0))
        else:
            self.log("[~] GraphQL validate 6: SKIP (random)")
            time.sleep(random.uniform(1.0, 3.0))

        if not _skip_step7:
            self.log("[~] GraphQL validate 7: CONTACTPOINT (final)")
            _bzt(random.choice(_falco_pool))
            self._validate_field("CONTACTPOINT", email_addr, fullname=fullname)
            time.sleep(random.uniform(1.0, 2.0))
        else:
            self.log("[~] GraphQL validate 7: SKIP (random)")
            time.sleep(random.uniform(0.3, 1.0))

        self.log("[~] GraphQL validate 8: PASSWORD (final)")
        _bzt(random.choice(_falco_pool))
        self._validate_field("PASSWORD", email_addr, password=password, username=username,
                             fullname=fullname, birthday=birthday)

        # Submit returns ig_reg_data bound to the current cookie context.
        # ps_l/ps_n must exist before submit, not only before confirm.
        self._ensure_ps_cookies()
        self.log("[~] Submitting registration form (GraphQL submit)...")
        time.sleep(random.uniform(0.2, 0.5))
        ok, user_id, context = self.submit_registration(
            email_addr, password, username, fullname, birthday)

        if not ok:
            result["error"] = f"Submit failed: {user_id}"
            return result
        result["user_id"] = user_id

        if not context:
            result["error"] = "No ig_reg_data in submit response"
            return result

        self.log(f"[~] Post-submit state: csrf=...{self.csrf_token[-8:] if self.csrf_token else 'None'}"
                 f"  mid={self.mid[:30] if self.mid else 'None'}"
                 f"  ig_reg_data_len={len(context)}")
        try:
            sc = dict(self.session.cookies)
            self.log(f"[~] Post-submit cookies: {list(sc.keys())}")
        except Exception:
            pass

        time.sleep(random.uniform(0.3, 0.6))

        for trigger in ["falco:perf", "falco:perf",
                        "falco:instagram_web_time_spent_bit_array",
                        "falco:instagram_web_time_spent_bit_array"]:
            self._bg_call(self._send_bz, CRN_REG, trigger)
            time.sleep(random.uniform(0.9, 1.1))

        self._call_graphql(self.DOC_ID_CONFIRM_FORM,
                           {"args": {"context": context}, "scale": 1},
                           "CAAConfirmationFormDesktopQuery")
        self._call_graphql(self.DOC_ID_CONFIRM_SEO, {},
                           "CAARegistrationConfirmationSeoLinksQuery")

        _code_result = [None]
        _code_done = threading.Event()

        def _fetch_code():
            _code_result[0] = self.wait_for_code(email_addr, email_password)
            _code_done.set()

        threading.Thread(target=_fetch_code, daemon=True).start()

        _bz_t0 = time.time()
        while not _code_done.wait(timeout=random.uniform(10.0, 15.0)):
            _elapsed = int(time.time() - _bz_t0)
            self.log(f"[~] Waiting for code... ({_elapsed}s) — sending telemetry")
            time.sleep(random.uniform(0.5, 2.5))
            self._bg_call(self._send_bz, CRN_REG, "falco:instagram_web_time_spent_bit_array")
            time.sleep(random.uniform(1.0, 3.0))
            self._bg_call(self._send_bz, CRN_REG, "falco:ods_web_batch")

        code = _code_result[0]

        for trigger, jitter in [
            ("falco:ods_web_batch", random.uniform(0.3, 1.2)),
            ("falco:caa_acquisition_client_ig_event", random.uniform(0.7, 1.8)),
            ("falco:instagram_web_time_spent_bit_array", random.uniform(1.0, 2.0)),
            ("falco:instagram_web_time_spent_bit_array", random.uniform(0.5, 1.5)),
        ]:
            time.sleep(jitter)
            self._bg_call(self._send_bz, CRN_REG, trigger)

        if not code:
            result["error"] = "No confirmation code received"
            return result

        time.sleep(random.uniform(5.0, 9.0))

        if not self.confirm_account(code, context):
            result["error"] = "Confirmation failed"
            return result

        self._bg_call(self._send_bz, CRN_REG, "falco:perf")

        uid = str(self.user_id) if self.user_id else "0"
        CRN_FEED = "comet.igweb.PolarisFeedRoute"
        device_cid = str(uuid.uuid4())

        def _locked_get(url, hdrs=None, timeout=10):
            try:
                self._safe_get(url, headers=hdrs or self._generate_nav_headers(), timeout=timeout)
            except Exception:
                pass

        def _bg_get(url, hdrs=None, timeout=10):
            self._bg_call(_locked_get, url, hdrs, timeout)

        def _locked_post(url, data=None, hdrs=None, timeout=10):
            try:
                self._safe_post(url, data=data, headers=hdrs or self._generate_headers(), timeout=timeout)
            except Exception:
                pass

        def _bg_post(url, data=None, hdrs=None, timeout=10):
            self._bg_call(_locked_post, url, data, hdrs, timeout)

        try:
            self.log("[~] Post-reg: starting Feed emulation (~30s)...")

            time.sleep(random.uniform(0.8, 2.7))
            feed_resp = self._safe_get(
                f"{self.BASE_URL}/?caa_reg_splash_screen=1",
                headers=self._generate_nav_headers(referer=f"{self.BASE_URL}/accounts/emailsignup/?next="),
                timeout=15
            )
            self._update_claim_from_response(feed_resp)
            self.lsd = self._extract_lsd_from_text(feed_resp.text) or self.lsd

            m_dtsg = re.search(r'"DTSGInitialData"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"]+)"', feed_resp.text)
            if m_dtsg:
                self.fb_dtsg = m_dtsg.group(1)
            if "ds_user_id" in self.session.cookies:
                self.user_id = self.session.cookies["ds_user_id"]
                uid = str(self.user_id)
            if "csrftoken" in self.session.cookies:
                self.csrf_token = self.session.cookies["csrftoken"]

            self.log(f"[+] Post-reg: Feed loaded (claim={self.ig_www_claim[:15]}..., dtsg_len={len(self.fb_dtsg) if self.fb_dtsg else 0})")

            time.sleep(random.uniform(0.5, 1.4))
            qm_data = urllib.parse.urlencode({
                "event_id": self._IG_HSI,
                "marker_page_time": str(random.randint(2000, 9000)),
                "script_path": "/",
                "weight": "0",
                "client_start": "1",
                "lsd": self.lsd or "",
            })
            _bg_post(f"{self.BASE_URL}/ajax/qm/?__a=1&__user=0&__comet_req=7&jazoest={self._JAZOEST}", data=qm_data)
            _bg_get(f"{self.BASE_URL}/data/manifest.json")
            time.sleep(random.uniform(0.8, 2.1))
            self._send_bz(CRN_FEED, "falco:ig_web_page_view", req_user=uid, module="feedPage")
            if random.random() < 0.75:
                self._bg_call(self._ws_warmup)
            self.log("[+] Post-reg: lightweight emulation complete")

        except Exception as e:
            self.log(f"[~] Post-reg error: {e}")

        time.sleep(random.uniform(12.0, 45.0))

        account_alive = True
        if result.get("username"):
            try:
                if random.random() < 0.18:
                    self.log("[~] External check deferred/skipped for pattern reduction")
                else:
                    if random.random() < 0.45:
                        time.sleep(random.uniform(8.0, 28.0))
                    account_alive = self.check_account_alive(result["username"])
            except Exception as e:
                self.log(f"[~] Post-confirm alive check error: {e}")
        if not account_alive:
            result["status"] = "suspended"
        else:
            result["status"] = "success"
        result["cookies"] = dict(self.session.cookies)
        result["device_id"] = self.ig_did
        result["user_agent"] = self.user_agent

        if enable_2fa:
            try:
                totp_secret = self.enable_2fa()
                if totp_secret:
                    result["totp_secret"] = totp_secret
            except Exception as e:
                self.log(f"[~] 2FA failed: {e}")
        else:
            self.log("[~] 2FA skipped (disabled by user)")

        return result


# ══════════════════════════════════════════════════════════════════════════════
#  ACCOUNT SAVER
# ══════════════════════════════════════════════════════════════════════════════

def save_account(data: Dict, out_dir: str = "accounts") -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    cookies_dir = os.path.join(out_dir, "cookies")
    os.makedirs(cookies_dir, exist_ok=True)

    username   = data.get("username", "unknown")
    ig_pass    = data.get("password", "")
    email_addr = data.get("email", "")
    email_pass = data.get("email_password", "")

    totp_secret = data.get("totp_secret", "")

    txt_path = os.path.join(out_dir, "accounts.txt")
    with open(txt_path, 'a', encoding='utf-8') as f:
        if totp_secret:
            f.write(f"{username}:{ig_pass}:{email_addr}:{email_pass}:{totp_secret}\n")
        else:
            f.write(f"{username}:{ig_pass}:{email_addr}:{email_pass}\n")

    safe_user = re.sub(r'[^\w\-.]', '_', username)
    safe_pass = re.sub(r'[^\w\-.]', '_', ig_pass)
    cookie_path = os.path.join(cookies_dir, f"{safe_user}_{safe_pass}.json")

    editcookie = [
        {
            "name":           name,
            "value":          value,
            "domain":         ".instagram.com",
            "hostOnly":       False,
            "path":           "/",
            "secure":         True,
            "httpOnly":       True,
            "sameSite":       "Lax",
            "session":        False,
            "expirationDate": int(time.time()) + 60 * 60 * 24 * 365,
            "storeId":        "0",
        }
        for name, value in (data.get("cookies") or {}).items()
    ]
    with open(cookie_path, 'w', encoding='utf-8') as f:
        json.dump(editcookie, f, indent=2, ensure_ascii=False)

    return txt_path, cookie_path


# ══════════════════════════════════════════════════════════════════════════════
#  DATA GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class DataGenerator:
    FIRST_NAMES = [
        "Liam","Noah","Oliver","Elijah","James","Aiden","Lucas","Mason",
        "Ethan","Logan","Emma","Olivia","Ava","Sophia","Isabella","Mia",
        "Amelia","Harper","Evelyn","Abigail","Sofia","Elena","Natalia",
        "Anastasia","Valeria","Alina","Kristina","Daria","Polina","Irina",
        "Dmitri","Alexei","Sergei","Andrei","Mikhail","Ivan","Nikolai",
    ]
    LAST_NAMES = [
        "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller",
        "Davis","Wilson","Taylor","Anderson","Thomas","Jackson","White",
        "Harris","Martin","Thompson","Young","Allen","King","Scott","Green",
        "Ivanov","Petrov","Sidorov","Kuznetsov","Novikov","Morozov",
        "Volkov","Popov","Sokolov","Kozlov","Lebedev","Orlov","Fedorov",
    ]
    PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"

    @staticmethod
    def fullname() -> str:
        return (f"{random.choice(DataGenerator.FIRST_NAMES)} "
                f"{random.choice(DataGenerator.LAST_NAMES)}")

    @staticmethod
    def password(length: int = 14) -> str:
        chars = DataGenerator.PASSWORD_CHARS
        pwd   = [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                 random.choice("0123456789"), random.choice("!@#$")]
        pwd  += random.choices(chars, k=length - 3)
        random.shuffle(pwd)
        return ''.join(pwd)

    @staticmethod
    def birthday() -> Tuple[int, int, int]:
        year    = random.randint(1979, 2006)
        month   = random.randint(1, 12)
        max_day = [31,28,31,30,31,30,31,31,30,31,30,31][month-1]
        return random.randint(1, max_day), month, year


# ══════════════════════════════════════════════════════════════════════════════
#  IMAP helper (manual server)
# ══════════════════════════════════════════════════════════════════════════════

def _wait_with_server(reg, email_address, email_password, imap_srv, max_wait=120):
    reg.log(f"[~] IMAP override: {imap_srv}")
    try:
        mail = imaplib.IMAP4_SSL(imap_srv, 993, timeout=30)
        mail.login(email_address, email_password)
        mail.select('INBOX')
        reg.log("[+] IMAP OK")
    except Exception as e:
        reg.log(f"[!] IMAP error: {e}")
        return None

    def _extract(raw_bytes):
        msg  = email.message_from_bytes(raw_bytes)
        subj = ""
        try:
            h    = decode_header(msg['Subject'])[0]
            subj = h[0] if isinstance(h[0], str) else h[0].decode('utf-8', errors='ignore')
        except Exception:
            pass
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except Exception:
                pass
        text = f"{subj} {body}"
        low = text.lower()
        markers = ('instagram', 'confirmation code', 'security code', 'confirm your email', 'instagram code')
        if not any(m in low for m in markers):
            return None
        m = re.search(r'\b(\d{6})\b', text)
        return m.group(1) if m else None

    max_existing = 0
    try:
        st, all_data = mail.search(None, 'ALL')
        all_ids = all_data[0].split() if (st == 'OK' and all_data[0]) else []
        if all_ids:
            max_existing = int(all_ids[-1])
    except Exception:
        pass

    t0 = time.time()
    while time.time() - t0 < max_wait:
        try:
            st, data = mail.search(None, 'ALL')
            if st == 'OK' and data[0]:
                new_ids = [i for i in data[0].split() if int(i) > max_existing]
                for eid in reversed(new_ids):
                    res, mdata = mail.fetch(eid, '(RFC822)')
                    if res != 'OK':
                        continue
                    code = _extract(mdata[0][1])
                    if code:
                        mail.store(eid, '+FLAGS', '\\Seen')
                        mail.close(); mail.logout()
                        reg.log(f"[+] Код: {code}")
                        return code
            time.sleep(5)
        except Exception as e:
            reg.log(f"[!] IMAP poll: {e}")
            time.sleep(5)

    mail.close(); mail.logout()
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════════════════════════

BG     = "#0d0d0d"
BG2    = "#141414"
BG3    = "#1c1c1c"
BORDER = "#252525"
ACC    = "#e1306c"
ACC2   = "#b01050"
FG     = "#e5e5e5"
FG2    = "#888888"
FG3    = "#444444"
GREEN  = "#43a843"
RED    = "#e05050"
YELLOW = "#d4a017"
MONO   = ("Consolas", 9)
SANS   = ("Segoe UI", 10)
SANS_B = ("Segoe UI", 10, "bold")
SANS_S = ("Segoe UI", 9)
SANS_H = ("Segoe UI", 15, "bold")


def _btn(parent, text, command, bg=BG3, fg=FG2, **kw):
    b = tk.Button(parent, text=text, command=command,
                  bg=bg, fg=fg, font=SANS_B,
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=ACC2, activeforeground="white",
                  padx=14, pady=7, **kw)
    return b


SETTINGS_FILE = "ig_registrar_settings.json"


class AnyMessageClient:
    """
    AnyMessage Shop API client (anymessage.shop).
    Orders disposable email for Instagram registration,
    receives confirmation code via API.
    """

    BASE = "https://api.anymessage.shop"

    def __init__(self, token: str, log_fn=None):
        self.token = token
        self.log = log_fn or print
        self._session = requests.Session()

    def check_balance(self) -> Optional[float]:
        try:
            r = self._session.get(
                f"{self.BASE}/user/balance",
                params={"token": self.token}, timeout=15)
            data = r.json()
            if data.get("status") == "success":
                bal = float(data["balance"])
                self.log(f"[+] AnyMessage balance: ${bal:.4f}")
                return bal
            self.log(f"[!] AnyMessage balance error: {data}")
            return None
        except Exception as e:
            self.log(f"[!] AnyMessage balance error: {e}")
            return None

    def order_email(self, domain: str = "gmx.com") -> Optional[dict]:
        params = {
            "token": self.token,
            "site": "instagram.com",
            "domain": domain,
        }
        try:
            r = self._session.get(
                f"{self.BASE}/email/order",
                params=params, timeout=15)
            data = r.json()
            if data.get("status") == "success":
                result = {"id": data["id"], "email": data["email"]}
                self.log(f"[+] AnyMessage ordered: {result['email']} (id={result['id']})")
                return result
            self.log(f"[!] AnyMessage order error: {data}")
            return None
        except Exception as e:
            self.log(f"[!] AnyMessage order error: {e}")
            return None

    def get_code(self, activation_id: str, max_wait: int = 120) -> Optional[str]:
        t0 = time.time()
        attempt = 0
        while time.time() - t0 < max_wait:
            attempt += 1
            try:
                r = self._session.get(
                    f"{self.BASE}/email/getmessage",
                    params={"token": self.token, "id": activation_id},
                    timeout=15)
                data = r.json()
                if data.get("status") == "success":
                    msg = data.get("value", "")
                    m = re.search(r'\b(\d{6})\b', str(msg))
                    if m:
                        code = m.group(1)
                        self.log(f"[+] AnyMessage code: {code}")
                        return code
                    if attempt % 3 == 0:
                        self.log(f"[~] AnyMessage: code not found (attempt {attempt})")
                elif data.get("value") == "wait message":
                    if attempt % 5 == 0:
                        elapsed = int(time.time() - t0)
                        self.log(f"[~] AnyMessage: waiting for email... ({elapsed}s)")
                elif data.get("value") == "activation canceled":
                    self.log("[!] AnyMessage: activation canceled")
                    return None
                elif data.get("value") == "no activation":
                    self.log("[!] AnyMessage: activation not found")
                    return None
            except Exception as e:
                self.log(f"[~] AnyMessage getmessage error: {e}")
            time.sleep(random.uniform(4.0, 6.0))
        self.log(f"[!] AnyMessage: timeout {max_wait}s — code not received")
        return None

    def cancel(self, activation_id: str):
        try:
            self._session.get(
                f"{self.BASE}/email/cancel",
                params={"token": self.token, "id": activation_id},
                timeout=10)
        except Exception:
            pass

    def wait_for_code_via_anymessage(self, activation_id: str,
                                     max_wait: int = 120) -> Optional[str]:
        return self.get_code(activation_id, max_wait)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IG Registrar v18 Headless")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(820, 700)

        self._proxy_pool = ProxyPool()
        self._email_pool = EmailPool()
        self._running    = False
        self._thread     = None
        self._success    = 0
        self._failed     = 0
        self._done       = 0

        self._build()
        self._load_settings()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if not PYNACL_AVAILABLE:
            self.after(500, lambda: messagebox.showwarning(
                "PyNaCl not installed",
                "Password encryption (#PWD_BROWSER:10) unavailable.\n"
                "Install: pip install pynacl\n\n"
                "Without encryption risk of ban is higher."
            ))

    def _load_settings(self):
        try:
            if not os.path.exists(SETTINGS_FILE):
                return
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                s = json.load(f)
            if s.get("emails"):
                self._txt_emails.delete("1.0", "end")
                self._txt_emails.insert("1.0", s["emails"])
                self._upd_email_cnt()
            if s.get("proxies"):
                self._txt_proxies.delete("1.0", "end")
                self._txt_proxies.insert("1.0", s["proxies"])
                self._upd_proxy_cnt()
            if s.get("count"):
                self._v_count.set(int(s["count"]))
            if s.get("imap"):
                self._v_imap.set(s["imap"])
            if s.get("anymessage_token"):
                self._v_anymessage_token.set(s["anymessage_token"])
            if s.get("anymessage_domain"):
                self._v_am_domain.set(s["anymessage_domain"])
            if "enable_2fa" in s:
                self._v_2fa.set(bool(s["enable_2fa"]))
        except Exception:
            pass

    def _save_settings(self):
        try:
            s = {
                "emails":  self._txt_emails.get("1.0", "end").strip(),
                "proxies": self._txt_proxies.get("1.0", "end").strip(),
                "count":   self._v_count.get(),
                "imap":    self._v_imap.get().strip(),
                "anymessage_token": self._v_anymessage_token.get().strip(),
                "anymessage_domain": self._v_am_domain.get().strip(),
                "enable_2fa": self._v_2fa.get(),
            }
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(s, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _on_close(self):
        self._save_settings()
        self.destroy()

    def _build(self):
        self._build_header()
        pane = tk.PanedWindow(self, orient="horizontal", bg=BG,
                              sashwidth=4, sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        left  = tk.Frame(pane, bg=BG, width=350)
        right = tk.Frame(pane, bg=BG)
        pane.add(left,  minsize=320, stretch="never")
        pane.add(right, minsize=300, stretch="always")

        self._build_left(left)
        self._build_right(right)
        self._build_statusbar()

    def _build_header(self):
        h = tk.Frame(self, bg=BG)
        h.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(h, text="Instagram Registrar (Headless)",
                 bg=BG, fg=ACC, font=SANS_H).pack(side="left")
        mods = "[M1\u2713]" if PYNACL_AVAILABLE else "[M1\u2717]"
        tk.Label(h, text=mods, bg=BG, fg=FG3,
                 font=("Segoe UI", 8)).pack(side="left", padx=8)
        self._lbl_total   = tk.Label(h, text="/ 0",  bg=BG, fg=FG2,  font=SANS_S)
        self._lbl_failed  = tk.Label(h, text="\u2717 0",  bg=BG, fg=RED,  font=SANS_B)
        self._lbl_success = tk.Label(h, text="\u2713 0",  bg=BG, fg=GREEN, font=SANS_B)
        self._lbl_total.pack(side="right", padx=(6,0))
        self._lbl_failed.pack(side="right", padx=(8,0))
        self._lbl_success.pack(side="right", padx=(8,0))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=14)

    def _card(self, parent, title: str) -> tk.Frame:
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="x", pady=(0, 8))
        tk.Label(outer, text=f"  {title}",
                 bg=BG2, fg=ACC, font=SANS_B,
                 anchor="w", pady=5).pack(fill="x")
        inner = tk.Frame(outer, bg=BG2, padx=10, pady=8)
        inner.pack(fill="x")
        return inner

    def _field_row(self, parent, label: str, hint: str = "",
                   password: bool = False) -> tk.StringVar:
        row = tk.Frame(parent, bg=BG2)
        row.pack(fill="x", pady=3)
        tk.Label(row, text=label, bg=BG2, fg=FG2, font=SANS_S,
                 width=16, anchor="e").pack(side="left", padx=(0, 8))
        var = tk.StringVar()
        kw  = {}
        if password: kw["show"] = "\u2022"
        e = tk.Entry(row, textvariable=var, bg=BG3, fg=FG,
                     insertbackground=FG, relief="flat", font=SANS_S,
                     bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=ACC, **kw)
        e.pack(side="left", fill="x", expand=True, ipady=5)
        if hint:
            tk.Label(parent, text=hint, bg=BG2, fg=FG3, font=("Segoe UI", 8)
                     ).pack(anchor="e", padx=4)
        return var

    def _build_left(self, parent):
        c = self._card(parent, "\U0001f4e7  Emails")
        tk.Label(c, text="Format: email@domain:password  (one per line)",
                 bg=BG2, fg=FG3, font=("Segoe UI", 8)).pack(anchor="w", pady=(0,3))
        self._txt_emails = tk.Text(c, bg=BG3, fg=FG, insertbackground=FG,
                                   relief="flat", font=MONO, bd=0, height=5,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   highlightcolor=ACC)
        self._txt_emails.pack(fill="x")
        self._lbl_em_cnt = tk.Label(c, text="Emails: 0",
                                    bg=BG2, fg=FG2, font=("Segoe UI", 8))
        self._lbl_em_cnt.pack(anchor="e", pady=(2,0))
        self._txt_emails.bind("<KeyRelease>", self._upd_email_cnt)

        c2 = self._card(parent, "\U0001f310  Proxies  (for IG requests only)")
        tk.Label(c2, text="Format: ip:port:login:pass  (one per line)",
                 bg=BG2, fg=FG3, font=("Segoe UI", 8)).pack(anchor="w", pady=(0,3))
        self._txt_proxies = tk.Text(c2, bg=BG3, fg=FG, insertbackground=FG,
                                    relief="flat", font=MONO, bd=0, height=4,
                                    highlightthickness=1, highlightbackground=BORDER,
                                    highlightcolor=ACC)
        self._txt_proxies.pack(fill="x")
        self._lbl_px_cnt = tk.Label(c2, text="Proxies: 0",
                                    bg=BG2, fg=FG2, font=("Segoe UI", 8))
        self._lbl_px_cnt.pack(anchor="e", pady=(2,0))
        self._txt_proxies.bind("<KeyRelease>", self._upd_proxy_cnt)
        tk.Label(c2, text="Leave empty — requests go without proxy",
                 bg=BG2, fg=FG3, font=("Segoe UI", 8)).pack(anchor="w")

        c3 = self._card(parent, "\u2699\ufe0f  Settings")
        row = tk.Frame(c3, bg=BG2); row.pack(fill="x", pady=3)
        tk.Label(row, text="Accounts:", bg=BG2, fg=FG2, font=SANS_S,
                 width=16, anchor="e").pack(side="left", padx=(0,8))
        self._v_count = tk.IntVar(value=1)
        sb = tk.Spinbox(row, textvariable=self._v_count, from_=1, to=99999,
                        bg=BG3, fg=FG, buttonbackground=BG3,
                        relief="flat", font=SANS_S, bd=0,
                        highlightthickness=1, highlightbackground=BORDER,
                        highlightcolor=ACC, width=8)
        sb.pack(side="left", ipady=5)

        self._v_2fa = tk.BooleanVar(value=True)
        cb_2fa = tk.Checkbutton(c3, text="Enable 2FA", variable=self._v_2fa,
                                bg=BG2, fg=FG, font=SANS_B,
                                selectcolor=BG3, activebackground=BG2,
                                activeforeground=FG, anchor="w")
        cb_2fa.pack(fill="x", pady=(4, 0), padx=(16, 0))

        self._v_imap   = self._field_row(c3, "IMAP (opt.):",
                                         "Empty = auto-detect by domain")
        self._v_anymessage_token = self._field_row(
            c3, "AnyMessage Token:",
            "If set — orders email via anymessage.shop")

        row_am = tk.Frame(c3, bg=BG2)
        row_am.pack(fill="x", pady=3)
        tk.Label(row_am, text="AnyMessage Domain:", bg=BG2, fg=FG2, font=SANS_S,
                 width=16, anchor="e").pack(side="left", padx=(0, 8))
        self._v_am_domain = tk.StringVar(value="gmx.com")
        am_domains = ["gmx.com", "mail.com", "email.com", "icloud.com",
                       "rambler.ru", "gmail.com", "outlook.com", "hotmail.com"]
        am_combo = tk.OptionMenu(row_am, self._v_am_domain, *am_domains)
        am_combo.config(bg=BG3, fg=FG, activebackground=ACC2, activeforeground="white",
                        highlightthickness=1, highlightbackground=BORDER,
                        relief="flat", font=SANS_S, bd=0)
        am_combo["menu"].config(bg=BG3, fg=FG, activebackground=ACC2,
                                activeforeground="white", font=SANS_S)
        am_combo.pack(side="left", fill="x", expand=True, ipady=3)
        tk.Label(c3, text="Domain for email ordering (gmx.com available)",
                 bg=BG2, fg=FG3, font=("Segoe UI", 8)).pack(anchor="e", padx=4)

        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", pady=(2, 0))

        self._btn_start = _btn(bf, "\u25b6  START", self._start, bg=ACC, fg="white")
        self._btn_start.pack(side="left", padx=(0, 6))
        _btn(bf, "\u25a0  STOP",   self._stop).pack(side="left", padx=(0, 6))
        _btn(bf, "\U0001f5d1  Log",   self._clear_log).pack(side="left")

    def _build_right(self, parent):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        tk.Label(parent, text="Execution log",
                 bg=BG, fg=FG2, font=SANS_S, anchor="w").grid(
            row=0, column=0, sticky="w", pady=(0, 4))

        self.log_box = scrolledtext.ScrolledText(
            parent, bg="#080808", fg="#9ef09e",
            insertbackground="#9ef09e",
            font=MONO, state="disabled", relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            selectbackground="#222")
        self.log_box.grid(row=1, column=0, sticky="nsew")

        self.log_box.tag_config("ok",   foreground="#43c843")
        self.log_box.tag_config("err",  foreground="#e05050")
        self.log_box.tag_config("warn", foreground="#d4a017")
        self.log_box.tag_config("dim",  foreground="#454545")
        self.log_box.tag_config("info", foreground="#9ef09e")

    def _build_statusbar(self):
        bar = tk.Frame(self, bg="#111", height=22)
        bar.pack(fill="x", side="bottom")
        self._status_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self._status_var,
                 bg="#111", fg=FG3, font=("Segoe UI", 8),
                 anchor="w", padx=10).pack(fill="x")

    def _upd_email_cnt(self, _=None):
        n = sum(1 for l in self._txt_emails.get("1.0","end").splitlines()
                if ':' in l.strip())
        self._lbl_em_cnt.config(text=f"Emails: {n}")

    def _sync_emails_widget(self):
        remaining = self._email_pool.to_text()
        self._txt_emails.delete("1.0", "end")
        if remaining:
            self._txt_emails.insert("1.0", remaining)
        self._upd_email_cnt()

    def _upd_proxy_cnt(self, _=None):
        n = sum(1 for l in self._txt_proxies.get("1.0","end").splitlines()
                if l.strip())
        self._lbl_px_cnt.config(text=f"Proxies: {n}")

    def _upd_counters(self):
        self.after(0, lambda: [
            self._lbl_success.config(text=f"\u2713 {self._success}"),
            self._lbl_failed.config(text=f"\u2717 {self._failed}"),
            self._lbl_total.config(text=f"/ {self._done}"),
        ])

    def _log(self, msg: str):
        def _do():
            self.log_box.configure(state="normal")
            ts  = datetime.now().strftime("%H:%M:%S")
            tag = "info"
            if   msg.startswith("[+]") or "SUCCESS" in msg.upper():  tag = "ok"
            elif msg.startswith("[\u2717]") or msg.startswith("[!]"): tag = "err"
            elif msg.startswith("[~]"):                     tag = "dim"
            elif "ERROR" in msg.upper(): tag = "warn"
            self.log_box.insert("end", f"[{ts}] {msg}\n", tag)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
            self._status_var.set(msg[:110])
        self.after(0, _do)

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _stop(self):
        self._running = False
        self._log("[~] Stop requested...")

    def _start(self):
        if self._thread and self._thread.is_alive():
            messagebox.showwarning("Busy", "Already running")
            return

        anymessage_token = self._v_anymessage_token.get().strip() or None

        self._email_pool.load(self._txt_emails.get("1.0", "end"))
        if self._email_pool.count() == 0 and not anymessage_token:
            messagebox.showerror("Error",
                "Add at least one email\nFormat: email:password\n"
                "Or set AnyMessage Token for auto-ordering")
            return

        self._proxy_pool.load(self._txt_proxies.get("1.0", "end"))

        count = max(1, self._v_count.get())
        if not anymessage_token and self._email_pool.count() < count:
            if not messagebox.askyesno(
                "Not enough emails",
                f"Emails: {self._email_pool.count()}, requested: {count}.\n"
                "Create as many as available?"
            ):
                return
            count = self._email_pool.count()

        self._done = self._success = self._failed = 0
        self._upd_counters()
        self._running = True
        self._btn_start.config(state="disabled")
        self._thread = threading.Thread(target=self._run_batch,
                                        args=(count,), daemon=True)
        self._thread.start()

    def _run_batch(self, total: int):
        anymessage_token = self._v_anymessage_token.get().strip() or None
        am_client = AnyMessageClient(anymessage_token, log_fn=self._log) if anymessage_token else None
        am_domain = self._v_am_domain.get().strip() if hasattr(self, '_v_am_domain') else "gmx.com"

        if am_client:
            bal = am_client.check_balance()
            if bal is None or bal <= 0:
                self._log("[!] AnyMessage: no balance or token error — stop")
                self._running = False
                self.after(0, lambda: self._btn_start.config(state="normal"))
                return
            self._log(f"[~] === Start: {total} accounts | AnyMessage API ({am_domain}) | "
                      f"proxies={self._proxy_pool.count()} ===")
        else:
            self._log(f"[~] === Start: {total} accounts | "
                      f"emails={self._email_pool.count()} | "
                      f"proxies={self._proxy_pool.count()} ===")

        for i in range(total):
            if not self._running:
                self._log("[~] Stopped")
                break

            if am_client:
                order = am_client.order_email(domain=am_domain)
                if not order:
                    self._log("[!] AnyMessage: failed to order email — skipping")
                    self._failed += 1
                    self._done += 1
                    self._upd_counters()
                    continue
                email_addr = order["email"]
                email_pwd = ""
                activation_id = order["id"]
            else:
                pair = self._email_pool.pop()
                if not pair:
                    self._log("[!] Emails exhausted — stop")
                    break
                email_addr, email_pwd = pair
                activation_id = None
                self.after(0, self._sync_emails_widget)

            proxy = self._proxy_pool.next()
            self._log(f"[~] -- Account {i+1}/{total} --  {email_addr}")
            if proxy:
                host = proxy.split('@')[-1] if '@' in proxy else proxy
                self._log(f"[~] Proxy: {host}")
            self._run_one(i + 1, total, email_addr, email_pwd, proxy,
                          am_client=am_client, activation_id=activation_id)

        self._running = False
        self.after(0, lambda: self._btn_start.config(state="normal"))
        self._log(f"[~] === Done: \u2713{self._success}  \u2717{self._failed} ===")

    def _run_one(self, idx: int, total: int,
                 email_addr: str, email_pwd: str, proxy: Optional[str],
                 am_client=None, activation_id=None):
        imap_host = self._v_imap.get().strip() or None

        fullname = DataGenerator.fullname()
        ig_password = DataGenerator.password()
        day, month, year = DataGenerator.birthday()

        fingerprint = BrowserFingerprint(proxy=proxy, geo='us')

        self._log(f"[~] {fullname}  {day:02d}.{month:02d}.{year}  pw={ig_password}")
        self._log(f"[+] Fingerprint: Chrome {fingerprint.chrome_major} | DPR={fingerprint.dpr} | Screen={fingerprint.hw_profile['screen_width']}x{fingerprint.hw_profile['screen_height']}")

        try:
            reg = InstagramRegistrar(
                proxy=proxy,
                log_fn=self._log,
                fingerprint=fingerprint,
            )

            if imap_host:
                def patched(ea, ep, mw=120):
                    return _wait_with_server(reg, ea, ep, imap_host, mw)
                reg.wait_for_code = patched

            if am_client and activation_id:
                _am_id = activation_id
                _am_ref = am_client
                def _am_wait(ea, ep, mw=120):
                    return _am_ref.wait_for_code_via_anymessage(_am_id, mw)
                reg.wait_for_code = _am_wait
                self._log(f"[+] AnyMessage: waiting for code via API (activation_id={activation_id})")

            result = reg.register(
                email_addr=email_addr, email_password=email_pwd,
                password=ig_password, fullname=fullname,
                birthday=(day, month, year),
                enable_2fa=self._v_2fa.get(),
            )

            self._done += 1

            if result["status"] == "success":
                username = result.get("username", "?")

                time.sleep(random.uniform(3, 6))
                alive = reg.check_account_alive(username)

                if not alive:
                    self._failed += 1
                    self._upd_counters()
                    self._log(f"[\u2717] @{username} — banned immediately, not saving")
                    return

                txt_path, cookie_path = save_account(result)
                self._success += 1
                self._upd_counters()
                self._log(f"[+] SUCCESS [{idx}/{total}]  @{username}")
                self._log(f"[+] {txt_path}")
                self._log(f"[+] {cookie_path}")
            else:
                self._failed += 1
                self._upd_counters()
                self._log(f"[\u2717] ERROR [{idx}/{total}]: {result['error']}")

        except Exception as e:
            import traceback
            self._log(f"[\u2717] ERROR [{idx}/{total}] EXCEPTION: {e}")
            self._log(f"[\u2717] {traceback.format_exc()}")
            self._failed += 1
            self._upd_counters()
        finally:
            if am_client and activation_id:
                try: am_client.cancel(activation_id)
                except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.mainloop()
