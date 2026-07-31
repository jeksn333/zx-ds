#!/usr/bin/env python3
"""
Instagram Runtime Hash Cache v3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Основной путь: Camoufox → открыть signup page → перехватить реальные runtime
hashes из request body / page HTML → закрыть браузер.

Если Camoufox не дал полный набор, пробуем nodriver.
"""

import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

CACHE_FILE = Path(__file__).parent / "ig_hashes_cache.json"
CACHE_TTL = 6 * 3600
REQUIRED = ("__dyn", "__csr", "__hsdp", "__hblp", "__sjsp")
REAL_HASH_RE = re.compile(r'^[A-Za-z0-9_\-]{30,}$')


FAKE_PREFIXES = ('gjh2', 'kw-wk', '04uwd')

def _is_real_hash(val):
    if not val or not REAL_HASH_RE.match(val):
        return False
    if val.startswith(':'):
        return False
    if re.match(r'^[\d,\s:]+$', val):
        return False
    for fp in FAKE_PREFIXES:
        if val.startswith(fp):
            return False
    return True


def _load_cache():
    if not CACHE_FILE.exists():
        return None
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        ts = data.get("_cached_at", 0)
        age_min = int((time.time() - ts) / 60)
        if time.time() - ts > CACHE_TTL:
            print(f"[hash-cache] Кэш старше 6 часов ({age_min} мин назад)")
            return None
        if all(_is_real_hash(data.get(k, "")) for k in REQUIRED):
            print(f"[hash-cache] Кэш свежий ({age_min} мин назад)")
            return data
        print("[hash-cache] Кэш найден, но значения не похожи на реальные runtime hash")
        return None
    except Exception as e:
        print(f"[hash-cache] Ошибка: {e}")
        return None


def _save_cache(data):
    out = {k: data[k] for k in REQUIRED if data.get(k)}
    out["_cached_at"] = time.time()
    CACHE_FILE.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[hash-cache] Сохранено в {CACHE_FILE.name}")


def _extract_from_text(text):
    """Extract hashes from any text (URL params, form data, JSON, HTML, etc.)."""
    if not text:
        return {}
    result = {}
    for key in REQUIRED:
        if result.get(key):
            continue
        # Try URL-encoded form: __dyn=xxx
        pat_url = re.escape(key) + r'=([A-Za-z0-9_\-]{20,})'
        m = re.search(pat_url, text)
        if m and _is_real_hash(m.group(1)):
            result[key] = m.group(1)
            continue
        # Try JSON: "__dyn":"xxx"
        pat_json = r'"' + re.escape(key) + r'"\s*:\s*"([A-Za-z0-9_\-]{20,})"'
        m = re.search(pat_json, text)
        if m and _is_real_hash(m.group(1)):
            result[key] = m.group(1)
    return result


def _merge_hashes(*sources):
    merged = {}
    for src in sources:
        if not src:
            continue
        for k in REQUIRED:
            v = src.get(k)
            if v and _is_real_hash(v) and not merged.get(k):
                merged[k] = v
    return merged


def _score_hashes(h):
    return sum(1 for k in REQUIRED if _is_real_hash(h.get(k, "")))


def _fetch_via_nodriver():
    try:
        import nodriver
    except Exception as e:
        print(f"[hash-cache] nodriver import failed: {e}")
        print(f"[hash-cache] Python: {sys.executable}")
        return {}

    import asyncio

    async def _run():
        print("[hash-cache] Запускаю Chrome (nodriver fallback)...")
        browser = await nodriver.start(
            headless=False,
            browser_args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-infobars",
                "--window-size=1920,1080",
            ],
        )
        page = await browser.get("https://www.instagram.com/accounts/emailsignup/")
        await page.sleep(12)
        js_hashes = {}
        try:
            result = await page.evaluate("""(() => {
                const r = {};
                const scripts = document.querySelectorAll('script');
                for (const s of scripts) {
                    const t = s.textContent || '';
                    if (t.length < 100) continue;
                    const pats = {
                        __dyn: /"__dyn"\\s*:\\s*"([A-Za-z0-9_\\-]{50,})"/,
                        __csr: /"__csr"\\s*:\\s*"([A-Za-z0-9_\\-]{50,})"/,
                        __hsdp: /"__hsdp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
                        __hblp: /"__hblp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
                        __sjsp: /"__sjsp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
                    };
                    for (const [k, p] of Object.entries(pats)) {
                        if (!r[k]) {
                            const m = t.match(p);
                            if (m && !m[1].match(/^[\\d:,]+$/)) r[k] = m[1];
                        }
                    }
                }
                return r;
            })()""")
            if result:
                js_hashes = {k: v for k, v in result.items() if _is_real_hash(v)}
        except Exception:
            pass
        try:
            browser.stop()
        except Exception:
            pass
        return js_hashes

    return asyncio.run(_run())


def _fetch_via_camoufox_sync():
    try:
        from camoufox.sync_api import Camoufox
    except Exception as e:
        print(f"[hash-cache] camoufox import failed: {e}")
        print(f"[hash-cache] Python: {sys.executable}")
        return {}

    print("[hash-cache] Запускаю Camoufox...")
    all_hashes = {}
    done = {"ready": False}

    def try_merge_from_text(text, tag=""):
        if not text or done["ready"]:
            return
        h = _extract_from_text(text)
        count = _score_hashes(h)
        if count > 0:
            before = _score_hashes(all_hashes)
            all_hashes.update({k: v for k, v in h.items() if _is_real_hash(v) and not all_hashes.get(k)})
            after = _score_hashes(all_hashes)
            if after > before:
                print(f"[hash-cache] {tag}: {after}/5 hash (+{after - before})")
        if _score_hashes(all_hashes) >= 5:
            done["ready"] = True
            print("[hash-cache] Все 5 hash получены!")

    JS_EXTRACT = """(() => {
        const r = {};
        const scripts = document.querySelectorAll('script');
        for (const s of scripts) {
            const t = s.textContent || '';
            if (t.length < 100) continue;
            const pats = {
                __dyn: /"__dyn"\\s*:\\s*"([A-Za-z0-9_\\-]{50,})"/,
                __csr: /"__csr"\\s*:\\s*"([A-Za-z0-9_\\-]{50,})"/,
                __hsdp: /"__hsdp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
                __hblp: /"__hblp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
                __sjsp: /"__sjsp"\\s*:\\s*"([A-Za-z0-9_\\-]{20,})"/,
            };
            for (const [k, p] of Object.entries(pats)) {
                if (!r[k]) {
                    const m = t.match(p);
                    if (m && !m[1].match(/^[\\d:,]+$/)) r[k] = m[1];
                }
            }
        }
        return r;
    })()"""

    def extract_js():
        try:
            result = page.evaluate(JS_EXTRACT) or {}
            return {k: v for k, v in result.items() if _is_real_hash(v)}
        except Exception:
            return {}

    try:
        with Camoufox(headless=True) as browser:
            page = browser.new_page()

            def handle_request(request):
                try:
                    url = request.url or ""
                    body = getattr(request, "post_data", None)
                    if callable(body):
                        body = body()
                    # Extract from URL params
                    if "?" in url:
                        try_merge_from_text(url.split("?", 1)[1], tag="req-url")
                    # Extract from POST body
                    if body:
                        try_merge_from_text(body, tag="req-body")
                except Exception:
                    pass

            def handle_response(response):
                try:
                    url = response.url or ""
                    # Extract from response URL params
                    if "?" in url:
                        try_merge_from_text(url.split("?", 1)[1], tag="resp-url")
                    # Extract from response body (small text only)
                    try:
                        ct = response.headers.get("content-type", "")
                        if "json" in ct or "text" in ct:
                            body = response.text()
                            if body and len(body) < 500000:
                                try_merge_from_text(body, tag="resp-body")
                    except Exception:
                        pass
                except Exception:
                    pass

            page.on("request", handle_request)
            page.on("response", handle_response)

            print("[hash-cache] Открываю signup page...")
            page.goto("https://www.instagram.com/accounts/emailsignup/", wait_until="domcontentloaded", timeout=60000)
            time.sleep(2)

            # Extract from page HTML immediately
            try:
                html = page.content()
                try_merge_from_text(html, tag="html")
            except Exception:
                pass

            # Extract from inline scripts
            js_h = extract_js()
            if js_h:
                all_hashes.update({k: v for k, v in js_h.items() if not all_hashes.get(k)})
                print(f"[hash-cache] js: {_score_hashes(all_hashes)}/5 hash")

            if done["ready"]:
                return all_hashes

            # Fill form to trigger more requests
            for selector, value in [
                ('input[name="emailOrPhone"]', 'test@testmail.com'),
                ('input[name="fullName"]', 'John Test'),
                ('input[name="username"]', 'testuser1234567'),
                ('input[name="password"]', 'Qwerty123!_987'),
            ]:
                try:
                    page.fill(selector, value)
                    time.sleep(0.5)
                except Exception:
                    pass

            try:
                page.mouse.move(400, 300)
                time.sleep(0.3)
                page.mouse.move(650, 420)
            except Exception:
                pass

            print(f"[hash-cache] Жду hashes (до 45 сек)...")

            # Try to submit the form to trigger graphql requests
            try:
                page.click('button[type="submit"]')
            except Exception:
                pass

            started = time.time()
            while time.time() - started < 45 and not done["ready"]:
                time.sleep(0.5)
                if done["ready"]:
                    break

                elapsed = int(time.time() - started)

                # Re-extract from JS every 2 seconds
                if elapsed % 2 == 0 and elapsed > 0:
                    js_h = extract_js()
                    if js_h:
                        before = _score_hashes(all_hashes)
                        all_hashes.update({k: v for k, v in js_h.items() if not all_hashes.get(k)})
                        after = _score_hashes(all_hashes)
                        if after > before:
                            print(f"[hash-cache] js: {after}/5 hash (+{after - before})")
                        if after >= 5:
                            done["ready"] = True
                            break

                # Re-extract from page HTML every 4 seconds
                if elapsed % 4 == 0 and elapsed > 0:
                    try:
                        html = page.content()
                        try_merge_from_text(html, tag="html-re")
                    except Exception:
                        pass

                if done["ready"]:
                    break

            print(f"[hash-cache] Итого: {_score_hashes(all_hashes)}/5 hash за {int(time.time() - started)} сек")
            return all_hashes
    except Exception as e:
        print(f"[hash-cache] camoufox ошибка: {e}")
        return all_hashes


def fetch_hashes_via_browser():
    """Prefer Camoufox, fallback to nodriver."""
    hashes = _fetch_via_camoufox_sync()
    if _score_hashes(hashes) == 5:
        return hashes

    print("[hash-cache] Camoufox не дал полный набор, пробую nodriver...")
    hashes2 = _fetch_via_nodriver()
    return _merge_hashes(hashes, hashes2)


def get_hashes(force_refresh=False):
    if not force_refresh:
        cached = _load_cache()
        if cached and all(_is_real_hash(cached.get(k, "")) for k in REQUIRED):
            return cached

    hashes = fetch_hashes_via_browser()
    if all(_is_real_hash(hashes.get(k, "")) for k in REQUIRED):
        _save_cache(hashes)
        print("[hash-cache] Все хеши закэшированы:")
        for k in REQUIRED:
            print(f"  {k}: {hashes[k][:40]}...")
    else:
        missing = [k for k in REQUIRED if not _is_real_hash(hashes.get(k, ""))]
        print(f"[hash-cache] Не удалось получить: {missing}")
    return hashes


if __name__ == "__main__":
    force = "--force" in sys.argv
    h = get_hashes(force_refresh=force)
    print("\n[RESULT]")
    for k in REQUIRED:
        v = h.get(k, "MISSING")
        print(f"  {k}: {v[:60] if v else 'MISSING'}")
