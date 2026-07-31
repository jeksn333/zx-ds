#!/usr/bin/env python3
import sys, os, json, time
sys.path.insert(0, r'C:\Users\jeksn\OneDrive\Рабочий стол\фышl\asik')
os.chdir(r'C:\Users\jeksn\OneDrive\Рабочий стол\фышl\asik')

from ig_hash_cache import _load_cache, _score_hashes, CACHE_TTL, REQUIRED, _is_real_hash, CACHE_FILE

print(f"Cache file: {CACHE_FILE}")
print(f"Exists: {CACHE_FILE.exists()}")
if CACHE_FILE.exists():
    data = json.loads(CACHE_FILE.read_text(encoding='utf-8'))
    ts = data.get('_cached_at', 0)
    age_min = int((time.time() - ts) / 60)
    print(f"Age: {age_min} min")
    print(f"Expired (>6h): {time.time() - ts > CACHE_TTL}")
    for k in REQUIRED:
        v = data.get(k, '')
        print(f"  {k}: len={len(v)} is_real={_is_real_hash(v)} val={v[:50]}")

print("\n--- _load_cache() ---")
result = _load_cache()
if result:
    print(f"Score: {_score_hashes(result)}")
else:
    print("None returned")

print("\n--- get_hashes(force_refresh=False) ---")
from ig_hash_cache import get_hashes
h = get_hashes(force_refresh=False)
print(f"Score: {_score_hashes(h)}")
for k in REQUIRED:
    v = h.get(k, '')
    print(f"  {k}: len={len(v)} val={v[:50] if v else 'MISSING'}")
