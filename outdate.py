#!/usr/bin/env python3
# package_problem_detector.py
# Output only problematic dependencies with all English fields
import argparse
import concurrent.futures as cf
import csv
import re
import time
from datetime import datetime, timezone
from threading import Lock, Semaphore

import requests
from packaging.version import Version, InvalidVersion

PACKAGIST_LIST_URL = "https://packagist.org/packages/list.json"
P2_URL = "https://repo.packagist.org/p2/{vendor}/{name}.json"
ABANDONED_URL = "https://packagist.org/packages/list.json"

UA = {"User-Agent": "PackagistProblemDetector/1.0"}
TIMEOUT = 25
MAX_RETRIES = 4
BACKOFF_BASE = 0.6

GLOBAL_NET_SEMA = Semaphore(64)
EXCLUDE_PREFIX = ("php", "ext-", "lib-")

def http_get_json(url, params=None):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with GLOBAL_NET_SEMA:
                r = requests.get(url, params=params, headers=UA, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except requests.RequestException:
            if attempt == MAX_RETRIES:
                raise
            time.sleep(BACKOFF_BASE * attempt)

def list_all_packages():
    return (http_get_json(PACKAGIST_LIST_URL).get("packageNames") or [])

def fetch_p2(fullname):
    vendor, name = fullname.split("/", 1)
    return http_get_json(P2_URL.format(vendor=vendor, name=name))

def parse_iso(ts):
    if not ts: return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def latest_stable_item(p2, fullname):
    items = (p2.get("packages", {}) or {}).get(fullname, []) or []
    best = None
    for it in items:
        ver = it.get("version")
        if not ver: continue
        if any(tag in ver for tag in ("dev", "alpha", "beta", "RC", "rc")):
            continue
        try:
            pv = Version(ver.lstrip("v"))
        except InvalidVersion:
            continue
        if best is None or pv > best[0]:
            best = (pv, it.get("version"), it.get("time"), it)
    if not best: return None
    return {"version": best[1], "time": best[2], "raw": best[3]}

# -------- Constraint Validation --------
R_EXACT = re.compile(r"^\s*v?\d+(\.\d+){0,2}\s*$")
R_WILDCARD_MAJOR = re.compile(r"^\s*(\d+)\.(\*|x)(?:-dev)?\s*$", re.I)
R_WILDCARD_MINOR = re.compile(r"^\s*(\d+)\.(\d+)\.(\*|x)(?:-dev)?\s*$", re.I)

def allows_latest_and_note(constraint: str, latest: Version):
    if latest is None:
        return True, ""
    c = (constraint or "").strip()
    first = re.split(r"\s*\|\|\s*|\s*,\s*", c)[0]


    if any(sym in first for sym in (">", "<")):
        try:
            ge = re.search(r">=?\s*([0-9][^<>\s]+)", first)
            lt = re.search(r"<\s*([0-9][^<>\s]+)", first)
            if ge and latest < Version(ge.group(1).lstrip("v")):
                return False, f"Allows >= {ge.group(1)}; latest {latest}"
            if lt and latest >= Version(lt.group(1).lstrip("v")):
                return False, f"Allows < {lt.group(1)}; latest {latest}"
            return True, ""
        except Exception:
            return True, ""


    if first.startswith("^"):
        try:
            base = Version(first[1:].lstrip("v"))
            if not (latest.major == base.major and latest >= base):
                return False, f"Allows >= {base.public} and < {base.major+1}.0.0; latest {latest}"
            return True, ""
        except Exception:
            return True, ""


    if first.startswith("~"):
        try:
            base = Version(first[1:].lstrip("v"))
            if not (latest.major == base.major and latest.minor == base.minor and latest >= base):
                return False, f"Allows >= {base.public} and < {base.major}.{base.minor+1}.0; latest {latest}"
            return True, ""
        except Exception:
            return True, ""


    m = R_WILDCARD_MAJOR.match(first)
    if m:
        maj = int(m.group(1))
        if latest.major != maj:
            return False, f"Allows {maj}.*; latest {latest}"
        return True, ""


    m = R_WILDCARD_MINOR.match(first)
    if m:
        maj = int(m.group(1)); minor = int(m.group(2))
        if not (latest.major == maj and latest.minor == minor):
            return False, f"Allows {maj}.{minor}.*; latest {latest}"
        return True, ""


    if R_EXACT.match(first):
        try:
            base = Version(first.lstrip("v"))
            if not (latest <= base):
                return False, f"Allows =={base.public}; latest {latest}"
            return True, ""
        except Exception:
            return True, ""

    return True, ""

_abandoned_cache = {}
_abandoned_lock = Lock()

def is_abandoned(fullname: str) -> bool:
    vendor, _ = fullname.split("/", 1)
    with _abandoned_lock:
        mp = _abandoned_cache.get(vendor)
    if mp is None:
        try:
            data = http_get_json(ABANDONED_URL, params={"vendor": vendor, "fields[]": ["abandoned"]})
            src = data.get("package", {}) or {}
            mp = {k: (v.get("abandoned") is True or isinstance(v.get("abandoned"), str)) for k, v in src.items()}
        except Exception:
            mp = {}
        with _abandoned_lock:
            _abandoned_cache[vendor] = mp
    return mp.get(fullname, False)

# -------- Process Root Package --------
def process_root(root_name: str, stale_days: int):
    rows = []
    try:
        p2 = fetch_p2(root_name)
        root = latest_stable_item(p2, root_name)
        if not root: return rows
        root_ver = root["version"]

        require = (root["raw"].get("require") or {})
        for dep, cons in require.items():
            if "/" not in dep or dep.startswith(EXCLUDE_PREFIX):
                continue

            dp2 = fetch_p2(dep)
            d = latest_stable_item(dp2, dep)
            dep_latest_ver = d["version"] if d else None
            dep_latest_time = d["time"] if d else None
            dep_latest_obj = None
            if dep_latest_ver:
                try:
                    dep_latest_obj = Version(dep_latest_ver.lstrip("v"))
                except InvalidVersion:
                    dep_latest_obj = None

            problems = []
            notes = []

            allowed, note = allows_latest_and_note(cons, dep_latest_obj)
            if not allowed:
                problems.append("Outdated version constraint")
                if note: notes.append(note)

            if is_abandoned(dep):
                problems.append("Abandoned")

            stale = False
            if dep_latest_time:
                dt = parse_iso(dep_latest_time)
                if dt:
                    age = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days
                    stale = age >= stale_days
            if stale:
                problems.append("Long time no update")

            if problems:
                rows.append({
                    "Root Package": root_name,
                    "Root Package Version": root_ver,
                    "Dependency Package": dep,
                    "Version Constraint": cons,
                    "Latest Dependency Version": dep_latest_ver or "-",
                    "Latest Dependency Release Time": dep_latest_time or "-",
                    "Problem Type": "; ".join(problems),
                    "Notes": "; ".join(notes) if notes else "",
                })

            time.sleep(0.01)
    except Exception:
        pass
    return rows

def main():
    ap = argparse.ArgumentParser(description="Output problematic dependencies (English field version)")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--out", default="out_problem_package.csv")
    ap.add_argument("--stale-months", type=int, default=6, help="Long time no update threshold (months)")
    ap.add_argument("--limit", type=int, default=0, help="Only scan first N packages (debug)")
    args = ap.parse_args()

    stale_days = int(args.stale_months * 30.4375)

    print("[1/3] Retrieving all package names ...")
    names = list_all_packages()
    if args.limit and args.limit > 0:
        names = names[:args.limit]
    total = len(names)
    print(f"Total {total} packages, starting concurrent processing ({args.workers} threads) ...")

    lock = Lock()
    processed = 0
    all_rows = []

    def worker(pkg):
        nonlocal processed
        rows = process_root(pkg, stale_days)
        with lock:
            processed += 1
            if processed % 500 == 0:
                print(f"  Progress {processed}/{total}")
            all_rows.extend(rows)

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(worker, names))

    print("[2/3] Writing CSV ...")
    fields = ["Root Package","Root Package Version","Dependency Package","Version Constraint","Latest Dependency Version","Latest Dependency Release Time","Problem Type","Notes"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in all_rows:
            w.writerow(r)

    print("[3/3] Completed")
    print(f"Output: {args.out}")
    #print(f"Problematic dependency entries: {len(all_rows)}")

if __name__ == "__main__":
    main()
