# scripts/rcpm_hourly_multipair.py
# Live hourly updater for one or more bases (RON/RCPM pairs).
# - Uses today's last full hour (UTC)
# - For each base, exports current lists, computes targets, then MOVES bundles
#   (add dest -> delete source) so final (RON ∪ RCPM) == old union
# - Writes:
#     report output/exports/export_*.csv   (pre-change backups)
#     report output/updated_lists/updated_*.csv (final planned composition per list)
#     report output/exports/final_*.csv    (post-update snapshots from API)

import os, re, csv
from datetime import date, timedelta, datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------- Config via ENV ----------
BASE_URL        = os.getenv("RCPM_BASE_URL", "https://ssp.playdigo.com")
TIMEOUT         = (10, 60)
PAGE_LIMIT      = int(os.getenv("PAGE_LIMIT", "50000"))
TIME_ZONE       = os.getenv("TIME_ZONE", "UTC")
DAY_GROUP       = "hour"
OUTDIR          = Path(os.getenv("OUTDIR", "report output/updated_lists"))
EXPORT_DIR      = Path(os.getenv("EXPORT_DIR", "report output/exports"))
LIVE_UPDATES    = os.getenv("LIVE_UPDATES", "true").lower() in {"1","true","yes","on"}
IMP_THRESHOLD   = float(os.getenv("IMP_THRESHOLD", "20"))
SRCPM_THRESHOLD = float(os.getenv("SRCPM_THRESHOLD", "0.7"))
WRITE_BATCH     = int(os.getenv("WRITE_BATCH", "1000"))

EMAIL           = os.getenv("TEQBLAZE_EMAIL", "")
PASSWORD        = os.getenv("TEQBLAZE_PASSWORD", "")
# Accept multiple bases via BASE_FILTERS (comma/semicolon/newline separated)
_BASE_FILTERS   = os.getenv("BASE_FILTERS") or os.getenv("BASE_FILTER", "")
BASES: List[str] = [b.strip() for b in re.split(r"[,\n;]+", _BASE_FILTERS) if b.strip()]

if not EMAIL or not PASSWORD:
    raise SystemExit("ENV TEQBLAZE_EMAIL and TEQBLAZE_PASSWORD are required.")
if not BASES:
    raise SystemExit("ENV BASE_FILTERS (or BASE_FILTER) must contain one or more base names.")

# ---------- Small utils ----------
def make_session(retries=5, backoff=0.5) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries, connect=retries, read=retries, status=retries,
        backoff_factor=backoff, status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"]), raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter); s.mount("http://", adapter)
    return s

def sanitize_filename(s: str) -> str:
    s = (s or "").strip()
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", s)[:180] or "unknown"

def write_csv(path: Path, headers: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows: w.writerow(r)
    print(f"[csv] wrote {len(rows)} -> {path}")

# ---------- Names & bundles ----------
def strip_trailing_id(s: str) -> str:
    return re.sub(r"[\s\-_()#]*\d+\s*$", "", s or "", flags=re.IGNORECASE).strip()

def extract_base_and_variant(name: str) -> Tuple[str, Optional[str]]:
    s = strip_trailing_id((name or "").strip())
    matches = list(re.finditer(r"(?<![A-Za-z0-9])(RON|RCPM)(?![A-Za-z0-9])", s, flags=re.IGNORECASE))
    if not matches:
        return (s.strip(" -_()"), None)
    last = matches[-1]
    base = re.sub(r"[\s\-_()*]+$", "", s[:last.start()]).strip(" -_()")
    return base, last.group(1).upper()

_NUM_RE = re.compile(r"^\d+$")
_ID_RE  = re.compile(r"^[Ii][Dd]\d+$")

def canonical_bundle(x: Any) -> str:
    s = str(x or "").strip()
    if _ID_RE.fullmatch(s): return s[2:]
    return s

def prefer_style(current_values: List[str]) -> str:
    return "id" if any(_ID_RE.fullmatch(v.strip()) for v in current_values) else "num"

def format_with_style(canon: str, style: str) -> str:
    return (f"id{canon}" if style == "id" else canon) if _NUM_RE.fullmatch(canon) else canon

# ---------- API ----------
def create_token(session: requests.Session, email: str, password: str, minutes=120) -> dict:
    r = session.post(f"{BASE_URL}/api/create_token",
                     data={"email": email, "password": password, "time": str(minutes)},
                     timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if (end_ts := data.get("end")):
        print(f"[auth] token ends (UTC): {datetime.utcfromtimestamp(float(end_ts)).isoformat()}Z")
    return data

def adx_report(session: requests.Session, token: str, d_from: str, d_to: str,
               attributes: List[str], metrics: List[str]) -> List[Dict[str, Any]]:
    url = f"{BASE_URL}/api/{token}/adx-report"
    page, out = 1, []
    while True:
        params = [("from", d_from), ("to", d_to),
                  ("time_zone", TIME_ZONE), ("day_group", DAY_GROUP),
                  ("limit", str(PAGE_LIMIT)), ("page", str(page))]
        for a in attributes: params.append(("attribute[]", a))
        for m in metrics:    params.append(("metric[]", m))
        r = session.get(url, params=params, timeout=TIMEOUT); r.raise_for_status()
        data = r.json()
        rows = data if isinstance(data, list) else (data.get("data") or data.get("rows") or data.get("items") or [])
        print(f"[report] page={page} rows={len(rows)}")
        out.extend(rows)
        if not rows or len(rows) < PAGE_LIMIT: break
        page += 1
    print(f"[report] total rows today: {len(out)}")
    return out

def list_filter_lists(session: requests.Session, token: str) -> List[dict]:
    r = session.get(f"{BASE_URL}/api/{token}/filter-list/list", timeout=TIMEOUT); r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else []

def get_filter_list_bundles(session: requests.Session, token: str, fl_id: int, per_page=500) -> List[str]:
    url = f"{BASE_URL}/api/{token}/filter-list/get-bundle"
    page, out = 1, []
    while True:
        r = session.get(url, params={"filter_list_id": str(fl_id), "limit": str(per_page), "page": str(page)}, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json() or {}
        data = j.get("data") or []
        out.extend(map(str, data))
        if page >= int(j.get("totalPages") or 1) or not data: break
        page += 1
    return out

def _post_form(session: requests.Session, url: str, form: List[Tuple[str, str]]) -> dict:
    r = session.post(url, data=form, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json() if "application/json" in (r.headers.get("Content-Type","")) else {}

def add_bundles(session: requests.Session, token: str, fl_id: int, bundles: List[str]) -> int:
    if not bundles: return 0
    url, total = f"{BASE_URL}/api/{token}/filter-list/add-bundle", 0
    for i in range(0, len(bundles), WRITE_BATCH):
        chunk = bundles[i:i+WRITE_BATCH]
        form = [("filter_list_id", str(fl_id))] + [("bundle[]", b) for b in chunk]
        j = _post_form(session, url, form); total += int(j.get("added_rows") or 0)
        print(f"[add] fl={fl_id} +{len(chunk)} requested")
    return total

def delete_bundles(session: requests.Session, token: str, fl_id: int, bundles: List[str]) -> int:
    if not bundles: return 0
    url, total = f"{BASE_URL}/api/{token}/filter-list/delete-bundle", 0
    for i in range(0, len(bundles), WRITE_BATCH):
        chunk = bundles[i:i+WRITE_BATCH]
        form = [("filter_list_id", str(fl_id))] + [("bundle[]", b) for b in chunk]
        j = _post_form(session, url, form); total += int(j.get("deleted_rows") or 0)
        print(f"[del] fl={fl_id} -{len(chunk)} requested")
    return total

# ---------- Hour helpers ----------
def last_full_hour_labels() -> Tuple[str, str]:
    lf = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    return lf.strftime("%Y-%m-%d %H:00"), lf.strftime("%Y-%m-%dT%H-00Z")

def row_hour_label(row: dict) -> Optional[str]:
    s = str(row.get("date") or row.get("day") or row.get("hour") or row.get("datetime") or "").strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:00")
        except ValueError:
            pass
    return None

# ---------- Build targets ----------
def build_lists_with_metrics(rows: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, float]], set, set]:
    def fnum(v): 
        try: return float(str(v).replace(",","").strip())
        except: return 0.0
    agg: Dict[str, Dict[str, float]] = {}
    for r in rows:
        dom_raw = str(r.get("domain") or r.get("bundle") or "").strip()
        if not dom_raw: continue
        c = canonical_bundle(dom_raw)
        a = agg.setdefault(c, {"impressions":0.0, "revenue":0.0, "_wsum":0.0, "_wden":0.0})
        imps = fnum(r.get("impressions"))
        a["impressions"] += imps
        a["revenue"]     += fnum(r.get("dsp_spend"))
        a["_wsum"]       += fnum(r.get("dsp_srcpm")) * imps
        a["_wden"]       += imps

    rows_fin = []
    for c,a in agg.items():
        srcpm = (a["_wsum"]/a["_wden"]) if a["_wden"]>0 else 0.0
        rows_fin.append({"canon": c, "impressions": a["impressions"], "revenue": a["revenue"], "dsp_srcpm": srcpm})

    rows_fin.sort(key=lambda x: x["revenue"], reverse=True)
    top5  = {r["canon"] for r in rows_fin[:5]}
    rule2 = {r["canon"] for r in rows_fin if r["impressions"] > IMP_THRESHOLD and r["dsp_srcpm"] > SRCPM_THRESHOLD}
    listA = top5 | rule2                 # RCPM
    listB = {r["canon"] for r in rows_fin if r["canon"] not in listA}  # RON
    metrics_by_canon = {r["canon"]: {"impressions": r["impressions"], "revenue": r["revenue"], "dsp_srcpm": r["dsp_srcpm"]} for r in rows_fin}
    return metrics_by_canon, listA, listB

# ---------- Pairing ----------
def compute_pairs(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        dsp = r.get("dsp_name") or r.get("dsp") or "unknown"
        by_name.setdefault(dsp, []).append(r)
    by_base: Dict[str, Dict[str, List[str]]] = {}
    for dsp in by_name:
        base, variant = extract_base_and_variant(dsp)
        if base not in by_base: by_base[base] = {"RON": [], "RCPM": []}
        if variant in ("RON","RCPM"): by_base[base][variant].append(dsp)
    return {b:v for b,v in by_base.items() if v["RON"] and v["RCPM"]}

# ---------- Exports ----------
def export_filter_list_csv(name: str, values: List[str], stamp: str):
    rows = [{"bundle": v} for v in values]
    write_csv(EXPORT_DIR / f"export_{stamp}__{sanitize_filename(name)}.csv", ["bundle"], rows)

# ---------- Per-base processor ----------
def process_base(base: str, rows_hour: List[Dict[str, Any]], fl_by_clean_name: Dict[str, dict],
                 session: requests.Session, token: str, hour_label_for_name: str):
    print(f"\n=== Processing base: {base} ===")

    # find pair names present in the hour
    all_pairs = compute_pairs(rows_hour)
    pair = all_pairs.get(base)
    if not pair:
        print(f"[skip] No RON/RCPM pair for base '{base}' in the last hour."); return

    rcpm_names, ron_names = list(pair["RCPM"]), list(pair["RON"])
    if not rcpm_names or not ron_names:
        print("[skip] Pair incomplete."); return
    rcpm_name, ron_name = strip_trailing_id(rcpm_names[0]), strip_trailing_id(ron_names[0])

    rcpm_fl = fl_by_clean_name.get(rcpm_name); ron_fl = fl_by_clean_name.get(ron_name)
    if not rcpm_fl or not ron_fl:
        print(f"[skip] Missing lists. RCPM? {bool(rcpm_fl)} | RON? {bool(ron_fl)}"); return

    rcpm_id, ron_id = int(rcpm_fl["filter_list_id"]), int(ron_fl["filter_list_id"])

    current_rcpm_vals = get_filter_list_bundles(session, token, rcpm_id)
    current_ron_vals  = get_filter_list_bundles(session, token, ron_id)

    # backup/export
    export_filter_list_csv(rcpm_name, current_rcpm_vals, hour_label_for_name)
    export_filter_list_csv(ron_name,  current_ron_vals,  hour_label_for_name)

    # style
    rcpm_style, ron_style = prefer_style(current_rcpm_vals), prefer_style(current_ron_vals)

    # canonical maps
    def canon_map(values: List[str]) -> Tuple[set, Dict[str, List[str]]]:
        m: Dict[str, List[str]] = {}; s: set = set()
        for v in values:
            c = canonical_bundle(v); s.add(c); m.setdefault(c, []).append(v)
        return s, m
    curR_set, curR_map = canon_map(current_rcpm_vals)
    curN_set, curN_map = canon_map(current_ron_vals)
    union_before = curR_set | curN_set

    # rows for THIS pair only
    dsp_names = set(rcpm_names + ron_names)
    pair_rows = [r for r in rows_hour if (r.get("dsp_name") or r.get("dsp")) in dsp_names]

    metrics_by_canon, targetR_set, targetN_set = build_lists_with_metrics(pair_rows)
    targetN_set = targetN_set - targetR_set  # disjoint

    # --- union-preserving desired membership (legacy non-target stay put) ---
    desiredR_set = (targetR_set & union_before) | (curR_set - (targetN_set & union_before))
    desiredN_set = (targetN_set & union_before) | (curN_set - (targetR_set & union_before))
    assert (desiredR_set | desiredN_set) == union_before, "Desired union must equal old union"

    # diff
    to_add_R = sorted(desiredR_set - curR_set)
    to_del_R = sorted(curR_set - desiredR_set)
    to_add_N = sorted(desiredN_set - curN_set)
    to_del_N = sorted(curN_set - desiredN_set)

    add_payload_R = [format_with_style(c, rcpm_style) for c in to_add_R]
    add_payload_N = [format_with_style(c, ron_style)  for c in to_add_N]

    del_from_R: List[str] = []
    for c in to_del_R: del_from_R.extend(curR_map.get(c, []))
    del_from_N: List[str] = []
    for c in to_del_N: del_from_N.extend(curN_map.get(c, []))

    print(f"[plan] base='{base}' add R:{len(add_payload_R)} N:{len(add_payload_N)} | del R:{len(del_from_R)} N:{len(del_from_N)} | union={len(union_before)}")

    if LIVE_UPDATES:
        # add first, delete second
        add_bundles(session, token, rcpm_id, add_payload_R)
        add_bundles(session, token, ron_id,  add_payload_N)
        delete_bundles(session, token, rcpm_id, del_from_R)
        delete_bundles(session, token, ron_id,  del_from_N)

        # verify + final snapshots
        new_rcpm_vals = get_filter_list_bundles(session, token, rcpm_id)
        new_ron_vals  = get_filter_list_bundles(session, token, ron_id)
        new_union = {canonical_bundle(v) for v in new_rcpm_vals} | {canonical_bundle(v) for v in new_ron_vals}
        if new_union != union_before:
            print(f"[WARN] Union changed! before={len(union_before)} after={len(new_union)}")
        else:
            print(f"[check] Union preserved exactly: {len(new_union)}")
        write_csv(EXPORT_DIR / f"final_{hour_label_for_name}__{sanitize_filename(rcpm_name)}.csv",
                  ["bundle"], [{"bundle": v} for v in new_rcpm_vals])
        write_csv(EXPORT_DIR / f"final_{hour_label_for_name}__{sanitize_filename(ron_name)}.csv",
                  ["bundle"], [{"bundle": v} for v in new_ron_vals])

    # CSVs of final planned composition (desired sets)
    def build_rows_full(canon_set: set, style: str) -> List[Dict[str, Any]]:
        def metric(c): return metrics_by_canon.get(c, {"revenue":0.0, "impressions":0.0, "dsp_srcpm":0.0})
        ordered = sorted(canon_set, key=lambda c: metric(c)["revenue"], reverse=True)
        return [{"bundle": format_with_style(c, style),
                 "impressions": int(metric(c)["impressions"]),
                 "revenue": round(metric(c)["revenue"],2),
                 "dsp_srcpm": round(metric(c)["dsp_srcpm"],4)} for c in ordered]

    rcpm_csv = build_rows_full(desiredR_set, rcpm_style)
    ron_csv  = build_rows_full(desiredN_set, ron_style)

    write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(rcpm_name)}.csv",
              ["bundle","impressions","revenue","dsp_srcpm"], rcpm_csv)
    write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(ron_name)}.csv",
              ["bundle","impressions","revenue","dsp_srcpm"], ron_csv)

# ---------- Main ----------
if __name__ == "__main__":
    d_str = date.today().isoformat()
    hour_label, hour_label_for_name = last_full_hour_labels()
    print(f"[window] last full hour (UTC): {hour_label}")

    session = make_session()
    token = create_token(session, EMAIL, PASSWORD, minutes=120)["token"]

    attributes = ["dsp_name", "domain"]
    metrics    = ["bid_requests", "impressions", "dsp_srcpm", "dsp_spend"]
    rows_today = adx_report(session, token, d_from=d_str, d_to=d_str, attributes=attributes, metrics=metrics)

    rows_hour = [r for r in rows_today if row_hour_label(r) == hour_label]
    print(f"[filter] rows in {hour_label}: {len(rows_hour)}")

    # catalog once
    fl_lists = list_filter_lists(session, token)
    fl_by_clean_name = {strip_trailing_id(obj.get("name") or ""): obj for obj in fl_lists}

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTDIR.mkdir(parents=True, exist_ok=True)

    # process each requested base
    bases_lower = {b.lower() for b in BASES}
    # We’ll iterate requested bases; if some don’t appear in the hour, we’ll log and continue.
    for base in BASES:
        process_base(base, rows_hour, fl_by_clean_name, session, token, hour_label_for_name)

    print("[done] multipair run complete.")
