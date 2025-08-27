# teqblaze_hourly_github.py
# GitHub Actions-ready version of your hourly updater.
# Logic matches your working multi-base script; it just reads credentials from
# env vars (TEQBLAZE_* preferred, PLAYDIGO_* accepted) or login.json.

import json, re, csv, os
from datetime import date, timedelta, datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------- Config ----------------
BASE = "https://ssp.playdigo.com"
TIMEOUT = (10, 60)
PAGE_LIMIT = 50_000           # matches your 50k cap
TIME_ZONE = "UTC"
DAY_GROUP = "hour"
OUTDIR = Path("report output/updated_lists")
EXPORT_DIR = Path("report output/exports")
LIVE_UPDATES = True           # True = write to API; False = dry-run plan only

# Bases to process (case-insensitive). Supports a list OR a comma/newline-separated string.
# Leave empty ([]) or "" to process ALL detected RON/RCPM pairs.
BASE_FILTERS = [
    "Media.net_IA_8CU43768M_Banner_Prebid_USeast",
    "Media.net_IA_8CU43768M_Video_Prebid_USeast",
    "Loop-Me_IA_12861_Video_oRTB_USeast",
    "FreeWheel_IA_1603410_Video(Android)_oRTB_USeast",
    "Sovrn_IA_489963_Banner(4SC)_oRTB_USeast",
]

# Selection thresholds for List A (RCPM)
IMP_THRESHOLD = 20
SRCPM_THRESHOLD = 0.7

# API write batching
WRITE_BATCH = 1000

# ---------------- Helpers ----------------
def load_creds(path="login.json") -> tuple[str, str]:
    """Prefer GitHub Actions env secrets; fall back to local login.json.
    Set repo secrets: TEQBLAZE_EMAIL, TEQBLAZE_PASSWORD (PLAYDIGO_* also accepted)
    """
    env_email = os.getenv("TEQBLAZE_EMAIL") or os.getenv("PLAYDIGO_EMAIL")
    env_password = os.getenv("TEQBLAZE_PASSWORD") or os.getenv("PLAYDIGO_PASSWORD")
    if env_email and env_password:
        return env_email, env_password
    with open(path, "r", encoding="utf-8") as f:
        j = json.load(f)
    return j["email"], j["password"]


def make_session(retries=5, backoff=0.5) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries, connect=retries, read=retries, status=retries,
        backoff_factor=backoff, status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"]), raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def to_float(v) -> float:
    try:
        return float(str(v).replace(",", "").strip())
    except Exception:
        return 0.0


def sanitize_filename(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r'[^A-Za-z0-9._ -]+', "_", s)
    return s[:180] or "unknown"


def write_csv(path: Path, headers: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[csv] wrote {len(rows)} -> {path}")


# ---------------- Name parsing ----------------

def strip_trailing_id(s: str) -> str:
    return re.sub(r'[\s\-_()#]*\d+\s*$', '', s or '', flags=re.IGNORECASE).strip()


def _normalize_base(s: str) -> str:
    # Lowercased, trimmed, trailing id stripped
    return strip_trailing_id((s or "")).strip().lower()


def parse_base_filters(x) -> set[str]:
    """Accept list/tuple/set OR comma/newline-separated string; return normalized set.
    Empty -> empty set (meaning: no filtering).
    """
    if not x:
        return set()
    parts = []
    if isinstance(x, (list, tuple, set)):
        for item in x:
            parts.extend(re.split(r"[,;\n]+", str(item)))
    else:
        parts = re.split(r"[,;\n]+", str(x))
    return { _normalize_base(p) for p in parts if p and p.strip() and p.strip() != '*' }


def extract_base_and_variant(name: str) -> Tuple[str, Optional[str]]:
    s = strip_trailing_id((name or '').strip())
    matches = list(re.finditer(r'(?<![A-Za-z0-9])(RON|RCPM)(?![A-Za-z0-9])', s, flags=re.IGNORECASE))
    if not matches:
        return (s.strip(' -_()'), None)
    last = matches[-1]
    base = s[:last.start()]
    base = re.sub(r'[\s\-_()*]+$', '', base).strip(' -_()')
    return base, last.group(1).upper()


# ---------------- API: read ----------------
def create_token(session: requests.Session, email: str, password: str, minutes=120) -> dict:
    url = f"{BASE}/api/create_token"
    r = session.post(url, data={"email": email, "password": password, "time": str(minutes)}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if (end_ts := data.get("end")):
        print(f"[auth] token ends (UTC): {datetime.utcfromtimestamp(float(end_ts)).isoformat()}Z")
    return data


def adx_report(session: requests.Session, token: str, d_from: str, d_to: str,
               attributes: List[str], metrics: List[str]) -> List[Dict[str, Any]]:
    base_url = f"{BASE}/api/{token}/adx-report"
    page, all_rows = 1, []
    while True:
        params = [("from", d_from), ("to", d_to),
                  ("time_zone", TIME_ZONE), ("day_group", DAY_GROUP),
                  ("limit", str(PAGE_LIMIT)), ("page", str(page))]
        for a in attributes:
            params.append(("attribute[]", a))
        for m in metrics:
            params.append(("metric[]", m))
        r = session.get(base_url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        rows = data if isinstance(data, list) else (data.get("data") or data.get("rows") or data.get("items") or [])
        print(f"[report] page={page} rows={len(rows)}")
        all_rows.extend(rows)
        if len(rows) < PAGE_LIMIT or not rows:
            break
        page += 1
    print(f"[report] total rows: {len(all_rows)}")
    return all_rows


def list_filter_lists(session: requests.Session, token: str) -> List[dict]:
    url = f"{BASE}/api/{token}/filter-list/list"
    r = session.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else []


def get_filter_list_bundles(session: requests.Session, token: str, fl_id: int, per_page=500) -> List[str]:
    url = f"{BASE}/api/{token}/filter-list/get-bundle"
    page, out = 1, []
    while True:
        r = session.get(url, params={"filter_list_id": str(fl_id), "limit": str(per_page), "page": str(page)}, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json() or {}
        data = j.get("data") or []
        out.extend(map(str, data))
        total_pages = int(j.get("totalPages") or 1)
        if page >= total_pages or not data:
            break
        page += 1
    return out


# ---------------- API: write ----------------
def _post_form(session: requests.Session, url: str, form: List[Tuple[str, str]]) -> dict:
    r = session.post(url, data=form, timeout=TIMEOUT)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        print(f"[write] {url} -> HTTP {r.status_code}: {r.text[:400]}")
        raise
    return r.json() if "application/json" in (r.headers.get("Content-Type","")) else {}


def add_bundles(session: requests.Session, token: str, fl_id: int, bundles: List[str]) -> int:
    if not bundles:
        return 0
    url = f"{BASE}/api/{token}/filter-list/add-bundle"
    total = 0
    for i in range(0, len(bundles), WRITE_BATCH):
        chunk = bundles[i:i+WRITE_BATCH]
        form = [("filter_list_id", str(fl_id))] + [("bundle[]", b) for b in chunk]
        j = _post_form(session, url, form)
        total += int(j.get("added_rows") or 0)
        print(f"[add] fl={fl_id} +{len(chunk)} requested")
    return total


def delete_bundles(session: requests.Session, token: str, fl_id: int, bundles: List[str]) -> int:
    if not bundles:
        return 0
    url = f"{BASE}/api/{token}/filter-list/delete-bundle"
    total = 0
    for i in range(0, len(bundles), WRITE_BATCH):
        chunk = bundles[i:i+WRITE_BATCH]
        form = [("filter_list_id", str(fl_id))] + [("bundle[]", b) for b in chunk]
        j = _post_form(session, url, form)
        total += int(j.get("deleted_rows") or 0)
        print(f"[del] fl={fl_id} -{len(chunk)} requested")
    return total


# ---------------- Bundle normalization ----------------
_bundle_num_re = re.compile(r'^\d+$')
_bundle_id_re  = re.compile(r'^[Ii][Dd]\d+$')

def canonical_bundle(x: Any) -> str:
    s = str(x or "").strip()
    if _bundle_id_re.fullmatch(s):
        return s[2:]  # strip 'id' prefix
    return s

def prefer_style_for_additions(current_values: List[str]) -> str:
    for v in current_values:
        if _bundle_id_re.fullmatch(v.strip()):
            return "id"
    return "num"

def format_with_preference(canon: str, style: str) -> str:
    if _bundle_num_re.fullmatch(canon):
        return f"id{canon}" if style == "id" else canon
    return canon


# ---------------- Pairing & list building ----------------
def compute_pairs(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        dsp = r.get("dsp_name") or r.get("dsp") or "unknown"
        by_name.setdefault(dsp, []).append(r)

    by_base: Dict[str, Dict[str, List[str]]] = {}
    for dsp in by_name.keys():
        base, variant = extract_base_and_variant(dsp)
        if base not in by_base:
            by_base[base] = {"RON": [], "RCPM": []}
        if variant in ("RON", "RCPM"):
            by_base[base][variant].append(dsp)

    return {b:v for b,v in by_base.items() if v["RON"] and v["RCPM"]}


def build_lists_with_metrics(rows: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, float]], set, set]:
    """
    metrics_by_canon,
    listA (RCPM) = Top-5 by revenue (dsp_spend) ∪ {impressions > 20 & dsp_srcpm > 0.7}
    listB (RON)  = remaining
    """
    agg: Dict[str, Dict[str, float]] = {}
    for r in rows:
        dom_raw = str(r.get("domain") or r.get("bundle") or "").strip()
        if not dom_raw:
            continue
        canon = canonical_bundle(dom_raw)
        a = agg.setdefault(canon, {"impressions":0.0, "revenue":0.0, "_wsum":0.0, "_wden":0.0})
        imps = to_float(r.get("impressions"))
        a["impressions"]  += imps
        a["revenue"]      += to_float(r.get("dsp_spend"))
        a["_wsum"]        += to_float(r.get("dsp_srcpm")) * imps
        a["_wden"]        += imps

    rows_fin = []
    for canon, a in agg.items():
        srcpm = (a["_wsum"]/a["_wden"]) if a["_wden"]>0 else 0.0
        rows_fin.append({"canon": canon, "impressions": a["impressions"], "revenue": a["revenue"], "dsp_srcpm": srcpm})

    rows_fin.sort(key=lambda x: x["revenue"], reverse=True)
    top5 = {r["canon"] for r in rows_fin[:5]}
    rule2 = {r["canon"] for r in rows_fin if r["impressions"] > IMP_THRESHOLD and r["dsp_srcpm"] > SRCPM_THRESHOLD}
    listA = top5 | rule2
    listB = {r["canon"] for r in rows_fin if r["canon"] not in listA}

    metrics_by_canon = {r["canon"]: {"impressions": r["impressions"], "revenue": r["revenue"], "dsp_srcpm": r["dsp_srcpm"]} for r in rows_fin}
    return metrics_by_canon, listA, listB


# ---------------- Hour helpers ----------------
def last_full_hour_labels() -> Tuple[str, str]:
    lf = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    return lf.strftime("%Y-%m-%d %H:00"), lf.strftime("%Y-%m-%dT%H-00Z")


def row_hour_label(row: dict) -> Optional[str]:
    s = str(row.get("date") or row.get("day") or row.get("hour") or row.get("datetime") or "").strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%d %H:00")
        except ValueError:
            pass
    return None


# ---------------- Export helpers ----------------
def export_filter_list_csv(name: str, values: List[str], stamp: str):
    rows = [{"bundle": v} for v in values]
    fname = sanitize_filename(name)
    path = EXPORT_DIR / f"export_{stamp}__{fname}.csv"
    write_csv(path, ["bundle"], rows)


# ---------------- Main ----------------
if __name__ == "__main__":
    # Today (UTC)
    d_str = date.today().isoformat()

    # Auth
    email, password = load_creds()
    session = make_session()
    token = create_token(session, email, password, minutes=120)["token"]

    # Pull rows for today, grouped by hour
    attributes = ["dsp_name", "domain"]
    metrics    = ["bid_requests", "impressions", "dsp_srcpm", "dsp_spend"]
    rows_all = adx_report(session, token, d_from=d_str, d_to=d_str, attributes=attributes, metrics=metrics)

    # Keep only the last full hour (n-1)
    hour_label, hour_label_for_name = last_full_hour_labels()
    rows = [r for r in rows_all if row_hour_label(r) == hour_label]
    print(f"[filter] last full hour {hour_label}: {len(rows)} rows")

    # Build pairs and filter to requested bases (if any)
    all_pairs = compute_pairs(rows)
    allowed_bases = parse_base_filters(BASE_FILTERS)
    if allowed_bases:
        pairs = {b:v for b,v in all_pairs.items() if _normalize_base(b) in allowed_bases}
        print(f"[pairs] filtered to {len(pairs)} pair(s) from {len(allowed_bases)} requested base(s)")
    else:
        pairs = all_pairs
        print(f"[pairs] no base filter provided — using all detected pairs: {len(pairs)}")
    if not pairs:
        print("[exit] No matching RON/RCPM pairs found for the requested bases.")
        raise SystemExit(0)

    # Fetch filter list catalog
    fl_lists = list_filter_lists(session, token)
    fl_by_clean_name: Dict[str, dict] = {}
    for obj in fl_lists:
        nm = strip_trailing_id(obj.get("name") or "")
        fl_by_clean_name[nm] = obj

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTDIR.mkdir(parents=True, exist_ok=True)

    for base, varmap in pairs.items():
        rcpm_names = list(varmap["RCPM"])
        ron_names  = list(varmap["RON"])
        if not rcpm_names or not ron_names:
            print("[exit] Pair incomplete (missing RCPM or RON).")
            continue

        rcpm_name = strip_trailing_id(rcpm_names[0])
        ron_name  = strip_trailing_id(ron_names[0])

        rcpm_fl = fl_by_clean_name.get(rcpm_name)
        ron_fl  = fl_by_clean_name.get(ron_name)
        if not rcpm_fl or not ron_fl:
            print(f"[warn] Missing lists. RCPM exists? {bool(rcpm_fl)} | RON exists? {bool(ron_fl)}")
            print("[exit] Need both lists to perform union-preserving moves.")
            continue

        rcpm_id = int(rcpm_fl["filter_list_id"])
        ron_id  = int(ron_fl["filter_list_id"])

        current_rcpm_vals = get_filter_list_bundles(session, token, rcpm_id)
        current_ron_vals  = get_filter_list_bundles(session, token, ron_id)

        # Export backups
        export_filter_list_csv(rcpm_name, current_rcpm_vals, hour_label_for_name)
        export_filter_list_csv(ron_name,  current_ron_vals,  hour_label_for_name)

        # Style preferences
        rcpm_style = prefer_style_for_additions(current_rcpm_vals)
        ron_style  = prefer_style_for_additions(current_ron_vals)

        # Canonical maps (for deletes, use exact stored strings)
        def canon_map(values: List[str]) -> Tuple[set, Dict[str, List[str]]]:
            m: Dict[str, List[str]] = {}
            s: set = set()
            for v in values:
                c = canonical_bundle(v)
                s.add(c)
                m.setdefault(c, []).append(v)
            return s, m
        curR_set, curR_map = canon_map(current_rcpm_vals)
        curN_set, curN_map = canon_map(current_ron_vals)
        union_before = curR_set | curN_set

        # Build targets from the current hour data (for this pair only)
        dsp_names = set(rcpm_names + ron_names)
        pair_rows = [r for r in rows if (r.get("dsp_name") or r.get("dsp")) in dsp_names]
        metrics_by_canon, targetR_set, targetN_set = build_lists_with_metrics(pair_rows)
        targetN_set = targetN_set - targetR_set  # disjoint

        # ---- UNION-PRESERVING MOVE LOGIC (exact equality to old union) ----
        # Desired membership LIMITED to old union (legacy non-target items stay where they are)
        desiredR_set = (targetR_set & union_before) | (curR_set - (targetN_set & union_before))
        desiredN_set = (targetN_set & union_before) | (curN_set - (targetR_set & union_before))
        assert (desiredR_set | desiredN_set) == union_before, "Desired union must equal old union"

        # Plan adds/deletes
        to_add_R_canon = sorted(desiredR_set - curR_set)
        to_del_R_canon = sorted(curR_set - desiredR_set)
        to_add_N_canon = sorted(desiredN_set - curN_set)
        to_del_N_canon = sorted(curN_set - desiredN_set)

        # Convert to payloads (adds: style; deletes: exact stored strings)
        add_payload_R = [format_with_preference(c, rcpm_style) for c in to_add_R_canon]
        add_payload_N = [format_with_preference(c, ron_style)  for c in to_add_N_canon]

        del_from_R = []
        for c in to_del_R_canon:
            del_from_R.extend(curR_map.get(c, []))  # exact values

        del_from_N = []
        for c in to_del_N_canon:
            del_from_N.extend(curN_map.get(c, []))

        # Execute (destination-first so nothing is ever in zero lists)
        if LIVE_UPDATES:
            added_R = add_bundles(session, token, rcpm_id, add_payload_R)
            added_N = add_bundles(session, token, ron_id,  add_payload_N)

            deleted_R = delete_bundles(session, token, rcpm_id, del_from_R)
            deleted_N = delete_bundles(session, token, ron_id,  del_from_N)

            print(f"[live] adds R:{added_R} N:{added_N} | dels R:{deleted_R} N:{deleted_N}")

            # Verify union unchanged
            new_rcpm_vals = get_filter_list_bundles(session, token, rcpm_id)
            new_ron_vals  = get_filter_list_bundles(session, token, ron_id)
            new_union = {canonical_bundle(v) for v in new_rcpm_vals} | {canonical_bundle(v) for v in new_ron_vals}
            if new_union != union_before:
                print(f"[WARN] Union changed! before={len(union_before)} after={len(new_union)} "
                      f"delta_add={len(new_union - union_before)} delta_del={len(union_before - new_union)}")
            else:
                print(f"[check] Union preserved exactly: {len(new_union)} bundles")

            # Save the *actual* final lists as CSVs
            write_csv(EXPORT_DIR / f"final_{hour_label_for_name}__{sanitize_filename(rcpm_name)}.csv",
                      ["bundle"], [{"bundle": v} for v in new_rcpm_vals])
            write_csv(EXPORT_DIR / f"final_{hour_label_for_name}__{sanitize_filename(ron_name)}.csv",
                      ["bundle"], [{"bundle": v} for v in new_ron_vals])

            print(f"[final] RCPM={len(new_rcpm_vals)} | RON={len(new_ron_vals)} | union={len(new_union)}")
        else:
            print(f"[dry-run] Plan → add R:{len(add_payload_R)} N:{len(add_payload_N)} | "
                  f"del R:{len(del_from_R)} N:{len(del_from_N)} (union preserved: {len(union_before)} bundles)")

        # ---- CSV (audit of FINAL PLANNED composition, includes legacy items) ----
        def build_csv_rows_full(canon_set: set, style: str) -> List[Dict[str, Any]]:
            # include items even if they have no current-hour metrics
            def metric(c):
                return metrics_by_canon.get(c, {"revenue":0.0, "impressions":0.0, "dsp_srcpm":0.0})
            ordered = sorted(canon_set, key=lambda c: metric(c)["revenue"], reverse=True)
            out = []
            for c in ordered:
                m = metric(c)
                out.append({
                    "bundle":     format_with_preference(c, style),
                    "impressions": int(round(m.get("impressions", 0.0))),
                    "revenue":     round(m.get("revenue", 0.0), 2),
                    "dsp_srcpm":   round(m.get("dsp_srcpm", 0.0), 4),
                })
            return out

        rcpm_csv = build_csv_rows_full(desiredR_set, rcpm_style)
        ron_csv  = build_csv_rows_full(desiredN_set, ron_style)

        write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(rcpm_name)}.csv",
                  ["bundle","impressions","revenue","dsp_srcpm"], rcpm_csv)
        write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(ron_name)}.csv",
                  ["bundle","impressions","revenue","dsp_srcpm"], ron_csv)

        print(f"[done] base='{base}' — union preserved (final == old) and CSVs reflect final planned composition")
