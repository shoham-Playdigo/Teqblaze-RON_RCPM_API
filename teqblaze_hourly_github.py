# teqblaze_hourly_github.py
curR_set, curR_map = canon_map(current_rcpm_vals)
curN_set, curN_map = canon_map(current_ron_vals)
union_before = curR_set | curN_set


# Build targets from the current hour data (for this pair only)
dsp_names = set(rcpm_names + ron_names)
pair_rows = [r for r in rows if (r.get("dsp_name") or r.get("dsp")) in dsp_names]
metrics_by_canon, targetR_set, targetN_set = build_lists_with_metrics(pair_rows)
targetN_set = targetN_set - targetR_set # disjoint


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
add_payload_N = [format_with_preference(c, ron_style) for c in to_add_N_canon]


del_from_R = []
for c in to_del_R_canon:
del_from_R.extend(curR_map.get(c, [])) # exact values
del_from_N = []
for c in to_del_N_canon:
del_from_N.extend(curN_map.get(c, []))


# Execute (destination-first so nothing is ever in zero lists)
if LIVE_UPDATES:
added_R = add_bundles(session, token, rcpm_id, add_payload_R)
added_N = add_bundles(session, token, ron_id, add_payload_N)


deleted_R = delete_bundles(session, token, rcpm_id, del_from_R)
deleted_N = delete_bundles(session, token, ron_id, del_from_N)


print(f"[live] adds R:{added_R} N:{added_N} | dels R:{deleted_R} N:{deleted_N}")


# Verify union unchanged
new_rcpm_vals = get_filter_list_bundles(session, token, rcpm_id)
new_ron_vals = get_filter_list_bundles(session, token, ron_id)
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
"bundle": format_with_preference(c, style),
"impressions": int(round(m.get("impressions", 0.0))),
"revenue": round(m.get("revenue", 0.0), 2),
"dsp_srcpm": round(m.get("dsp_srcpm", 0.0), 4),
})
return out


rcpm_csv = build_csv_rows_full(desiredR_set, rcpm_style)
ron_csv = build_csv_rows_full(desiredN_set, ron_style)


write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(rcpm_name)}.csv",
["bundle","impressions","revenue","dsp_srcpm"], rcpm_csv)
write_csv(OUTDIR / f"updated_{hour_label_for_name}__{sanitize_filename(ron_name)}.csv",
["bundle","impressions","revenue","dsp_srcpm"], ron_csv)


print(f"[done] base='{base}' — union preserved (final == old) and CSVs reflect final planned composition")
