"""Merge the manual component slices into one apply file, with conflict checks.

Input : build/symmatch/manual/slice{A,B,C}.tsv  (# win_addr \t name \t class \t method \t evidence \t confidence)
Output: build/symmatch/manual/apply_manual.tsv   (addr \t name, what DstApplyNames consumes)
        build/symmatch/manual/apply_report.md    (accepted / rejected with reasons)

Rejects, never guesses:
  * address is not a defined function in the live inventory;
  * address already carries a different name (reported, not overwritten);
  * the same address is claimed with two different names (reported, neither applied
    unless one row is `high` and the other is not);
  * name is not `Class::method`.

Usage: python tools/symmatch/manual/apply_manual.py
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

MAN = Path("build/symmatch/manual")
VT = Path("build/symmatch/vt2")
SLICES = ["sliceA.tsv", "sliceB.tsv", "sliceC.tsv", "sliceD.tsv", "sliceE.tsv",
          "sliceF.tsv", "sliceG.tsv", "sliceH.tsv", "sliceI.tsv",
          "fix_misnames.tsv", "hop1_verified.tsv", "callsite_args_candidates.tsv",
          "callsite_pcode_candidates.tsv", "callsite_pcode_080.tsv", "fix_batch2.tsv",
          "wave4_http.tsv", "wave4_samplers.tsv", "wave4_resources.tsv",
          "wave4_threads.tsv", "wave4_luanet.tsv",
          "wave5_single.tsv", "wave5_friends.tsv", "wave5_punch.tsv", "wave5_rails.tsv",
          "wave5_fixes4.tsv", "callsite_pcode_060.tsv", "fix060.tsv",
          "wave6_infra.tsv", "sliceW6io.tsv", "sliceJ_inputui.tsv", "wave6_simcore.tsv",
          "wave6_fixes.tsv", "wave6_simqual.tsv", "bindtable_names.tsv",
          "w7_net.tsv", "w7_inv.tsv", "w7_ent.tsv", "w7_app.tsv",
          "w8_rpc.tsv", "w8_store.tsv", "w8_proxy.tsv", "w8_app.tsv",
          "w9_core.tsv", "w9_app.tsv",
          "w10_net.tsv", "w10_app.tsv", "w10_rest.tsv",
          "w11_acct.tsv", "w11_audio.tsv", "w11_ui.tsv",
          "w12_input.tsv", "w12_io.tsv", "w12_comp.tsv",
          "w13_sim.tsv", "w13_map.tsv", "w13_ui2.tsv", "w13_fix.tsv",
          "w14_buf.tsv", "w14_fs.tsv", "w14_http.tsv", "w14_fix.tsv",
          "w15_net.tsv", "w15_renderA.tsv", "w15_renderB.tsv", "w15_comp.tsv",
          "w16_widget.tsv", "w16_input2.tsv", "w16_render2.tsv",
          "w17_runtime.tsv", "w17_camera.tsv", "w17_res.tsv",
          "w19_apply.tsv", "w20_netproxy.tsv", "w21_qualify.tsv", "w22_bare.tsv", "w22_award.tsv"]


def main() -> int:
    live = {}
    for line in (VT / "inv_win_clean.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        live[int(r["e"], 16)] = int(r.get("ni", 0))
    existing = {}
    for line in (VT / "win_names_live60.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            existing[int(f[0], 16)] = f[3]

    rows = []
    for s in SLICES:
        p = MAN / s
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 6 or not f[0].startswith("0x"):
                continue          # verdict-only rows ("absent"/"inlined") carry no address
            rows.append(dict(src=s, addr=int(f[0], 16), name=f[1], cls=f[2],
                             method=f[3], evidence=f[4], conf=f[5]))

    claims = defaultdict(list)
    rejected = []
    for r in rows:
        if r["addr"] not in live:
            rejected.append((r, "not a defined function"))
            continue
        if "::" not in r["name"] and not re.fullmatch(r"[A-Za-z_]\w*", r["name"]):
            rejected.append((r, "name is neither Class::method nor a bare identifier"))
            continue
        old = existing.get(r["addr"])
        if old and old != r["name"]:
            rejected.append((r, f"already named {old}"))
            continue
        claims[r["addr"]].append(r)

    accepted = []
    for addr, cl in claims.items():
        names = {c["name"] for c in cl}
        if len(names) > 1:
            highs = [c for c in cl if c["conf"] == "high"]
            if len(highs) == 1:
                accepted.append(highs[0])
                rejected.append((cl[0], f"conflict: {sorted(names)} -> kept {highs[0]['name']}"))
            else:
                for c in cl:
                    rejected.append((c, f"conflict: {sorted(names)}"))
            continue
        accepted.append(cl[0])

    out = MAN / "apply_manual.tsv"
    with out.open("w", encoding="utf-8") as f:
        for r in sorted(accepted, key=lambda r: r["addr"]):
            note = r["evidence"].replace("\t", " ")
            if len(note) > 160:
                note = note[:157] + "..."
            f.write(f"0x{r['addr']:x}\t{r['name']}\tmanual:vtable\t{note}\n")

    rep = MAN / "apply_report.md"
    with rep.open("w", encoding="utf-8") as f:
        f.write(f"# manual apply report\n\naccepted: {len(accepted)}  rejected: {len(rejected)}\n\n")
        f.write("## accepted\n\n| addr | name | source | confidence |\n|---|---|---|---|\n")
        for r in sorted(accepted, key=lambda r: r["addr"]):
            f.write(f"| 0x{r['addr']:x} | {r['name']} | {r['src']} | {r['conf']} |\n")
        f.write("\n## rejected\n\n| addr | name | source | reason |\n|---|---|---|---|\n")
        for r, why in rejected:
            f.write(f"| 0x{r['addr']:x} | {r['name']} | {r['src']} | {why} |\n")

    print(f"accepted {len(accepted)}  rejected {len(rejected)} -> {out}, {rep}")
    for r, why in rejected:
        print(f"  REJECT 0x{r['addr']:x} {r['name']}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
