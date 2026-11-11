"""Turn the unresolved backlog into verification candidates.

    python tools/symmatch/manual/backlog_probe.py build/symmatch/manual/BACKLOG_UNRESOLVED.tsv out.tsv

For every backlog row that has an Android address, the feature matcher produces a ranked list of
unnamed Windows functions in the adjacent size buckets.  Rows are kept only when

  * the Windows address is claimed by exactly one backlog target (a shared claim means a stub), and
  * the margin over the runner-up is at least 0.10.

The output is a *candidate* list, never a name list: every row still needs its own two facts
(`DumpFn.java` + a literal/assert-path check) before it may enter a slice.
"""
import collections
import json
import sys

sys.path.insert(0, "tools/symmatch/manual")
import feature_match as fm

VT = fm.VT


def main():
    src, out = sys.argv[1], sys.argv[2]
    a = fm.load_inv(VT + "inv_android_str2.jsonl")
    w = fm.load_inv(VT + "inv_win_repaired3.jsonl")
    named = set()
    for line in open(VT + "win_names_live56.tsv", encoding="utf-8"):
        if line.startswith("0x"):
            named.add(int(line.split("\t")[0], 16))
    wb = fm.buckets(w)
    widx = fm.literal_index(w)
    exclude = named | set(w) - {k for k in w}

    by_addr = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        by_addr[int(r["e"], 16)] = r.get("q") or ""

    claims = collections.defaultdict(list)
    for line in open(src, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 5 or not f[3].startswith("0x"):
            continue
        ai = int(f[3], 16)
        t = a.get(ai)
        if not t:
            continue
        cands = []
        for wi in fm.candidates(t, w, wb, widx, named):
            s = fm.score(t, w[wi])
            if s is not None:
                cands.append((s, wi))
        if len(cands) < 2:
            continue
        cands.sort()
        margin = cands[1][0] - cands[0][0]
        if margin < 0.10:
            continue
        claims[cands[0][0] if False else hex(cands[0][1])].append((f[0], f[1], f[2], hex(ai), cands[0][0], margin))

    rows = [(v[0] if len(v) == 1 else None) for v in [claims[k] for k in claims]]
    uniq = [r for r in rows if r]
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# win_addr\tslice\tclass\tmethod\tandroid_addr\tscore\tmargin\n")
        for v in sorted(uniq, key=lambda r: -r[5]):
            fh.write(f"{v[3] if False else v[3]}\t")  # placeholder replaced below
            fh.write("\n")
    # rewrite cleanly (the loop above kept the shape simple on purpose)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# win_addr\tslice\tclass\tmethod\tandroid_addr\tscore\tmargin\n")
        for (addr, vals) in sorted(claims.items()):
            if len(vals) != 1:
                continue
            sl, cls, meth, ai, sc, mg = vals[0]
            fh.write(f"{addr}\t{sl}\t{cls}\t{meth}\t{ai}\t{sc:.3f}\t{mg:.3f}\n")
    print(f"unique candidates: {len(uniq)} of {len(claims)} claimed addresses -> {out}")


if __name__ == "__main__":
    main()
