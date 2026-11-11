"""Name-level call-graph propagation across two builds.

usage: python tools/symmatch/manual/vergraph.py <old.jsonl> <old_names.tsv> <new.jsonl> <new_names.tsv> <out.tsv>

Once a few thousand names exist on the new build, the call graph itself is the best evidence:
an old function whose callees and callers already carry the same names in the new build is the
new function with exactly those neighbours.  Iterated to a fixed point, each accepted match adds
a name that can anchor further matches.
"""
import json
import sys
from collections import defaultdict


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = [int(c, 16) for c in (r.get("cal") or [])]
    return out


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def main():
    old_json, old_names_tsv, new_json, new_names_tsv, out_tsv = sys.argv[1:6]
    old_cal, new_cal = load_inv(old_json), load_inv(new_json)
    old_names, new_names = load_names(old_names_tsv), load_names(new_names_tsv)

    def callers_of(cal):
        inv = defaultdict(set)
        for a, cs in cal.items():
            for c in cs:
                inv[c].add(a)
        return inv

    old_caller, new_caller = callers_of(old_cal), callers_of(new_cal)
    rows = {}
    round_no = 0
    while True:
        round_no += 1
        new_by_name = defaultdict(list)
        for a, n in new_names.items():
            new_by_name[n].append(a)
        new_callee_names = {a: {new_names[c] for c in cs if c in new_names} for a, cs in new_cal.items()}
        new_caller_names = {a: {new_names[c] for c in new_caller.get(a, ()) if c in new_names} for a in new_cal}
        # index: name -> new functions calling something with that name / called by something with that name
        call_of_name = defaultdict(set)
        callee_of_name = defaultdict(set)
        for a, cs in new_cal.items():
            for c in cs:
                if c in new_names:
                    call_of_name[new_names[c]].add(a)
        for a, cs in new_caller.items():
            for c in cs:
                if c in new_names:
                    callee_of_name[new_names[c]].add(a)
        unmapped_new = [a for a in new_cal if a not in new_names]

        proposals = {}
        for oa, nm in old_names.items():
            if nm in new_by_name:
                continue
            wcal = {old_names[c] for c in old_cal.get(oa, ()) if c in old_names and c != oa}
            wcall = {old_names[c] for c in old_caller.get(oa, ()) if c in old_names and c != oa}
            if not wcal and not wcall:
                continue
            pool = set()
            for n in wcal:
                pool |= call_of_name.get(n, set())
            for n in wcall:
                pool |= callee_of_name.get(n, set())
            best = None
            for cand in pool:
                if cand in new_names:
                    continue
                score = 2 * len(wcal & new_callee_names.get(cand, set())) + len(wcall & new_caller_names.get(cand, set()))
                if score < 3:
                    continue
                if best is None or score > best[1]:
                    best = (cand, score)
                elif score == best[1]:
                    best = (best[0], -1)
            if best and best[1] > 0:
                proposals[oa] = (best[0], best[1], len(wcal))
        accepted = 0
        for oa, (na, score, n) in proposals.items():
            if na in new_names or old_names[oa] in new_by_name:
                continue
            new_names[na] = old_names[oa]
            rows[na] = (old_names[oa], score, n, oa)
            accepted += 1
        print(f"round {round_no}: accepted {accepted}")
        if not accepted:
            break
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tstage\tnote\n")
        for na, (nm, score, n, oa) in sorted(rows.items()):
            fh.write(f"0x{na:x}\t{nm}\tgraph:{score}/cal{n}\tfrom 0x{oa:x}\n")
    print(f"graph matches {len(rows)}")


if __name__ == "__main__":
    main()
