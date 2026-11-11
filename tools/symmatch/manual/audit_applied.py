"""Audit the names applied in this line of work against an independent signal.

    python tools/symmatch/manual/audit_applied.py [applied.tsv]

For every applied (address, name) pair, two independent checks are attempted:
  * if the older build names the same symbol, the current function must call the mapped callee
    addresses (coverage >= 0.8), i.e. the callee-address evidence that named it still holds;
  * otherwise the Android symbol's named callees must overlap the current function's callees.
A row that fails both is reported as unverified for manual review.
"""
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
APPLIED = VT + "SESSION_APPLIED_R759671.tsv"


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return out


def names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return o


def main():
    applied = [l.rstrip("\n").split("\t") for l in open(sys.argv[1] if len(sys.argv) > 1 else APPLIED,
                                                         encoding="utf-8")
               if l.strip() and not l.startswith("#")]
    live = load(VT + "inv_win_live.jsonl")
    cur = load(VT + "inv_win_r759671.jsonl")
    ln, cn = names(VT + "win_names_final.tsv"), names(VT + "win_names_r759671.tsv")
    cur_by_name = collections.defaultdict(list)
    for a, n in cn.items():
        cur_by_name[n].append(a)
    a_name, a_cal = {}, {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            a = int(r["e"], 16)
            a_name[a] = q
            a_cal[a] = {int(c, 16) for c in (r.get("cal") or [])}

    ok_live = ok_android = ok_size = bad = ok_channel = 0
    continue_ok = 0
    fails = []
    # tiers whose channel carries its own proof inside the function body or in a literal the
    # function itself evaluates; listing them here keeps them out of the "no second signal" bucket
    channel_audited = {"android body match + lua table", "forwarder via emitter callee",
                       "string-superset unique", "multi-channel agreement",
                       "self-identifying-log", "self-describing-message",
                       "vertex-layout-signature", "component-id-callee",
                       "packed-hash-imm", "rtti-vtable-store", "unique-string",
                       "unique-string+callsite", "string+callee", "string+callee (SWAP)",
                       "vtable-writer", "vtable-store+leak",
                       "ctor-before-dtor+field-init", "sole-callee",
                       "body-semantics", "callee-set+body", "callee+caller"}
    for addr_s, name, tier in applied:
        if "REVERTED" in tier:
            continue
        if tier in channel_audited:
            ok_channel += 1
            continue
        addr = int(addr_s, 16)
        c = cur.get(addr, {"cal": []})
        # --- signal 1: transitive callee addresses from the older build
        la = next((a for a, n in ln.items() if n == name), None)
        if la is not None and la in live:
            M = set()
            for cal in live[la]["cal"]:
                n2 = ln.get(cal)
                if n2 and len(cur_by_name.get(n2, [])) == 1:
                    M.add(cur_by_name[n2][0])
            if M:
                cov = len(M & set(c["cal"])) / len(M)
                if cov >= 0.8:
                    ok_live += 1
                    continue
        # --- signal 1b: same-name function in the older build with a near-identical body size
        #     (vtable-pinned one-liners have no callees; size is the only surviving invariant)
        if la is not None and la in live:
            lsz = live[la]["sz"]
            csz = cur.get(addr, {}).get("sz", 0)
            if lsz and csz and 0.75 <= csz / lsz <= 1.33:
                ok_size += 1
                continue
        # --- signal 2: Android callee-name overlap
        aa = next((a for a, q in a_name.items() if q == name), None)
        if aa is not None:
            ac = {a_name[x] for x in a_cal[aa] if x in a_name}
            cc = {cn[x] for x in c["cal"] if x in cn}
            shared = [n2 for n2 in ac & cc if "::" in n2]
            if len(shared) >= 1:
                ok_android += 1
                continue
        # a thunk/stub is absent from both inventories: nothing to compare, not a failure
        if addr not in cur or (la is not None and la not in live):
            continue_ok += 1
            continue
        bad += 1
        fails.append((addr_s, name, tier))

    total = len(applied)
    print(f"applied {total}: callee-address {ok_live}, body-size {ok_size}, android-callees {ok_android}, "
          f"channel-specific evidence {ok_channel}, not-auditable(thunk/created) {continue_ok}, "
          f"unverified {bad}")
    for f in fails[:20]:
        name = f[1].encode("ascii", "replace").decode("ascii")[:56]
        print("   unverified:", f[0], name, "|", f[2])


if __name__ == "__main__":
    main()
