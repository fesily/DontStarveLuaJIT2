#!/usr/bin/env python3
"""Unit tests for tools/symmatch — no Ghidra required.

Run directly (``python tests/performance/test_symmatch.py``).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "symmatch"
if str(TOOL) not in sys.path:
    sys.path.insert(0, str(TOOL))

from common import Func, Match, Side  # noqa: E402
from manual.coverage import head_of, norm_sig, strip_template, win_names  # noqa: E402
from pipeline import stage_unique_strings  # noqa: E402
from run import _dedupe, is_placeholder  # noqa: E402


def _func(entry: int, name: str, ninstr: int = 20, strings=(), imms=(), callees=()) -> Func:
    return Func(entry=entry, name=name, size=ninstr * 3, ninstr=ninstr, nbb=3,
                nedges=4, cyclo=3, strings=frozenset(strings),
                imms=frozenset(imms), drefs=frozenset(), callees=tuple(callees))


class UniqueStringTest(unittest.TestCase):
    def test_conflicting_claims_keep_only_one_pair(self) -> None:
        # two android functions each own a unique string that the same windows
        # function references: only the better-supported claim may survive.
        a = Side("a", {1: _func(1, "A1", strings=("sa",)),
                       2: _func(2, "A2", strings=("sb", "sb2"))}, {})
        w = Side("w", {10: _func(10, "W10", strings=("sa", "sb", "sb2"))}, {})
        matches = stage_unique_strings(a, w, set(), set())
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].android, 2)
        self.assertEqual(matches[0].windows, 10)

    def test_ambiguous_side_is_ignored(self) -> None:
        a = Side("a", {1: _func(1, "A1", strings=("shared",))}, {})
        w = Side("w", {10: _func(10, "W10", strings=("shared",)),
                       11: _func(11, "W11", strings=("shared",))}, {})
        self.assertEqual(stage_unique_strings(a, w, set(), set()), [])


class DedupeTest(unittest.TestCase):
    def test_one_name_per_target_and_one_target_per_name(self) -> None:
        rows = [
            Match(1, 10, "SameName", "exact", "bind", 1.0),
            Match(2, 11, "SameName", "exact", "bind", 1.0),
            Match(3, 10, "Other", "exact", "string", 0.9),
        ]
        kept, dropped = _dedupe(rows)
        self.assertEqual(len(kept), 1)
        self.assertEqual(dropped, 2)
        self.assertEqual(kept[0].windows, 10)

    def test_placeholder_detection(self) -> None:
        self.assertTrue(is_placeholder("FUN_00719000"))
        self.assertTrue(is_placeholder("thunk_FUN_140001000"))
        self.assertTrue(is_placeholder(""))
        self.assertFalse(is_placeholder("cResourceManager_Release"))
        self.assertFalse(is_placeholder("~cApplication"))


class OperatorNameTest(unittest.TestCase):
    """`operator<<` must not be mistaken for a template argument.

    The method-name extractor used a blind `split("<")[0]`, which turned every
    `BinaryBufferWriter::operator<<` symbol into `operator`; the database names such functions
    `BinaryBufferWriter::operator<<_<hex>`, so 34 rows silently stayed "unproven" even though they
    were already symbolized (round 86).
    """

    def test_operator_tokens_survive(self) -> None:
        for name in ("operator<<", "operator<", "operator<=", "operator->"):
            self.assertEqual(strip_template(name), name)

    def test_template_arguments_are_dropped(self) -> None:
        self.assertEqual(strip_template("cLuaNetworkVariable<unsigned short>"), "cLuaNetworkVariable")
        self.assertEqual(strip_template("vector<int>"), "vector")

    def test_mixed_operator_and_template(self) -> None:
        # an operator defined on a template class: the class template is cut, the operator is not
        self.assertEqual(strip_template("cLuaNetworkVariableArray<unsigned short>::operator<<"),
                         "cLuaNetworkVariableArray::operator<<")
        self.assertEqual(strip_template("std::vector<int>::operator<"), "std::vector::operator<")


class HeadOfTest(unittest.TestCase):
    """`head_of` must keep an operator's own parentheses and cut only the parameter list.

    Cutting at the first `(` turned `X::operator()(void const*, unsigned long)` into `X::operator`,
    so `SHA256_Klei::operator()` could never match its database name (round 106).
    """

    def test_operator_call_keeps_its_parens(self) -> None:
        self.assertEqual(head_of("SHA256_Klei::operator()(void const*, unsigned long)"),
                         "SHA256_Klei::operator()")
        self.assertEqual(head_of("SHA256_Klei::operator()"), "SHA256_Klei::operator()")

    def test_other_operators_unaffected(self) -> None:
        self.assertEqual(head_of("cStringBuilder::operator<<(char const*)"),
                         "cStringBuilder::operator<<")
        self.assertEqual(head_of("tServerListing::operator<(tServerListing const&) const"),
                         "tServerListing::operator<")

    def test_plain_method_cuts_at_arguments(self) -> None:
        self.assertEqual(head_of("cEntity::SetPristine()"), "cEntity::SetPristine")
        self.assertEqual(head_of("cEntity::SetParent(cEntity*, bool)"), "cEntity::SetParent")


class SignatureCreditTest(unittest.TestCase):
    """Overloads must be credited individually, never as a group.

    The Windows DB stores a parameter list on overloaded names, the Android symbol comes from
    c++filt with libc++ spellings; comparing `Class::operator>>` alone reported already-named
    overloads as `unproven` and credited one name to every sibling.
    """

    def test_libcxx_and_libstdcpp_spellings_agree(self) -> None:
        ndk = ("BinaryBufferReader::operator>>(std::__ndk1::basic_string<char, "
               "std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> >&)")
        db = "BinaryBufferReader::operator>>(std::string&)"
        self.assertEqual(norm_sig(ndk), norm_sig(db))

    def test_distinct_overloads_stay_distinct(self) -> None:
        self.assertNotEqual(norm_sig("BinaryBufferReader::operator>>(float&)"),
                            norm_sig("BinaryBufferReader::operator>>(double&)"))

    def test_name_export_signatures_are_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "names.tsv"
            p.write_text(
                "0x140000100\t50\t9\tBinaryBufferReader::operator>>(KleiMath::Vector2<float>&)\tUSER_DEFINED\tsym:x\n"
                "0x140000200\t64\t9\tBinaryBufferReader::operator>>_140000200\tUSER_DEFINED\tsym:y\n")
            _full, _bare, sigs = win_names(str(p))
        self.assertIn("BinaryBufferReader::operator>>(KleiMath::Vector2<float>&)", sigs)
        # the `_<hex>` ICF suffix is stripped before indexing
        self.assertIn("BinaryBufferReader::operator>>", sigs)


def doubled_namespace(name: str) -> bool:
    """True when a qualified name repeats its leading qualifier block.

    `DontStarveGameService::LuaProxy::DontStarveGameService::LuaProxy::AwardAchievement` came from
    setting a fully-qualified name on a symbol that already lived in that namespace (round 142).
    A constructor (`X::X`) is not doubled - the block must be at least two components long.
    """
    parts = name.split("::")
    return any(parts[:k] == parts[k:2 * k] for k in range(2, len(parts) // 2 + 1))


class DoubledNamespaceTest(unittest.TestCase):
    def test_detects_the_real_defect(self) -> None:
        self.assertTrue(doubled_namespace(
            "DontStarveGameService::LuaProxy::DontStarveGameService::LuaProxy::AwardAchievement"))

    def test_constructors_are_not_doubled(self) -> None:
        self.assertFalse(doubled_namespace("AtlasManager::AtlasManager"))
        self.assertFalse(doubled_namespace("MapLuaProxy::SetPrimaryColor"))

    def test_current_export_is_clean(self) -> None:
        snap = REPO / "build/symmatch/vt2/win_names_live148.tsv"
        if not snap.exists():
            self.skipTest("no name snapshot")
        rows = [l.split("\t") for l in snap.read_text(encoding="utf-8").splitlines() if l.startswith("0x")]
        self.assertGreater(len(rows), 7000, "snapshot looks truncated - the check would be vacuous")
        bad = [f[3] for f in rows if len(f) >= 4 and doubled_namespace(f[3])]
        self.assertEqual(bad, [])


class CoverageUniverseTest(unittest.TestCase):
    """The numerator and the denominator must be counted over the same symbol universe.

    `android_pairs()` attributes a symbol to the *enclosing* core type, so it yields more symbols
    (4,963) than the per-type table's `导出函数` column sums to (4,811): nested scopes such as
    `DontStarveInputHandler::LuaProxy::X` and template instantiations are counted with their owner.
    Using the column sum as the denominator while counting pairs described an impossible ratio
    (>100 % once everything is named).
    """

    def test_denominator_is_the_pair_count(self) -> None:
        sys.path.insert(0, str(TOOL / "manual"))
        try:
            from coverage import android_pairs  # noqa: PLC0415
            pairs = android_pairs()
        except (FileNotFoundError, AssertionError) as exc:     # inputs are build artefacts
            self.skipTest(f"android inventory not present: {exc}")
        declared = sum(
            int(m.group(2))
            for m in (re.match(r"\| `(\w+)` \| (\d+) \|", line)
                      for line in open(REPO / "3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md",
                                       encoding="utf-8")) if m)
        # the table counts the direct scope; nested scopes and template instantiations add ~170
        self.assertGreater(len(pairs) - declared, 100)

        export = REPO / "build/symmatch/vt2/win_names_live111.tsv"
        if not export.exists():
            self.skipTest("name export not present")
        # --out into a temp file: the test must not overwrite the committed coverage report
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, str(TOOL / "manual/coverage.py"), str(export),
                                  "--out", str(Path(tmp) / "coverage.md")],
                                 capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(out.returncode, 0, out.stderr)
        m = re.search(r"named \*\*(\d+) / (\d+)\*\*", out.stdout)
        self.assertIsNotNone(m, out.stdout)
        self.assertEqual(int(m.group(2)), len(pairs),
                         "the denominator must be the same universe the numerator is counted over")


class EndToEndTest(unittest.TestCase):
    def test_synthetic_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)

            def row(e: int, n: str, ni: int, strs=(), imms=(), cal=()) -> dict:
                return {"e": hex(e), "n": n, "sz": ni * 3, "ni": ni, "nb": 3, "ne": 4, "cx": 3,
                        "str": list(strs), "imm": [hex(v) for v in imms], "dr": [],
                        "cal": [hex(c) for c in cal]}

            android = [row(0x1000, "Alpha", 20),
                       row(0x2000, "FUN_2000", 25, strs=("unique_two",)),
                       row(0x3000, "FUN_3000", 40, imms=(0xDEADBEEF, 5), cal=(0x1000,))]
            windows = [row(0x9000, "FUN_9000", 21),
                       row(0xA000, "FUN_a000", 31, strs=("unique_two",)),
                       row(0xB000, "FUN_b000", 41, imms=(0xDEADBEEF, 5), cal=(0x9000,))]
            (d / "ia.jsonl").write_text("\n".join(json.dumps(r) for r in android) + "\n")
            (d / "iw.jsonl").write_text("\n".join(json.dumps(r) for r in windows) + "\n")
            (d / "ba.tsv").write_text("Alpha\t0x1000\t0\t24\n")
            (d / "bw.tsv").write_text("Alpha\t0x9000\t0\t24\n")

            r = subprocess.run(
                [sys.executable, str(TOOL / "run.py"), "match",
                 "--android-inv", str(d / "ia.jsonl"), "--windows-inv", str(d / "iw.jsonl"),
                 "--android-bind", str(d / "ba.tsv"), "--windows-bind", str(d / "bw.tsv"),
                 "--out", str(d)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

            matches = (d / "matches.tsv").read_text().splitlines()
            unresolved = (d / "unresolved.tsv").read_text().splitlines()
            self.assertTrue(any("\tAlpha\t" in line for line in matches))
            # FUN_2000 is a real pair but carries no Android symbol -> review bucket only
            self.assertEqual(len(matches), 1)
            self.assertTrue(any("0xa000" in line for line in unresolved))


if __name__ == "__main__":
    unittest.main()
