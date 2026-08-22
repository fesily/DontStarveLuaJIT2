#!/usr/bin/env python3
"""Gate dual-face package identity: modinfo.lua vs native PluginManifest.

Compares plugin_id / version / host_gate keys between package modinfo and
native man.* when both faces exist. When Mod/plugins/<stem>/modinfo.lua
exists, it must be byte-identical to the src copy. Stems without
modinfo.lua are skipped (exit 0).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DUAL_FACE = [
    "plugin_network_rpc",
    "plugin_network_sim",
    "plugin_save_fork",
    "plugin_sim_lagcomp",
    "plugin_debug_profiler",
    "plugin_fps_render",
    "plugin_render_shadow",
]

PLUGIN_ID_RE = re.compile(r"""plugin_id\s*=\s*["']([^"']+)["']""")
VERSION_RE = re.compile(r"""version\s*=\s*["']([^"']+)["']""")
HOST_GATE_RE = re.compile(
    r"""host_gate\s*=\s*(true|["']all_of["']|["']any_of["'])""",
    re.IGNORECASE,
)
NAME_ASSIGN_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""")

MAN_ID_RE = re.compile(r"""man\.id\s*=\s*["']([^"']+)["']""")
MAN_VERSION_RE = re.compile(r"""man\.version\s*=\s*["']([^"']+)["']""")
MAN_OPTIONS_KIND_RE = re.compile(
    r"""man\.options\.kind\s*=\s*OptionRuleKind::(\w+)"""
)
MAN_OPTIONS_KEYS_RE = re.compile(
    r"""man\.options\.keys\s*=\s*\{([^}]*)\}""",
    re.DOTALL,
)
# Resolve ds::config::keys::kFoo → "Foo" when header has constexpr string_view.
KEY_CONST_RE = re.compile(
    r"""(?:inline\s+)?constexpr\s+std::string_view\s+(k\w+)\s*=\s*["']([^"']+)["']"""
)
KEY_CONST_USE_RE = re.compile(
    r"""(?:std::string\s*\{\s*)?(?:ds::config::keys::)?(k\w+)(?:\s*\})?"""
)
STRING_IN_CPP_RE = re.compile(r"""["']([^"']+)["']""")


@dataclass
class ModinfoIdentity:
    plugin_id: str | None = None
    version: str | None = None
    option_keys: set[str] = field(default_factory=set)
    option_rule: str | None = None  # all_of | any_of | option | None


@dataclass
class NativeIdentity:
    plugin_id: str | None = None
    version: str | None = None
    option_kind: str | None = None  # AlwaysOn | AllOf | AnyOf | ...
    option_keys: set[str] = field(default_factory=set)


def plugins_root(source_root: Path) -> Path:
    return source_root / "src" / "DontStarveInjector" / "plugins"


def package_dir(source_root: Path, stem: str) -> Path:
    return plugins_root(source_root) / stem


def parse_host_gate_keys(text: str) -> tuple[set[str], set[str]]:
    all_of: set[str] = set()
    any_of: set[str] = set()
    for m in HOST_GATE_RE.finditer(text):
        kind = m.group(1).strip("'\"")
        before = text[: m.start()]
        names = NAME_ASSIGN_RE.findall(before)
        if not names:
            continue
        name = names[-1]
        if kind.lower() == "any_of":
            any_of.add(name)
        else:
            all_of.add(name)
    return all_of, any_of


def parse_modinfo(text: str) -> ModinfoIdentity:
    out = ModinfoIdentity()
    m = PLUGIN_ID_RE.search(text)
    if m:
        out.plugin_id = m.group(1)
    # Prefer first top-level version= assignment (engine field).
    m = VERSION_RE.search(text)
    if m:
        out.version = m.group(1)

    all_of, any_of = parse_host_gate_keys(text)
    out.option_keys = all_of | any_of
    if any_of:
        out.option_rule = "any_of"
    elif all_of:
        out.option_rule = "all_of"
    else:
        out.option_rule = None
    return out


def _load_key_constants(plugin_dir: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for path in sorted(plugin_dir.rglob("*")):
        if path.suffix.lower() not in {".hpp", ".h", ".cpp", ".cc", ".cxx"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in KEY_CONST_RE.finditer(text):
            mapping[m.group(1)] = m.group(2)
    return mapping


def _resolve_cpp_key_token(token: str, constants: dict[str, str]) -> str | None:
    token = token.strip()
    if not token:
        return None
    # Strip std::string{ ... } wrappers already handled by regex; try string lit.
    lit = STRING_IN_CPP_RE.fullmatch(token)
    if lit:
        return lit.group(1)
    m = KEY_CONST_USE_RE.search(token)
    if m:
        name = m.group(1)
        if name in constants:
            return constants[name]
        # Fallback: kEnableForkSave → EnableForkSave
        if name.startswith("k") and len(name) > 1:
            return name[1:]
    # Bare identifier like EnableForkSave without quotes (unlikely)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
        if token in constants:
            return constants[token]
        if token.startswith("k") and len(token) > 1:
            return token[1:]
        return token
    return None


def parse_native(plugin_dir: Path) -> NativeIdentity:
    out = NativeIdentity()
    constants = _load_key_constants(plugin_dir)
    texts: list[str] = []
    for path in sorted(plugin_dir.rglob("*")):
        if path.suffix.lower() not in {".cpp", ".cc", ".cxx", ".hpp", ".h"}:
            continue
        try:
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    blob = "\n".join(texts)
    m = MAN_ID_RE.search(blob)
    if m:
        out.plugin_id = m.group(1)
    m = MAN_VERSION_RE.search(blob)
    if m:
        out.version = m.group(1)
    m = MAN_OPTIONS_KIND_RE.search(blob)
    if m:
        out.option_kind = m.group(1)
    m = MAN_OPTIONS_KEYS_RE.search(blob)
    if m:
        body = m.group(1)
        # Split on commas at top level of the initializer list.
        parts = [p.strip() for p in body.split(",") if p.strip()]
        keys: set[str] = set()
        for part in parts:
            resolved = _resolve_cpp_key_token(part, constants)
            if resolved:
                keys.add(resolved)
        out.option_keys = keys
    return out


def find_cpp_present(plugin_dir: Path, stem: str) -> bool:
    if not plugin_dir.is_dir():
        return False
    direct = plugin_dir / f"{stem}.cpp"
    if direct.is_file():
        return True
    return any(plugin_dir.rglob(f"{stem}.cpp")) or any(
        p.suffix.lower() == ".cpp" for p in plugin_dir.rglob("*") if p.is_file()
    )


def check_stem(source_root: Path, stem: str) -> list[str]:
    """Return list of error messages for stem (empty = ok / skip)."""
    pkg = package_dir(source_root, stem)
    modinfo_path = pkg / "modinfo.lua"
    if not modinfo_path.is_file():
        # Migration not done yet — skip.
        return []
    if not find_cpp_present(pkg, stem):
        return [f"{stem}: modinfo.lua present but native plugin sources missing under {pkg}"]

    try:
        modinfo_text = modinfo_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [f"{stem}: failed to read modinfo.lua: {exc}"]

    mod = parse_modinfo(modinfo_text)
    native = parse_native(pkg)
    errors: list[str] = []

    if not mod.plugin_id:
        errors.append(f"{stem}: modinfo missing plugin_id")
    if not mod.version:
        errors.append(f"{stem}: modinfo missing version")
    if not native.plugin_id:
        errors.append(f"{stem}: native man.id not found")
    if not native.version:
        errors.append(f"{stem}: native man.version not found")

    if mod.plugin_id and native.plugin_id and mod.plugin_id != native.plugin_id:
        errors.append(
            f"{stem}: id drift: modinfo plugin_id={mod.plugin_id!r} "
            f"!= man.id={native.plugin_id!r}"
        )
    if mod.version and native.version and mod.version != native.version:
        errors.append(
            f"{stem}: version drift: modinfo version={mod.version!r} "
            f"!= man.version={native.version!r}"
        )

    kind = (native.option_kind or "").lower()
    if kind in {"allof", "anyof"}:
        if mod.option_keys != native.option_keys:
            errors.append(
                f"{stem}: option key drift: modinfo options={sorted(mod.option_keys)!r} "
                f"!= man.options.keys={sorted(native.option_keys)!r} "
                f"(kind={native.option_kind})"
            )

    installed = source_root / "Mod" / "plugins" / stem / "modinfo.lua"
    if installed.is_file():
        src_bytes = modinfo_path.read_bytes()
        dst_bytes = installed.read_bytes()
        if src_bytes != dst_bytes:
            errors.append(f"{stem}: Mod/plugins/{stem}/modinfo.lua differs from src")
    return errors


def run(source_root: Path, stems: list[str] | None = None) -> int:
    source_root = source_root.resolve()
    targets = stems if stems else list(DUAL_FACE)
    all_errors: list[str] = []
    checked = 0
    skipped = 0
    for stem in targets:
        pkg = package_dir(source_root, stem)
        if not (pkg / "modinfo.lua").is_file():
            skipped += 1
            print(f"skip {stem}: no modinfo.lua")
            continue
        errs = check_stem(source_root, stem)
        if errs:
            all_errors.extend(errs)
            for e in errs:
                print(e, file=sys.stderr)
        else:
            checked += 1
            print(f"ok {stem}")
    if all_errors:
        print(
            f"identity gate FAILED: {len(all_errors)} issue(s); "
            f"checked={checked} skipped={skipped}",
            file=sys.stderr,
        )
        return 1
    print(f"identity gate OK: checked={checked} skipped={skipped}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Repository / fixture root containing src/DontStarveInjector/plugins",
    )
    p.add_argument(
        "--stem",
        action="append",
        dest="stems",
        default=None,
        help="Limit check to one dual-face stem (repeatable). Default: all DUAL_FACE.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args.source_root, args.stems)


if __name__ == "__main__":
    raise SystemExit(main())
