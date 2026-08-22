#!/usr/bin/env python3
"""Generate per-platform plugin manifests, meta sidecars, and per-plugin zips.

Also merges platform partials into a single plugins-manifest.json.

Discovers modules both flat under the plugins root and inside package
subdirectories (plugins/plugin_<stem>/plugin_<stem>.{dll,so,dylib}). Package
zips include package-relative Lua (modinfo.lua, modmain.lua, scripts/**).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

MODULE_TO_ID: dict[str, str] = {
    "plugin_core_vm": "core.vm",
    "plugin_dummy": "debug.dummy",
    "plugin_network_rpc": "network.rpc",
    "plugin_network_sim": "network.sim",
    "plugin_network_tick": "network.tick",
    "plugin_render_vbpool": "render.vbpool",
    "plugin_render_angle": "render.angle",
    "plugin_render_shadow": "render.shadow",
    "plugin_save_fork": "save.fork",
    "plugin_sim_lagcomp": "sim.lagcomp",
    "plugin_debug_profiler": "debug.profiler",
    "plugin_fps_render": "fps.render",
    "plugin_manager": "plugin.manager",
}

MODULE_EXTS = {".dll", ".so", ".dylib"}
VERSION_RE = re.compile(
    r"""man\.version\s*=\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']"""
)
ABI_VERSION = "1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def module_stem(path: Path) -> str:
    name = path.name
    # Handle libfoo.so.1 style; our modules use PREFIX "" so stem is plugin_*.
    if name.endswith(".dylib"):
        return name[: -len(".dylib")]
    if name.endswith(".dll"):
        return name[: -len(".dll")]
    if name.endswith(".so"):
        return name[: -len(".so")]
    return path.stem


def is_plugin_module(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() not in MODULE_EXTS:
        return False
    return path.name.startswith("plugin_")


def extract_version_from_source(source_root: Path, stem: str) -> str:
    plugin_dir = source_root / "src" / "DontStarveInjector" / "plugins" / stem
    candidates: list[Path] = []
    if plugin_dir.is_dir():
        candidates.extend(sorted(plugin_dir.rglob("*.cpp")))
        candidates.extend(sorted(plugin_dir.rglob("*.hpp")))
        candidates.extend(sorted(plugin_dir.rglob("*.h")))
    # Fallback: scan all plugin sources for this stem filename.
    if not candidates:
        root = source_root / "src" / "DontStarveInjector" / "plugins"
        if root.is_dir():
            candidates = sorted(root.rglob(f"{stem}.*"))

    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = VERSION_RE.search(text)
        if m:
            return m.group(1)

    print(
        f"warning: man.version not found for {stem}; using 0.0.0",
        file=sys.stderr,
    )
    return "0.0.0"


def logical_id_for_stem(stem: str) -> str | None:
    if stem in MODULE_TO_ID:
        return MODULE_TO_ID[stem]
    print(f"warning: unknown plugin stem {stem!r}; skipping", file=sys.stderr)
    return None


def write_meta(path: Path, meta: dict[str, Any]) -> None:
    path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iter_plugin_modules(plugins_dir: Path) -> list[Path]:
    """Discover plugin modules: flat under plugins_dir or package subdirs.

    Package layout: plugins/plugin_<stem>/plugin_<stem>.{dll,so,dylib}
    Flat (legacy / C-only staging): plugins/plugin_<stem>.{dll,so,dylib}
    """
    found: list[Path] = []
    if not plugins_dir.is_dir():
        return found
    for p in sorted(plugins_dir.iterdir()):
        if is_plugin_module(p):
            found.append(p)
            continue
        if p.is_dir() and p.name.startswith("plugin_"):
            for ext in MODULE_EXTS:
                cand = p / f"{p.name}{ext}"
                if cand.is_file():
                    found.append(cand)
                    break
    return found


def package_dir_for_module(module_path: Path) -> Path | None:
    """Return package directory when module lives in plugins/plugin_<stem>/."""
    stem = module_stem(module_path)
    parent = module_path.parent
    if parent.name == stem:
        return parent
    return None


def collect_package_lua_files(pkg_dir: Path) -> list[Path]:
    """Collect modinfo/modmain and scripts/**/*.lua under a package dir."""
    files: list[Path] = []
    for name in ("modinfo.lua", "modmain.lua"):
        cand = pkg_dir / name
        if cand.is_file():
            files.append(cand)
    scripts = pkg_dir / "scripts"
    if scripts.is_dir():
        files.extend(sorted(p for p in scripts.rglob("*.lua") if p.is_file()))
    return files


def make_plugin_zip(
    zip_path: Path,
    members: Iterable[tuple[Path, str]],
) -> None:
    """Write zip with (source_path, arcname) members. Arcnames may be nested."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, arcname in members:
            # Normalize zip entry separators to forward slash.
            zf.write(src, arcname=arcname.replace("\\", "/"))


def generate_partial(args: argparse.Namespace) -> int:
    plugins_dir = Path(args.plugins_dir)
    source_root = Path(args.source_root)
    out_manifest = Path(args.out_manifest)
    out_zips_dir = Path(args.out_zips_dir) if args.out_zips_dir else None
    platform = args.platform

    if not plugins_dir.is_dir():
        print(f"error: plugins dir missing: {plugins_dir}", file=sys.stderr)
        return 1

    modules = iter_plugin_modules(plugins_dir)
    plugins: list[dict[str, Any]] = []

    for module_path in modules:
        stem = module_stem(module_path)
        plugin_id = logical_id_for_stem(stem)
        if plugin_id is None:
            continue

        version = extract_version_from_source(source_root, stem)
        digest = sha256_file(module_path)
        meta_name = f"{stem}.meta.json"
        pkg_dir = package_dir_for_module(module_path)
        # Meta lives next to the module (package subdir or flat plugins root).
        meta_path = (pkg_dir / meta_name) if pkg_dir is not None else (plugins_dir / meta_name)
        meta = {
            "id": plugin_id,
            "version": version,
            "sha256": digest,
            "module": module_path.name,
        }
        if args.write_meta:
            write_meta(meta_path, meta)

        asset = f"{stem}-{version}-{platform}.zip"
        # Members: (path, arcname). Prefer package-relative layout when packaged.
        members: list[tuple[Path, str]] = []
        files: list[str] = []

        def add_member(path: Path, arcname: str) -> None:
            arc = arcname.replace("\\", "/")
            if arc in files:
                return
            members.append((path, arc))
            files.append(arc)

        add_member(module_path, module_path.name)
        if meta_path.is_file():
            add_member(meta_path, meta_name)

        if pkg_dir is not None:
            for lua_path in collect_package_lua_files(pkg_dir):
                rel = lua_path.relative_to(pkg_dir).as_posix()
                add_member(lua_path, rel)

        if out_zips_dir is not None:
            make_plugin_zip(out_zips_dir / asset, members)

        plugins.append(
            {
                "id": plugin_id,
                "version": version,
                "platforms": {
                    platform: {
                        "available": True,
                        "asset": asset,
                        "sha256": digest,
                        "module": module_path.name,
                        "files": files,
                    }
                },
            }
        )

    plugins.sort(key=lambda p: p["id"])
    partial: dict[str, Any] = {
        "schema_version": 1,
        "repo": args.repo,
        "release_tag": args.release_tag,
        "mod_version": args.mod_version,
        "abi_version": ABI_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "plugins": plugins,
    }
    out_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_manifest.write_text(
        json.dumps(partial, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return 0


def platform_from_mod_zip_name(name: str) -> str | None:
    # windows_Mod.zip / linux_Mod.zip / macos_Mod.zip
    m = re.match(r"^(windows|linux|macos)_Mod\.zip$", name)
    return m.group(1) if m else None


def merge_manifests(args: argparse.Namespace) -> int:
    partial_paths = [Path(p) for p in args.merge]
    if not partial_paths:
        print("error: --merge requires at least one partial path", file=sys.stderr)
        return 1

    merged_plugins: dict[str, dict[str, Any]] = {}
    top: dict[str, Any] = {
        "schema_version": 1,
        "repo": None,
        "release_tag": None,
        "mod_version": None,
        "abi_version": ABI_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    for path in partial_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("repo", "release_tag", "mod_version", "abi_version"):
            if data.get(key) is not None:
                if top[key] is None:
                    top[key] = data[key]
                elif top[key] != data[key] and key != "abi_version":
                    print(
                        f"warning: conflicting {key}: {top[key]!r} vs {data[key]!r} ({path})",
                        file=sys.stderr,
                    )
        for entry in data.get("plugins", []):
            pid = entry["id"]
            slot = merged_plugins.setdefault(
                pid,
                {
                    "id": pid,
                    "version": entry.get("version", "0.0.0"),
                    "platforms": {},
                },
            )
            # Prefer non-empty version if later partial differs; keep first non-zero.
            if entry.get("version") and (
                slot["version"] in (None, "", "0.0.0")
                or slot["version"] == entry["version"]
            ):
                slot["version"] = entry["version"]
            elif entry.get("version") and slot["version"] != entry["version"]:
                print(
                    f"warning: version mismatch for {pid}: "
                    f"{slot['version']} vs {entry['version']}",
                    file=sys.stderr,
                )
            for plat, info in entry.get("platforms", {}).items():
                slot["platforms"][plat] = info

    plugins_list = sorted(merged_plugins.values(), key=lambda p: p["id"])
    result: dict[str, Any] = {
        "schema_version": int(top["schema_version"] or 1),
        "repo": top["repo"] or "",
        "release_tag": top["release_tag"] or "",
        "mod_version": top["mod_version"] or "",
        "abi_version": top["abi_version"] or ABI_VERSION,
        "generated_at": top["generated_at"],
        "plugins": plugins_list,
    }

    bundle_paths: list[Path] = []
    if args.bundle_zips:
        for pattern in args.bundle_zips:
            p = Path(pattern)
            if p.is_file():
                bundle_paths.append(p)
            else:
                # Allow shell-expanded globs that failed to expand on Windows.
                parent = p.parent if p.parent != Path("") else Path(".")
                if parent.is_dir():
                    bundle_paths.extend(sorted(parent.glob(p.name)))

    if bundle_paths:
        bundle: dict[str, Any] = {}
        for zp in bundle_paths:
            plat = platform_from_mod_zip_name(zp.name)
            if plat is None:
                print(f"warning: skip unrecognized bundle zip {zp.name}", file=sys.stderr)
                continue
            bundle[plat] = {"asset": zp.name, "sha256": sha256_file(zp)}
        if bundle:
            result["bundle"] = bundle

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--merge",
        nargs="*",
        default=None,
        metavar="PARTIAL",
        help="Merge platform partial manifests into one plugins-manifest.json",
    )
    p.add_argument(
        "--bundle-zips",
        nargs="*",
        default=None,
        metavar="ZIP",
        help="Optional Mod zips for merged bundle sha256 entries",
    )
    p.add_argument("--out", default=None, help="Output path for --merge mode")

    p.add_argument("--plugins-dir", default=None, help="Staged plugins directory")
    p.add_argument(
        "--platform",
        default=None,
        choices=("windows", "linux", "macos"),
        help="Platform key for partial manifest",
    )
    p.add_argument("--repo", default=None, help="GitHub owner/repo")
    p.add_argument("--release-tag", default=None, help="Release / preview tag")
    p.add_argument("--mod-version", default=None, help="Monorepo mod version")
    p.add_argument(
        "--source-root",
        default=".",
        help="Repo root used to extract man.version from sources",
    )
    p.add_argument("--out-manifest", default=None, help="Partial manifest output path")
    p.add_argument(
        "--out-zips-dir",
        default=None,
        help="Directory for per-plugin zip packages",
    )
    p.add_argument(
        "--write-meta",
        action="store_true",
        help="Write plugin_*.meta.json beside each module",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.merge is not None:
        if args.out is None:
            print("error: --merge requires --out", file=sys.stderr)
            return 2
        # When invoked as `--merge a b --out x`, nargs='*' captures a b.
        # If user passes only `--merge` with no files, error.
        if len(args.merge) == 0:
            print("error: --merge requires partial manifest paths", file=sys.stderr)
            return 2
        return merge_manifests(args)

    required = {
        "plugins_dir": args.plugins_dir,
        "platform": args.platform,
        "repo": args.repo,
        "release_tag": args.release_tag,
        "mod_version": args.mod_version,
        "out_manifest": args.out_manifest,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        print(
            "error: generate mode requires "
            + ", ".join("--" + m.replace("_", "-") for m in missing),
            file=sys.stderr,
        )
        return 2
    return generate_partial(args)


if __name__ == "__main__":
    raise SystemExit(main())
