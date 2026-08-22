#!/usr/bin/env python3
"""Read/write DST client modconfiguration_* files (KLEI plain Lua form).

Format:
  KLEI     1 local t = { ... option blocks ... }; return t

Mutates `saved` / `saved_client` for named options. Nested braces OK.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))

DEFAULT_MOD_ALIASES = (
    "workshop-3444078585",
    "DontStarveLuaJit2",
    "DontStarveLuaJIT2",
)


def klei_base() -> Path:
    env = os.environ.get("KLEI_ROOT")
    if env:
        return Path(env)
    return Path.home() / "Documents" / "Klei" / "DoNotStarveTogether"


def find_steam_account_dirs(base: Path) -> list[Path]:
    if not base.exists():
        return []
    out = []
    for p in base.iterdir():
        if p.is_dir() and p.name.isdigit() and (p / "client_save").exists():
            out.append(p)
    return sorted(out, key=lambda x: x.stat().st_mtime, reverse=True)


def mod_config_dir(account: Path) -> Path:
    return account / "client_save" / "mod_config_data"


def resolve_config_path(
    *,
    account_id: Optional[str] = None,
    mod_aliases: tuple[str, ...] = DEFAULT_MOD_ALIASES,
    prefer_dev: bool = True,
) -> Path:
    base = klei_base()
    if account_id:
        accounts = [base / account_id]
    else:
        accounts = find_steam_account_dirs(base)
        if not accounts:
            accounts = [base]
    for acc in accounts:
        if (acc / "client_save").exists():
            mdir = mod_config_dir(acc)
        else:
            mdir = base / "client_save" / "mod_config_data"
        for alias in mod_aliases:
            names = [f"modconfiguration_{alias}_dev", f"modconfiguration_{alias}"]
            if not prefer_dev:
                names = list(reversed(names))
            for name in names:
                p = mdir / name
                if p.exists():
                    return p
    if accounts:
        mdir = mod_config_dir(accounts[0]) if (accounts[0] / "client_save").exists() else base / "client_save" / "mod_config_data"
        mdir.mkdir(parents=True, exist_ok=True)
        return mdir / f"modconfiguration_{mod_aliases[0]}_dev"
    raise FileNotFoundError(f"no Klei account under {base}")


def _format_lua_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    if isinstance(v, float):
        if v.is_integer():
            return str(int(v))
        return str(v)
    if v is None:
        return '""'
    s = str(v)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _parse_lua_literal(token: str) -> Any:
    token = token.strip()
    if token == "true":
        return True
    if token == "false":
        return False
    if token == "nil":
        return None
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    try:
        if "." in token:
            return float(token)
        return int(token)
    except ValueError:
        return token


def _find_table_array(text: str) -> Tuple[int, int]:
    """Return [start, end) of the top-level `local t = { ... }` value braces."""
    m = re.search(r"local\s+t\s*=\s*\{", text)
    if not m:
        raise ValueError("no local t = { in config")
    open_i = m.end() - 1
    depth = 0
    i = open_i
    while i < len(text):
        c = text[i]
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    break
                i += 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return open_i, i + 1
        i += 1
    raise ValueError("unbalanced braces in local t")


def _split_top_level_entries(table_body: str) -> List[Tuple[int, int]]:
    """table_body is content BETWEEN the outer braces of t. Return relative spans of top-level `{...}` entries."""
    spans: List[Tuple[int, int]] = []
    depth = 0
    start = -1
    i = 0
    while i < len(table_body):
        c = table_body[i]
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < len(table_body):
                if table_body[i] == "\\":
                    i += 2
                    continue
                if table_body[i] == q:
                    break
                i += 1
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                spans.append((start, i + 1))
                start = -1
        i += 1
    return spans


def _option_name(block: str) -> Optional[str]:
    m = re.search(r'name\s*=\s*"([^"]+)"', block)
    return m.group(1) if m else None


def _option_saved(block: str) -> Optional[Any]:
    m = re.search(r"saved\s*=\s*([^,\n]+)", block)
    if not m:
        return None
    return _parse_lua_literal(m.group(1))


def load_saved_options(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("KLEI"):
        raise ValueError(f"not a KLEI config file: {path}")
    open_i, close_i = _find_table_array(text)
    body = text[open_i + 1 : close_i - 1]
    out: Dict[str, Any] = {}
    for a, b in _split_top_level_entries(body):
        block = body[a:b]
        name = _option_name(block)
        if not name or name.startswith("SECTION_"):
            continue
        val = _option_saved(block)
        if val is not None:
            out[name] = val
    return out


def _set_field(block: str, field: str, lua_val: str) -> str:
    rx = re.compile(rf"({field}\s*=\s*)([^,\n]+)")
    if rx.search(block):
        return rx.sub(rf"\g<1>{lua_val}", block, count=1)
    # insert after name=
    return re.sub(
        r'(name\s*=\s*"[^"]+"\s*,)',
        rf"\1\n    {field}={lua_val},",
        block,
        count=1,
    )


def apply_overrides(path: Path, overrides: Dict[str, Any], *, backup: bool = True) -> Path:
    if not path.exists():
        raise FileNotFoundError(
            f"config file missing: {path}\n"
            "Launch the client once with the mod enabled so DST writes a baseline file."
        )
    text = path.read_text(encoding="utf-8")
    if not text.startswith("KLEI"):
        raise ValueError(f"not a KLEI config file: {path}")

    if backup:
        bak = path.with_suffix(path.suffix + ".bak")
        # only write bak once so repeated applies keep original
        if not bak.exists():
            shutil.copy2(path, bak)

    open_i, close_i = _find_table_array(text)
    body = text[open_i + 1 : close_i - 1]
    spans = _split_top_level_entries(body)

    # rebuild body from end so offsets stay valid
    new_body = body
    for a, b in reversed(spans):
        block = body[a:b]
        name = _option_name(block)
        if not name or name not in overrides:
            continue
        lua_val = _format_lua_value(overrides[name])
        block = _set_field(block, "saved", lua_val)
        if re.search(r"saved_client\s*=", block):
            block = _set_field(block, "saved_client", lua_val)
        new_body = new_body[:a] + block + new_body[b:]

    new_text = text[: open_i + 1] + new_body + text[close_i - 1 :]
    path.write_text(new_text, encoding="utf-8")
    return path


def restore_backup(path: Path) -> bool:
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        return False
    shutil.copy2(bak, path)
    return True


def load_profile(name: str) -> Dict[str, Any]:
    p = ROOT / "tests" / "plugin_client" / "profiles" / f"{name}.json"
    if not p.exists():
        raise FileNotFoundError(p)
    return json.loads(p.read_text(encoding="utf-8"))


def apply_profile(name: str, **kwargs: Any) -> Path:
    overrides = load_profile(name)
    path = resolve_config_path(**{k: v for k, v in kwargs.items() if k in ("account_id", "mod_aliases", "prefer_dev")})
    if not overrides:
        # defaults profile: no-op if file exists
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    return apply_overrides(path, overrides)


def main() -> int:
    ap = argparse.ArgumentParser(description="DST modconfiguration helper")
    ap.add_argument("cmd", choices=("show", "apply", "set", "restore", "path"))
    ap.add_argument("--profile", default=None)
    ap.add_argument("--path", default=None)
    ap.add_argument("--account", default=None)
    ap.add_argument("--kv", action="append", default=[], help="key=value (for set)")
    args = ap.parse_args()

    path = Path(args.path) if args.path else resolve_config_path(account_id=args.account)
    print(f"[mod_config] path={path}")

    if args.cmd == "path":
        return 0

    if args.cmd == "show":
        if not path.exists():
            print("missing", file=sys.stderr)
            return 1
        print(json.dumps(load_saved_options(path), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "restore":
        ok = restore_backup(path)
        print("restored" if ok else "no backup")
        return 0 if ok else 1

    if args.cmd == "apply":
        if not args.profile:
            print("--profile required", file=sys.stderr)
            return 1
        if args.path:
            apply_overrides(path, load_profile(args.profile))
        else:
            apply_profile(args.profile, account_id=args.account)
        print(json.dumps(load_saved_options(path), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "set":
        overrides: Dict[str, Any] = {}
        for item in args.kv:
            if "=" not in item:
                print(f"bad --kv {item}", file=sys.stderr)
                return 1
            k, v = item.split("=", 1)
            overrides[k] = _parse_lua_literal(v)
        apply_overrides(path, overrides)
        print(json.dumps(load_saved_options(path), ensure_ascii=False, indent=2, default=str))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
