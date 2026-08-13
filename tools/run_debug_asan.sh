#!/usr/bin/env bash
# run_debug_asan.sh — Debug + AddressSanitizer GC suite + DST dedicated server smoke
#
# Lanes:
#   1) Standalone LuaJIT ASAN+GCARENA unit suite (make ASAN=1)
#   2) CMake Debug FSANITIZE: luajit-5.1-gengc + Injector + InjectorStub → cmake --install Mod/
#   3) Dedicated server Master/Cluster_1 under ASAN (lua_vm_type=jit_gen)
#
# Portable package layout (post-Mod/deps refactor):
#   Mod/libInjector.so              real injector (RUNPATH $ORIGIN/deps)
#   Mod/deps/liblua51DS_gengc.so    gengc VM + third-party runtimes
#   Mod/bin64/linux/lib64/libInjector.so   thin stub for game LD_PRELOAD
#   game bin64/lib64/libInjector.so        stub only
#   game data/unsafedata/ds_luajit_injector.path → abs path to Mod/libInjector.so
# Never stage real Injector / VMs into game bin64.
#
# Usage:
#   tools/run_debug_asan.sh                  # suite + game (default)
#   tools/run_debug_asan.sh --suite-only
#   tools/run_debug_asan.sh --game-only
#   tools/run_debug_asan.sh --skip-build     # reuse existing binaries
#   tools/run_debug_asan.sh --soak 180       # keep server up N seconds after SUCCESS
#   tools/run_debug_asan.sh --no-clean       # do not make clean before suite build
#   tools/run_debug_asan.sh --evidence DIR   # override evidence output dir
#   tools/run_debug_asan.sh --timeout 300
#
# Env overrides:
#   GAME_ROOT, CLUSTER, SHARD, ASAN_LIB, LUAJIT_SRC, REPO_ROOT, BUILD_DIR
#   GAME_TIMEOUT_SEC (default 300), RSS_LIMIT_GB (default 8)
#   LUA_VM_TYPE (default jit_gen)
#
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LUAJIT_SRC="${LUAJIT_SRC:-$REPO_ROOT/luajit}"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/builds/ninja-multi-vcpkg}"
ASAN_LIB="${ASAN_LIB:-/usr/lib/x86_64-linux-gnu/libasan.so.8}"
CLUSTER="${CLUSTER:-Cluster_1}"
SHARD="${SHARD:-Master}"
LUA_VM_TYPE="${LUA_VM_TYPE:-jit_gen}"
GAME_TIMEOUT_SEC="${GAME_TIMEOUT_SEC:-300}"
RSS_LIMIT_GB="${RSS_LIMIT_GB:-8}"
SOAK_SEC="${SOAK_SEC:-0}"

MODE_SUITE=1
MODE_GAME=1
SKIP_BUILD=0
MAKE_CLEAN=1
EVIDENCE_DIR=""

ASAN_OPTIONS_SUITE="${ASAN_OPTIONS_SUITE:-detect_leaks=0:allow_user_poisoning=1:halt_on_error=1:exitcode=99}"
ASAN_OPTIONS_GAME="${ASAN_OPTIONS_GAME:-detect_leaks=0:allow_user_poisoning=1:halt_on_error=0:alloc_dealloc_mismatch=0:quarantine_size_mb=32}"

SUITE_PASS=0
SUITE_FAIL=0
BUILD_PASS=0
GAME_PASS=0
GAME_FAIL=0

SUITE_TESTS=(
  "test/test_gc_adversarial.lua"
  "test/test_gc_invariants.lua"
  "test/test_weak_stacks.lua"
  "test/test_finalizer_order.lua"
  "test/gc/openuv_vector_v31_assert.lua"
  "test/gc/openuv_dead_thread_mark_assert.lua"
  "test/gc/thread_openupval_sweep_assert.lua"
  "test/gc/thread_permgray_residual_assert.lua"
  "test/gc/white1_free_assert.lua"
  "test/gc/udata_finalize_assert.lua"
  "test/gc/huge_swept_tag_assert.lua"
  "test/gc/stale_gray_survivor_stress.lua"
  "test/test_str_rehash_sweep.lua"
  "__leaf_mini__"
)

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite-only) MODE_GAME=0; shift ;;
    --game-only)  MODE_SUITE=0; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-clean)   MAKE_CLEAN=0; shift ;;
    --soak)       SOAK_SEC="${2:?}"; shift 2 ;;
    --evidence)   EVIDENCE_DIR="${2:?}"; shift 2 ;;
    --timeout)    GAME_TIMEOUT_SEC="${2:?}"; shift 2 ;;
    -h|--help)    usage 0 ;;
    *) echo "Unknown arg: $1" >&2; usage 1 ;;
  esac
done

ts="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$REPO_ROOT/.omo/evidence/debug-asan-$ts"
fi
# Absolute path: suite/game lanes pushd into luajit/ or game bin64.
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
SUMMARY="$EVIDENCE_DIR/SUMMARY.md"
LOG_MAIN="$EVIDENCE_DIR/run.log"

exec > >(tee -a "$LOG_MAIN") 2>&1

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { log "FATAL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

require_asan_lib() {
  [[ -f "$ASAN_LIB" ]] || die "ASAN runtime missing: $ASAN_LIB (set ASAN_LIB=...)"
  log "ASAN_LIB=$ASAN_LIB"
}

# Parse .vscode/settings.json as JSONC (// comments + trailing commas).
resolve_game_root() {
  if [[ -n "${GAME_ROOT:-}" && -d "$GAME_ROOT" ]]; then
    printf '%s\n' "$GAME_ROOT"
    return
  fi
  local settings="$REPO_ROOT/.vscode/settings.json"
  if [[ -f "$settings" ]]; then
    local root
    root="$(python3 - "$settings" <<'PY'
import json, re, sys
from pathlib import Path

def strip_jsonc(text: str) -> str:
    out = []
    in_str = False
    esc = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(i + 2, n)
            continue
        out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))

obj = json.loads(strip_jsonc(Path(sys.argv[1]).read_text(encoding="utf-8")))
game = obj.get("steam.game.root")
steam = obj.get("steam.root")
if isinstance(game, str) and game.strip():
    g = game.strip()
    if "${steam.root}" in g and isinstance(steam, str):
        g = g.replace("${steam.root}", steam.rstrip("/"))
    print(g)
elif isinstance(steam, str) and steam.strip():
    print(steam.rstrip("/") + "/common/Don't Starve Together")
PY
)" || true
    if [[ -n "${root:-}" && -d "$root" ]]; then
      printf '%s\n' "$root"
      return
    fi
  fi
  for cand in \
    "$HOME/.steam/debian-installation/steamapps/common/Don't Starve Together" \
    "$HOME/.steam/steam/steamapps/common/Don't Starve Together" \
    "$HOME/.local/share/Steam/steamapps/common/Don't Starve Together"; do
    if [[ -d "$cand" ]]; then
      printf '%s\n' "$cand"
      return
    fi
  done
  return 1
}

clear_stale_host_buildvm_arch() {
  # make ASAN=1 leaves GCMARK host/buildvm_arch.h; CMake classic buildvm
  # #include "buildvm_arch.h" prefers host/ over variants/default/.
  rm -f "$LUAJIT_SRC/src/host/buildvm_arch.h"
}

run_suite_build() {
  log "=== Lane 1: standalone ASAN+GCARENA build ==="
  require_asan_lib
  pushd "$LUAJIT_SRC" >/dev/null
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    if [[ "$MAKE_CLEAN" -eq 1 ]]; then
      make -C src clean >"$EVIDENCE_DIR/asan-build-clean.log" 2>&1 || true
    fi
    # shellcheck disable=SC2086
    make -C src -j"$(nproc)" ASAN=1 \
      XCFLAGS="-DLUAJIT_ENABLE_GCARENA -DLUA_USE_ASSERT" \
      >"$EVIDENCE_DIR/asan-build.log" 2>&1 \
      || die "standalone ASAN build failed (see asan-build.log)"
    log "standalone ASAN build OK"
    clear_stale_host_buildvm_arch
  else
    [[ -x "$LUAJIT_SRC/src/luajit" ]] || die "skip-build but $LUAJIT_SRC/src/luajit missing"
    log "skip-build: reusing $LUAJIT_SRC/src/luajit"
  fi
  popd >/dev/null
}

run_leaf_mini() {
  local out="$EVIDENCE_DIR/asan-leaf_mini.log"
  local lj="$LUAJIT_SRC/src/luajit"
  ASAN_OPTIONS="${ASAN_OPTIONS_SUITE}" \
  "$lj" -e '
    local t = {}
    for i = 1, 4000 do t["k"..i] = i end
    collectgarbage("step", 200)
    for i = 1, 8000 do t["k"..i] = i * 2 end
    collectgarbage("step", 400)
    for i = 1, 2000 do t[i] = {i, i+1, i+2} end
    for _ = 1, 20 do collectgarbage("step", 100) end
    local n = 0
    for _ in pairs(t) do n = n + 1 end
    assert(n > 8000, "leaf_mini: unexpected size "..n)
    collectgarbage()
    print("leaf_mini_ok")
  ' >"$out" 2>&1
}

run_one_suite_test() {
  local rel="$1"
  local name out rc
  if [[ "$rel" == "__leaf_mini__" ]]; then
    name="leaf_mini"
    out="$EVIDENCE_DIR/asan-leaf_mini.log"
    set +e
    run_leaf_mini
    rc=$?
    set -e
  else
    name="$(basename "$rel" .lua)"
    out="$EVIDENCE_DIR/asan-${name}.log"
    set +e
    ( cd "$LUAJIT_SRC"; ASAN_OPTIONS="${ASAN_OPTIONS_SUITE}" ./src/luajit "$rel" ) >"$out" 2>&1
    rc=$?
    set -e
  fi
  if [[ $rc -eq 0 ]]; then
    # also fail if hard ASAN text appears with exit 0 (should not)
    if grep -qE 'ERROR: AddressSanitizer:|heap-use-after-free|use-after-poison|heap-buffer-overflow|double-free' "$out" 2>/dev/null; then
      log "FAIL  $name (ASAN in log) -> $out"
      SUITE_FAIL=$((SUITE_FAIL + 1))
      return 1
    fi
    log "PASS  $name"
    SUITE_PASS=$((SUITE_PASS + 1))
    return 0
  fi
  log "FAIL  $name (rc=$rc) -> $out"
  SUITE_FAIL=$((SUITE_FAIL + 1))
  return 1
}

run_suite() {
  SUITE_PASS=0
  SUITE_FAIL=0
  log "=== Lane 1: ASAN GC suite (${#SUITE_TESTS[@]} tests) ==="
  local t
  for t in "${SUITE_TESTS[@]}"; do
    run_one_suite_test "$t" || true
  done
  printf 'SUMMARY suite pass=%s fail=%s\n' "$SUITE_PASS" "$SUITE_FAIL" \
    | tee "$EVIDENCE_DIR/asan-suite-summary.txt"
  [[ "$SUITE_FAIL" -eq 0 ]]
}

run_cmake_asan_build() {
  log "=== Lane 2: CMake Debug FSANITIZE gengc ==="
  require_asan_lib
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    log "skip-build: skip cmake"
    return 0
  fi
  [[ -f "$BUILD_DIR/build.ninja" || -f "$BUILD_DIR/CMakeCache.txt" ]] \
    || die "CMake build dir missing: $BUILD_DIR (run cmake --preset ninja-multi-vcpkg)"

  if ! grep -q 'LUAJIT_ENABLE_FSANITIZE:BOOL=ON' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null; then
    log "enabling LUAJIT_ENABLE_FSANITIZE=ON"
    cmake -DLUAJIT_ENABLE_FSANITIZE=ON -S "$REPO_ROOT" -B "$BUILD_DIR" \
      >"$EVIDENCE_DIR/cmake-reconfigure.log" 2>&1 \
      || die "cmake reconfigure failed"
  fi

  clear_stale_host_buildvm_arch

  # Prefer public gengc alias; fall back to arenagc on older trees.
  local gengc_tgt=luajit-5.1-gengc
  if ! ninja -C "$BUILD_DIR" -t targets 2>/dev/null | grep -qF 'luajit-5.1-gengc:'; then
    gengc_tgt=luajit-5.1-arenagc
  fi
  log "building gengc target: $gengc_tgt"

  ASAN_OPTIONS=detect_leaks=0 \
    cmake --build "$BUILD_DIR" --config Debug --target "$gengc_tgt" -j"$(nproc)" \
      >"$EVIDENCE_DIR/cmake-debug-gengc.log" 2>&1 \
    || die "cmake gengc build failed (see cmake-debug-gengc.log)"

  ASAN_OPTIONS=detect_leaks=0 \
    cmake --build "$BUILD_DIR" --config Debug --target Injector InjectorStub -j"$(nproc)" \
      >"$EVIDENCE_DIR/cmake-debug-injector.log" 2>&1 \
    || die "Injector/InjectorStub Debug build failed (see cmake-debug-injector.log)"
  log "Injector + InjectorStub Debug build OK"

  ASAN_OPTIONS=detect_leaks=0 \
    cmake --install "$BUILD_DIR" --config Debug \
      >"$EVIDENCE_DIR/cmake-install.log" 2>&1 \
    || die "cmake --install failed (Mod/ package)"

  BUILD_PASS=1
  log "cmake install OK → $REPO_ROOT/Mod"
}

# Resolve newest existing path among candidates.
_first_existing() {
  local p
  for p in "$@"; do
    if [[ -f "$p" ]]; then
      printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

deploy_to_game() {
  local game_root="$1"
  local bin64="$game_root/bin64"
  local lib64="$bin64/lib64"
  local mod_root="$REPO_ROOT/Mod"
  local mod_deps="$mod_root/deps"
  local marker_dir="$game_root/data/unsafedata"
  mkdir -p "$lib64" "$mod_deps" "$marker_dir" "$mod_root/bin64/linux/lib64"

  # --- sources (prefer cmake --install Mod/ layout, then build tree) ---
  local src_gengc src_real_inj src_stub
  src_gengc="$(_first_existing \
    "$mod_deps/liblua51DS_gengc.so" \
    "$BUILD_DIR/luajit/Debug/liblua51DS_gengc.so" \
    "$BUILD_DIR/luajit/liblua51DS_gengc.so" \
    "$mod_root/bin64/linux/lib64/liblua51DS_gengc.so" \
  )" || die "liblua51DS_gengc.so not found (build lane 2 / cmake --install first)"

  src_real_inj="$(_first_existing \
    "$mod_root/libInjector.so" \
    "$BUILD_DIR/src/DontStarveInjector/Debug/libInjector.so" \
    "$BUILD_DIR/src/DontStarveInjector/libInjector.so" \
  )" || die "real libInjector.so not found (build Injector first)"

  # Stub is ~0.7MB; real is tens of MB — never confuse them.
  src_stub="$(_first_existing \
    "$mod_root/bin64/linux/lib64/libInjector.so" \
    "$BUILD_DIR/src/DontStarveInjector/Debug/stub/libInjector.so" \
    "$BUILD_DIR/src/DontStarveInjector/stub/libInjector.so" \
  )" || true
  if [[ -z "${src_stub:-}" ]]; then
    die "InjectorStub libInjector.so not found (build InjectorStub / cmake --install)"
  fi
  local stub_sz real_sz
  stub_sz="$(stat -c%s "$src_stub")"
  real_sz="$(stat -c%s "$src_real_inj")"
  if [[ "$stub_sz" -ge "$real_sz" ]]; then
    die "stub candidate looks like real Injector (stub=${stub_sz}B real=${real_sz}B): $src_stub"
  fi

  # --- stage into Mod package (source of truth) ---
  if [[ "$(realpath "$src_real_inj")" != "$(realpath "$mod_root/libInjector.so" 2>/dev/null || echo)" ]]; then
    cp -f "$src_real_inj" "$mod_root/libInjector.so"
  fi
  if [[ "$(realpath "$src_gengc")" != "$(realpath "$mod_deps/liblua51DS_gengc.so" 2>/dev/null || echo)" ]]; then
    cp -f "$src_gengc" "$mod_deps/liblua51DS_gengc.so"
  fi
  if [[ "$(realpath "$src_stub")" != "$(realpath "$mod_root/bin64/linux/lib64/libInjector.so" 2>/dev/null || echo)" ]]; then
    cp -f "$src_stub" "$mod_root/bin64/linux/lib64/libInjector.so"
  fi

  # --- game: stub PRELOAD path only ---
  cp -f "$mod_root/bin64/linux/lib64/libInjector.so" "$lib64/libInjector.so"

  # Drop stale real Injector / VMs previously mirrored into game bin64.
  rm -f \
    "$bin64/libInjector.so" \
    "$lib64/liblua51DS_gengc.so" \
    "$lib64/liblua51DS.so" \
    "$lib64/liblua51DS_arenagc.so" \
    "$lib64/liblua51Original.so" \
    "$bin64/liblua51DS_gengc.so" \
    "$bin64/signatures_server.json" \
    "$bin64/signatures_client.json"

  # Marker: bootstrap loads real Injector from this absolute path.
  local real_abs
  real_abs="$(realpath "$mod_root/libInjector.so")"
  printf '%s\n' "$real_abs" >"$marker_dir/ds_luajit_injector.path"

  {
    echo "mod_root=$mod_root"
    echo "real_injector=$real_abs"
    echo "stub=$mod_root/bin64/linux/lib64/libInjector.so -> $lib64/libInjector.so"
    echo "gengc=$mod_deps/liblua51DS_gengc.so"
    echo "marker=$marker_dir/ds_luajit_injector.path"
  } >"$EVIDENCE_DIR/deployed-layout.txt"
  {
    sha256sum "$mod_deps/liblua51DS_gengc.so"
    sha256sum "$mod_root/libInjector.so"
    sha256sum "$lib64/libInjector.so"
  } >"$EVIDENCE_DIR/deployed.sha256"
  printf '%s\n' "$mod_deps/liblua51DS_gengc.so" >"$EVIDENCE_DIR/deployed-gengc-src.txt"

  log "deployed layout: real_inj=${real_sz}B stub=${stub_sz}B gengc=$(stat -c%s "$mod_deps/liblua51DS_gengc.so")B marker→$real_abs"
}

kill_leftover_servers() {
  # Only kill dedicated servers for this cluster — never broad pkill -f.
  local pids
  pids="$(pgrep -f "dontstarve_dedicated_server_nullrenderer_x64.*-cluster ${CLUSTER}" 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    log "killing leftover dedicated servers for cluster=$CLUSTER: $pids"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1
    pids="$(pgrep -f "dontstarve_dedicated_server_nullrenderer_x64.*-cluster ${CLUSTER}" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || true
    fi
  fi
}

rss_kb() {
  local pid="$1"
  if [[ -r "/proc/$pid/status" ]]; then
    awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

parse_game_markers() {
  local logf="$1"
  local et="$2"
  local success=0 world=0 jit=0 hard=0 assertn=0 mism=0
  if [[ -f "$logf" ]]; then
    success="$(grep -c 'LOADING LUA SUCCESS' "$logf" 2>/dev/null || true)"
    world="$(grep -c 'World generated' "$logf" 2>/dev/null || true)"
    if grep -qE 'jit_gen|lua_vm_type[=:].*jit_gen|Using.*jit_gen' "$logf" 2>/dev/null; then
      jit=1
    elif grep -q 'jit_gen' "$logf" 2>/dev/null; then
      jit=1
    fi
    hard="$(grep -cE 'ERROR: AddressSanitizer:|heap-use-after-free|use-after-poison|heap-buffer-overflow|double-free|SUMMARY: AddressSanitizer:' "$logf" 2>/dev/null || true)"
    assertn="$(grep -cE 'LuaJIT ASSERT|LJ_ASSERT|assertion failed' "$logf" 2>/dev/null || true)"
    mism="$(grep -c 'alloc-dealloc-mismatch' "$logf" 2>/dev/null || true)"
  fi
  # normalize empty
  success=${success:-0}; world=${world:-0}; hard=${hard:-0}; assertn=${assertn:-0}; mism=${mism:-0}

  {
    echo "## Game ASAN smoke"
    echo
    echo "| Marker | Value |"
    echo "|---|---|"
    echo "| et_sec | $et |"
    echo "| LOADING LUA SUCCESS | $success |"
    echo "| World generated | $world |"
    echo "| jit_gen seen | $jit |"
    echo "| ASAN hard error | $hard |"
    echo "| LuaJIT ASSERT | $assertn |"
    echo "| alloc-dealloc-mismatch count | $mism (ignored if no GC frames) |"
    echo "| log | \`$logf\` |"
  } | tee "$EVIDENCE_DIR/game-markers.md"

  # PASS: SUCCESS + zero hard ASAN + zero ASSERT
  if [[ "$success" -ge 1 && "$hard" -eq 0 && "$assertn" -eq 0 ]]; then
    log "GAME PASS (SUCCESS=$success ASAN_hard=$hard ASSERT=$assertn world=$world jit=$jit et=${et}s)"
    GAME_PASS=1
    return 0
  fi
  log "GAME FAIL (SUCCESS=$success ASAN_hard=$hard ASSERT=$assertn world=$world jit=$jit et=${et}s)"
  GAME_FAIL=1
  return 1
}

run_game_smoke() {
  log "=== Lane 3: ASAN dedicated server smoke ==="
  require_asan_lib

  local game_root
  game_root="$(resolve_game_root)" || die "GAME_ROOT not found (set GAME_ROOT or fix .vscode/settings.json steam.root)"
  [[ -d "$game_root/bin64" ]] || die "invalid GAME_ROOT (no bin64): $game_root"

  local bin="$game_root/bin64/dontstarve_dedicated_server_nullrenderer_x64"
  [[ -x "$bin" ]] || die "missing dedicated server binary: $bin"

  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    run_cmake_asan_build
  else
    log "skip-build: deploy existing artifacts only"
  fi
  deploy_to_game "$game_root"
  kill_leftover_servers

  local game_log="$EVIDENCE_DIR/dst-asan-master.log"
  : >"$game_log"
  local rss_limit_kb=$((RSS_LIMIT_GB * 1024 * 1024))
  local start_ts end_ts et pid
  start_ts="$(date +%s)"

  (
    cd "$game_root/bin64"
    export lua_vm_type="$LUA_VM_TYPE"
    export ASAN_OPTIONS="$ASAN_OPTIONS_GAME"
    export LD_PRELOAD="${ASAN_LIB}:./lib64/libInjector.so"
    export LD_LIBRARY_PATH="./lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    exec ./dontstarve_dedicated_server_nullrenderer_x64 -cluster "$CLUSTER" -shard "$SHARD"
  ) >>"$game_log" 2>&1 &
  pid=$!
  echo "$pid" >"$EVIDENCE_DIR/server.pid"
  log "server pid=$pid log=$game_log"

  local met_success=0 met_world=0 stop_reason=""
  while kill -0 "$pid" 2>/dev/null; do
    et=$(( $(date +%s) - start_ts ))
    local rss
    rss="$(rss_kb "$pid")"
    if [[ "$rss" -gt "$rss_limit_kb" ]]; then
      stop_reason="RSS>${RSS_LIMIT_GB}GB (${rss}kB)"
      log "killing server: $stop_reason"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    if [[ "$et" -ge "$GAME_TIMEOUT_SEC" ]]; then
      stop_reason="timeout ${GAME_TIMEOUT_SEC}s"
      log "killing server: $stop_reason"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    if grep -q 'LOADING LUA SUCCESS' "$game_log" 2>/dev/null; then
      met_success=1
    fi
    if grep -q 'World generated' "$game_log" 2>/dev/null; then
      met_world=1
    fi
    if [[ "$met_success" -eq 1 && "$met_world" -eq 1 ]]; then
      if [[ "$SOAK_SEC" -gt 0 ]]; then
        log "markers met (SUCCESS+World); soak ${SOAK_SEC}s"
        sleep "$SOAK_SEC"
      else
        log "markers met (SUCCESS+World); stopping after ${et}s (soak=0)"
      fi
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    sleep 2
  done

  wait "$pid" 2>/dev/null || true
  end_ts="$(date +%s)"
  et=$(( end_ts - start_ts ))
  parse_game_markers "$game_log" "$et" || true
}

write_summary() {
  local verdict="FAIL"
  local suite_ok=0 game_ok=0
  if [[ "$MODE_SUITE" -eq 0 || "$SUITE_FAIL" -eq 0 ]]; then suite_ok=1; fi
  if [[ "$MODE_GAME" -eq 0 || "$GAME_PASS" -eq 1 ]]; then game_ok=1; fi
  if [[ "$suite_ok" -eq 1 && "$game_ok" -eq 1 ]]; then verdict="PASS"; fi

  {
    echo "# debug+ASAN run $ts"
    echo
    echo "- repo: \`$REPO_ROOT\`"
    echo "- evidence: \`$EVIDENCE_DIR\`"
    echo "- ASAN_LIB: \`$ASAN_LIB\`"
    echo "- LUA_VM_TYPE: \`$LUA_VM_TYPE\`"
    echo
    if [[ "$MODE_SUITE" -eq 1 ]]; then
      echo "## Suite"
      echo
      echo "| pass | fail |"
      echo "|---|---|"
      echo "| $SUITE_PASS | $SUITE_FAIL |"
      echo
    fi
    if [[ "$MODE_GAME" -eq 1 ]]; then
      echo "## Game"
      echo
      echo "| pass | fail |"
      echo "|---|---|"
      echo "| $GAME_PASS | $GAME_FAIL |"
      echo
    fi
    echo "## Verdict"
    echo
    echo "**$verdict**"
  } | tee "$SUMMARY"
  log "summary -> $SUMMARY"
  [[ "$verdict" == "PASS" ]]
}

main() {
  log "REPO_ROOT=$REPO_ROOT"
  log "EVIDENCE_DIR=$EVIDENCE_DIR"
  log "ASAN_LIB=$ASAN_LIB"

  local rc=0
  if [[ "$MODE_SUITE" -eq 1 ]]; then
    run_suite_build
    run_suite || rc=1
  fi
  if [[ "$MODE_GAME" -eq 1 ]]; then
    # Lane order in logs historically printed Lane 3 banner then Lane 2 build —
    # keep build-inside-game for --game-only; when both lanes run, suite first.
    run_game_smoke || rc=1
  fi
  write_summary || rc=1
  exit "$rc"
}

main "$@"
