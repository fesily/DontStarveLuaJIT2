---
name: steam-linux-binary-toolchain-provenance
description: "Identify compiler/distro/Steam-Runtime provenance of a Linux game binary (.comment, glibc versions, PIE/CET, bundled libs); distinguish scout/soldier/sniper."
---

# Steam/Linux binary toolchain provenance

Use when asked what compiler/distro/Steam-Runtime a Linux game binary was built with, or why a byte signature drifted across game builds.

## Steam Runtime generations (Valve's anti-fragmentation containers; SDK = OCI images at `registry.gitlab.steamos.cloud/steamrt/<name>/sdk`)

| codename | Steam Linux Runtime | base distro | notes |
|---|---|---|---|
| scout | 1.0 | Ubuntu 12.04 | classic native Linux / Deck |
| soldier | 2.0 | Debian 11 | Proton container |
| sniper | 3.0 | Ubuntu 20.04 | modern native Linux |

## Procedure

1. `readelf -h <bin>` → `Type: DYN (PIE)` vs `EXEC`; note compilers with PIE default (Ubuntu >=17.10) emit `ET_DYN`.
2. `readelf -p .comment <bin>` → exact `GCC: (Ubuntu X.Y...) Z` string = compiler + build distro. (If binary only in Ghidra DB: `mcp__ghidra_mcp_search_strings` for `GCC:` or read the `.comment` address space.)
3. `objdump -T <bin> | grep -oE '(GLIBC|GLIBCXX|CXXABI)_[0-9.]+' | sort -uV` → max glibc required. This caps the oldest distro it can run on (e.g. max GLIBC_2.29 cannot run under scout's glibc 2.15).
4. `readelf -n <bin>` → build-id; `objdump -d` for `endbr64` (`f3 0f 1e fa`) = CET/-fcf-protection; `lea reg,[rip+disp]` vs `mov reg,imm32` = PIE vs non-PIE.
5. `strings -a <bin> | grep -aiE 'steam-runtime|scout|soldier|sniper|/build/|/home/'` → leaked build paths.
6. Check launcher script (e.g. `<game>/bin64/dontstarve`) and `<game>/bin64/lib64` (bundled deps → dev manages libs itself, not the runtime).
7. Installed runtime: read `<Steam>/steamapps/common/SteamLinuxRuntime/README.md` + `VERSIONS.txt` + `toolmanifest.vdf`.

## Caveat

`.comment` only records OS + GCC — it does NOT prove the binary was built in Valve's container vs any same-version distro image. State "matches sniper SDK" as inference, not proof.

## Why it matters

Different toolchain (PIE/CET/distro gcc version) reorders codegen → compiler-generated rel8 jump displacements drift across builds → byte signatures with pinned displacement bytes break. Wildcard `jXX` displacement bytes.
