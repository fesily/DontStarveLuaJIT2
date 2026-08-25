#include "NucleusAdapter.hpp"

#include <cstring>
#include <fstream>
#include <list>
#include <string>
#include <utility>
#include <vector>

// Nucleus stock pipeline (algorithm surface untouched).
#include "cfg.h"
#include "disasm.h"
#include "loader.h"
#include <frida-gum.h>

#include "options.h"

namespace function_relocation {
namespace {

// Infer preferred ImageBase from a loaded Nucleus Binary.
// PE: sections/symbols use image VA (ImageBase + rva). Prefer optional-header
// ImageBase (DST lua51 PE is typically 0x180000000).
// ELF ET_DYN (shared libs / PIE): section VMAs are already load-bias-relative
// (often near 0). process_va = process_base + (image_va - image_base) requires
// image_base == 0; page-aligning the lowest section VMA breaks remapping and
// leaves apply_nucleus_function_table with sized==0.
uint64_t infer_image_base_from_binary(const Binary &bin,
                                      const std::filesystem::path &path) {
  if (bin.type == Binary::BIN_TYPE_PE) {
    auto base = pe_image_base(path);
    if (base) {
      return *base;
    }
    // PE fallback only: page-align lowest section VMA (already ImageBase+RVA).
    if (!bin.sections.empty()) {
      uint64_t lo = bin.sections.front().vma;
      for (const auto &s : bin.sections) {
        if (s.vma < lo) {
          lo = s.vma;
        }
      }
      return lo & ~uint64_t{0xFFF};
    }
  }
  // ELF: ET_DYN section VMAs are load-bias relative (near 0) → image_base 0.
  // ET_EXEC uses absolute preferred base (DST server is typically 0x400000).
  // process_va = process_base + (image_va - image_base); wrong base empties
  // containing() for many spans and breaks knowns/create (e.g. lua_close).
  if (!bin.sections.empty()) {
    uint64_t lo = bin.sections.front().vma;
    for (const auto &s : bin.sections) {
      if (s.vma < lo) {
        lo = s.vma;
      }
    }
    // Heuristic: absolute preferred bases are page-aligned and not near 0.
    if (lo >= 0x10000) {
      return lo & ~uint64_t{0xFFF};
    }
  }
  return 0;
}

std::expected<std::string, std::string>
path_to_utf8(const std::filesystem::path &path) {
  try {
    return path.string();
  } catch (const std::exception &e) {
    return std::unexpected(std::string("path encoding: ") + e.what());
  }
}

} // namespace

std::expected<uint64_t, std::string>
pe_image_base(const std::filesystem::path &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    return std::unexpected("failed to open PE for image_base: " + path.string());
  }
  // DOS header
  char dos[64];
  f.read(dos, 64);
  if (!f || dos[0] != 'M' || dos[1] != 'Z') {
    return std::unexpected("not a PE (missing MZ): " + path.string());
  }
  uint32_t e_lfanew = 0;
  std::memcpy(&e_lfanew, dos + 0x3c, sizeof(e_lfanew));
  f.seekg(e_lfanew);
  char pe_sig[4];
  f.read(pe_sig, 4);
  if (!f || pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0) {
    return std::unexpected("not a PE (missing PE signature): " + path.string());
  }
  // COFF FileHeader (20 bytes) then OptionalHeader Magic
  f.seekg(static_cast<std::streamoff>(e_lfanew) + 4 + 20);
  uint16_t magic = 0;
  f.read(reinterpret_cast<char *>(&magic), sizeof(magic));
  if (!f) {
    return std::unexpected("truncated PE optional header: " + path.string());
  }
  if (magic == 0x20b) {
    // PE32+: ImageBase at optional+24
    f.seekg(static_cast<std::streamoff>(e_lfanew) + 4 + 20 + 24);
    uint64_t image_base = 0;
    f.read(reinterpret_cast<char *>(&image_base), sizeof(image_base));
    if (!f) {
      return std::unexpected("truncated PE32+ ImageBase: " + path.string());
    }
    return image_base;
  }
  if (magic == 0x10b) {
    // PE32: ImageBase at optional+28
    f.seekg(static_cast<std::streamoff>(e_lfanew) + 4 + 20 + 28);
    uint32_t image_base32 = 0;
    f.read(reinterpret_cast<char *>(&image_base32), sizeof(image_base32));
    if (!f) {
      return std::unexpected("truncated PE32 ImageBase: " + path.string());
    }
    return static_cast<uint64_t>(image_base32);
  }
  return std::unexpected("unsupported PE optional magic");
}

std::expected<NucleusAnalyzeResult, std::string>
nucleus_analyze_file(const std::filesystem::path &path,
                     const NucleusAnalyzeOptions & /*opt*/) {
  if (!std::filesystem::exists(path)) {
    return std::unexpected("file not found: " + path.string());
  }

  auto fname_exp = path_to_utf8(path);
  if (!fname_exp) {
    return std::unexpected(fname_exp.error());
  }
  std::string fname = *std::move(fname_exp);

  // Frida Gum Capstone is modular: register arches then init runtime once.
  // Matches function_relocation::init_ctx() (cs_arch_register_x86 + cs_open).
  static bool gum_ready = false;
  if (!gum_ready) {
    gum_init_embedded();
    cs_arch_register_x86();
    gum_ready = true;
  }

  // Ensure linear strategy defaults are live (options_defaults static ctor).
  // bb_score/bb_mutate lazy-load from options.strategy_function.name == "linear".
  if (options.strategy_function.name.empty()) {
    options.strategy_function.name = "linear";
  }
  options.verbosity = 0;
  options.only_code_sections = 1;

  Binary bin;
  if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
    return std::unexpected("nucleus load_binary failed: " + fname);
  }

  NucleusAnalyzeResult out;
  out.image_base = infer_image_base_from_binary(bin, path);

  std::list<DisasmSection> disasm;
  if (nucleus_disasm(&bin, &disasm) < 0) {
    unload_binary(&bin);
    return std::unexpected("nucleus_disasm failed: " + fname);
  }

  CFG cfg;
  if (cfg.make_cfg(&bin, &disasm) < 0) {
    unload_binary(&bin);
    return std::unexpected("nucleus make_cfg failed: " + fname);
  }

  // Map Nucleus Function -> FunctionSpan.
  // Nucleus Function::{start,end}: end is exclusive (from BB::end = first byte
  // past last instruction). Keep as-is so containing uses start <= addr < end.
  for (const auto &f : cfg.functions) {
    if (f.end <= f.start) {
      continue;
    }
    out.table.add(FunctionSpan{f.start, f.end});
  }

  // FUNC-symbol refine: PE .pdata / ELF .eh_frame_hdr / exports that sit
  // strictly inside a parent span become sub-span starts. Without this,
  // containing(lua_dump) snaps to a merged outer body (same class as
  // lua_resume inside lua_yield on Windows).
  {
    std::vector<uint64_t> export_vas;
    export_vas.reserve(bin.symbols.size());
    for (const auto &sym : bin.symbols) {
      if ((sym.type & Symbol::SYM_TYPE_FUNC) != 0 && sym.addr != 0) {
        export_vas.push_back(sym.addr);
      }
    }
    out.table.split_at_known_entries(export_vas);
  }

  unload_binary(&bin);

  if (out.table.empty()) {
    return std::unexpected("nucleus produced empty FunctionTable for " + fname);
  }
  return out;
}

std::expected<FunctionTable, std::string>
nucleus_analyze_file_table(const std::filesystem::path &path,
                           const NucleusAnalyzeOptions &opt) {
  auto res = nucleus_analyze_file(path, opt);
  if (!res) {
    return std::unexpected(res.error());
  }
  return std::move(res->table);
}

} // namespace function_relocation
