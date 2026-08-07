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
// PE sections/symbols already use image VA (image_base + rva). For PE we recover
// ImageBase as the greatest power-of-two base that is a lower bound of every
// section VMA and entry; for the DST lua51 path ImageBase is 0x180000000.
// Simpler + exact: re-read PE optional header via pe_image_base when type is PE.
uint64_t infer_image_base_from_binary(const Binary &bin,
                                      const std::filesystem::path &path) {
  if (bin.type == Binary::BIN_TYPE_PE) {
    auto base = pe_image_base(path);
    if (base) {
      return *base;
    }
  }
  // Fallback: lowest section VMA rounded down is unreliable; use 0 for RVA space.
  if (!bin.sections.empty()) {
    uint64_t lo = bin.sections.front().vma;
    for (const auto &s : bin.sections) {
      if (s.vma < lo) {
        lo = s.vma;
      }
    }
    // Common PE preferred bases: if entry and sections share a high base, keep it.
    return lo & ~uint64_t{0xFFF}; // page-align down of lowest section (best effort)
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
