#pragma once

#include "FunctionTable.hpp"
#include "export.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

namespace function_relocation {

// Options for on-disk PE/ELF analysis via vendored Nucleus.
struct NucleusAnalyzeOptions {
  // Reserved: when true, log pdata mismatches if a future path supplies them.
  bool log_pdata_crosscheck = false;
};

// Result of nucleus_analyze_file.
//
// VA convention (document once, use everywhere):
//   FunctionTable spans use image virtual addresses:
//     va = image_base + rva
//   matching Nucleus PE loader section VMA and export symbol addresses
//   (pe-parse IterSec/IterExpVA). Prefer preferred ImageBase from the PE
//   optional header (not the process load address).
//
// End is exclusive: start <= addr < end.
struct NucleusAnalyzeResult {
  FunctionTable table;
  uint64_t image_base = 0; // preferred ImageBase (0 if unknown / non-PE)
};

// Analyze a PE/ELF file on disk through stock Nucleus load -> linear disasm ->
// make_cfg. On failure returns an error string (no silent empty success).
FUNCTION_RELOCATION_API
std::expected<NucleusAnalyzeResult, std::string>
nucleus_analyze_file(const std::filesystem::path &path,
                     const NucleusAnalyzeOptions &opt = {});

// Convenience: same as nucleus_analyze_file but returns only the table
// (image_base discarded). Prefer the full result when you need export VAs.
FUNCTION_RELOCATION_API
std::expected<FunctionTable, std::string>
nucleus_analyze_file_table(const std::filesystem::path &path,
                           const NucleusAnalyzeOptions &opt = {});

// Read preferred PE ImageBase without running Nucleus (for export VA = base+rva).
FUNCTION_RELOCATION_API
std::expected<uint64_t, std::string>
pe_image_base(const std::filesystem::path &path);

} // namespace function_relocation
