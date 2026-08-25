#include "FunctionTable.hpp"
#include "NucleusAdapter.hpp"

// Keep checks active under RelWithDebInfo (NDEBUG would strip assert).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using function_relocation::FunctionTable;
using function_relocation::nucleus_analyze_file;
using function_relocation::pe_image_base;

#define REQUIRE(cond)                                                                          \
  do {                                                                                         \
    if (!(cond)) {                                                                             \
      std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);        \
      std::abort();                                                                            \
    }                                                                                          \
  } while (0)

static std::filesystem::path repo_lua51() {
  // Prefer Mod/deps/lua51.dll relative to cwd (ctest WORKING_DIRECTORY = source root).
  std::filesystem::path p = "Mod/deps/lua51.dll";
  if (std::filesystem::exists(p)) {
    return p;
  }
  p = std::filesystem::path{".."} / "Mod" / "deps" / "lua51.dll";
  if (std::filesystem::exists(p)) {
    return p;
  }
  // Walk up a few levels from executable if needed.
  return "Mod/deps/lua51.dll";
}

// Minimal PE export RVA lookup by name (no pe-parse dependency in the test).
static uint32_t pe_export_rva(const std::filesystem::path &path, const char *name) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(static_cast<bool>(f));
  std::vector<char> data((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
  REQUIRE(data.size() > 0x40);
  REQUIRE(data[0] == 'M' && data[1] == 'Z');

  auto rd16 = [&](size_t off) -> uint16_t {
    REQUIRE(off + 2 <= data.size());
    uint16_t v;
    std::memcpy(&v, data.data() + off, 2);
    return v;
  };
  auto rd32 = [&](size_t off) -> uint32_t {
    REQUIRE(off + 4 <= data.size());
    uint32_t v;
    std::memcpy(&v, data.data() + off, 4);
    return v;
  };

  const uint32_t e_lfanew = rd32(0x3c);
  REQUIRE(e_lfanew + 24 < data.size());
  REQUIRE(data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E');

  const uint16_t magic = rd16(e_lfanew + 4 + 20);
  REQUIRE(magic == 0x20b); // PE32+ (lua51.dll)

  // DataDirectory[0] = Export Table (RVA, Size) at optional+112 for PE32+.
  const uint32_t export_rva = rd32(e_lfanew + 4 + 20 + 112);
  const uint32_t export_size = rd32(e_lfanew + 4 + 20 + 116);
  REQUIRE(export_rva != 0);
  (void)export_size;

  // Map RVA -> file offset via section headers.
  const uint16_t nsec = rd16(e_lfanew + 4 + 2);
  const uint16_t opt_size = rd16(e_lfanew + 4 + 16);
  const size_t sec_off = static_cast<size_t>(e_lfanew) + 4 + 20 + opt_size;

  auto rva_to_off = [&](uint32_t rva) -> size_t {
    for (uint16_t i = 0; i < nsec; ++i) {
      const size_t sh = sec_off + static_cast<size_t>(i) * 40;
      const uint32_t vsize = rd32(sh + 8);
      const uint32_t va = rd32(sh + 12);
      const uint32_t raw_size = rd32(sh + 16);
      const uint32_t raw_ptr = rd32(sh + 20);
      const uint32_t span = vsize > raw_size ? vsize : raw_size;
      if (rva >= va && rva < va + span) {
        return static_cast<size_t>(raw_ptr) + (rva - va);
      }
    }
    return static_cast<size_t>(-1);
  };

  const size_t exp_off = rva_to_off(export_rva);
  REQUIRE(exp_off != static_cast<size_t>(-1));
  // IMAGE_EXPORT_DIRECTORY
  const uint32_t n_names = rd32(exp_off + 24);
  const uint32_t addr_of_funcs = rd32(exp_off + 28);
  const uint32_t addr_of_names = rd32(exp_off + 32);
  const uint32_t addr_of_ords = rd32(exp_off + 36);

  const size_t names_off = rva_to_off(addr_of_names);
  const size_t ords_off = rva_to_off(addr_of_ords);
  const size_t funcs_off = rva_to_off(addr_of_funcs);
  REQUIRE(names_off != static_cast<size_t>(-1));
  REQUIRE(ords_off != static_cast<size_t>(-1));
  REQUIRE(funcs_off != static_cast<size_t>(-1));

  for (uint32_t i = 0; i < n_names; ++i) {
    const uint32_t name_rva = rd32(names_off + i * 4);
    const size_t name_off = rva_to_off(name_rva);
    if (name_off == static_cast<size_t>(-1)) {
      continue;
    }
    const char *s = data.data() + name_off;
    if (std::strcmp(s, name) != 0) {
      continue;
    }
    const uint16_t ord = rd16(ords_off + i * 2);
    return rd32(funcs_off + static_cast<size_t>(ord) * 4);
  }
  return 0;
}

static void test_table_containing_unit() {
  FunctionTable t;
  t.add({0x1000, 0x1100});
  t.add({0x2000, 0x2200});
  REQUIRE(t.containing(0x1000) == 0x1000);
  REQUIRE(t.containing(0x10ff) == 0x1000);
  REQUIRE(t.containing(0x1100) == 0);
  REQUIRE(t.containing(0x2100) == 0x2000);
  REQUIRE(t.containing(0x50) == 0);
  REQUIRE(t.span_containing(0x10ff) != nullptr);
  REQUIRE(t.span_containing(0x10ff)->end == 0x1100);

  // Nested spans with a dedicated interior entry span.
  FunctionTable nested;
  nested.add({0xad60, 0xb5ae}); // outer (e.g. pre-split yield body)
  nested.add({0xae30, 0xaf31}); // sibling inside outer
  nested.add({0xb4f0, 0xb54a}); // tight resume body
  REQUIRE(nested.containing(0xb4f0) == 0xb4f0);
  REQUIRE(nested.span_containing(0xb4f0)->end == 0xb54a);

  // Export-aware split: interior export VAs become sub-span starts.
  FunctionTable only_outer;
  only_outer.add({0xad60, 0xb5ae});
  only_outer.add({0xae30, 0xaf31});
  only_outer.split_at_known_entries({0xade0, 0xb4f0}); // yield, resume
  REQUIRE(only_outer.containing(0xb4f0) == 0xb4f0);
  REQUIRE(only_outer.span_containing(0xb4f0)->start == 0xb4f0);
  REQUIRE(only_outer.span_containing(0xb4f0)->end == 0xb5ae);
  REQUIRE(only_outer.containing(0xade0) == 0xade0);
  REQUIRE(only_outer.span_containing(0xade0)->end == 0xb4f0);
  // Size for interior export E is End-E, not End-S.
  REQUIRE(only_outer.span_containing(0xb4f0)->end - 0xb4f0 == 0xb5ae - 0xb4f0);
}

static void test_lua51_getstack_span() {
  auto path = repo_lua51();
  if (!std::filesystem::exists(path)) {
    std::printf("FAIL test_lua51_getstack_span: missing %s\n", path.string().c_str());
    std::abort();
  }

  auto res = nucleus_analyze_file(path);
  if (!res) {
    std::fprintf(stderr, "nucleus_analyze_file failed: %s\n", res.error().c_str());
    std::abort();
  }
  const auto &table = res->table;
  REQUIRE(!table.empty());

  const uint32_t exp_rva = pe_export_rva(path, "lua_getstack");
  REQUIRE(exp_rva != 0);

  // VA convention: image VA = preferred ImageBase + export RVA (same as Nucleus).
  uint64_t image_base = res->image_base;
  if (image_base == 0) {
    auto base = pe_image_base(path);
    REQUIRE(base.has_value());
    image_base = *base;
  }
  const uint64_t getstack_va = image_base + exp_rva;

  const uint64_t entry = table.containing(getstack_va);
  REQUIRE(entry != 0);
  auto *sp = table.span_containing(getstack_va);
  REQUIRE(sp != nullptr);
  REQUIRE(sp->end > sp->start);
  REQUIRE(getstack_va >= sp->start);
  REQUIRE(getstack_va < sp->end);

  const uint64_t span_size = sp->end - sp->start;
  // Body must be much smaller than next-export gap (~0x150). Soft gate < 0x120.
  if (span_size >= 0x120) {
    std::fprintf(stderr,
                 "getstack span too large: start=0x%llx end=0x%llx size=0x%llx "
                 "(va=0x%llx rva=0x%x base=0x%llx functions=%zu)\n",
                 static_cast<unsigned long long>(sp->start),
                 static_cast<unsigned long long>(sp->end),
                 static_cast<unsigned long long>(span_size),
                 static_cast<unsigned long long>(getstack_va), exp_rva,
                 static_cast<unsigned long long>(image_base), table.size());
  }
  REQUIRE(span_size < 0x120);

  std::printf("lua_getstack: va=0x%llx entry=0x%llx end=0x%llx size=0x%llx "
              "functions=%zu image_base=0x%llx\n",
              static_cast<unsigned long long>(getstack_va),
              static_cast<unsigned long long>(entry),
              static_cast<unsigned long long>(sp->end),
              static_cast<unsigned long long>(span_size), table.size(),
              static_cast<unsigned long long>(image_base));
}

static void test_lua51_resume_containing() {
  auto path = repo_lua51();
  if (!std::filesystem::exists(path)) {
    std::printf("FAIL test_lua51_resume_containing: missing %s\n", path.string().c_str());
    std::abort();
  }
  auto res = nucleus_analyze_file(path);
  REQUIRE(res.has_value());
  uint64_t image_base = res->image_base;
  if (image_base == 0) {
    auto base = pe_image_base(path);
    REQUIRE(base.has_value());
    image_base = *base;
  }

  const uint32_t resume_rva = pe_export_rva(path, "lua_resume");
  const uint32_t yield_rva = pe_export_rva(path, "lua_yield");
  REQUIRE(resume_rva != 0);
  REQUIRE(yield_rva != 0);
  REQUIRE(resume_rva != yield_rva);

  const uint64_t resume_va = image_base + resume_rva;
  const uint64_t yield_va = image_base + yield_rva;

  auto *sp_resume = res->table.span_containing(resume_va);
  auto *sp_yield = res->table.span_containing(yield_va);
  REQUIRE(sp_resume != nullptr);
  REQUIRE(sp_yield != nullptr);
  // Export-aware split: each export is its own span start (not outer entry).
  REQUIRE(sp_resume->start == resume_va);
  REQUIRE(sp_yield->start == yield_va);
  REQUIRE(sp_resume->start != sp_yield->start);
  REQUIRE(resume_va < sp_resume->end);
  REQUIRE(yield_va < sp_yield->end);

  std::printf("lua_resume: va=0x%llx entry=0x%llx end=0x%llx size=0x%llx\n",
              static_cast<unsigned long long>(resume_va),
              static_cast<unsigned long long>(sp_resume->start),
              static_cast<unsigned long long>(sp_resume->end),
              static_cast<unsigned long long>(sp_resume->end - sp_resume->start));
  std::printf("lua_yield: va=0x%llx entry=0x%llx end=0x%llx size=0x%llx\n",
              static_cast<unsigned long long>(yield_va),
              static_cast<unsigned long long>(sp_yield->start),
              static_cast<unsigned long long>(sp_yield->end),
              static_cast<unsigned long long>(sp_yield->end - sp_yield->start));
}

// x64 .pdata BeginAddress RVAs that are real function starts (skip chained
// unwind fragments). Linux Nucleus equivalent is ELF FUNC symbols / eh_frame.
static std::vector<uint32_t> pe_pdata_begin_rvas(const std::filesystem::path &path) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(static_cast<bool>(f));
  std::vector<char> data((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
  auto rd16 = [&](size_t off) -> uint16_t {
    REQUIRE(off + 2 <= data.size());
    uint16_t v;
    std::memcpy(&v, data.data() + off, 2);
    return v;
  };
  auto rd32 = [&](size_t off) -> uint32_t {
    REQUIRE(off + 4 <= data.size());
    uint32_t v;
    std::memcpy(&v, data.data() + off, 4);
    return v;
  };
  const uint32_t e_lfanew = rd32(0x3c);
  REQUIRE(data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E');
  const uint16_t magic = rd16(e_lfanew + 4 + 20);
  REQUIRE(magic == 0x20b);
  const uint32_t pdata_rva = rd32(e_lfanew + 4 + 20 + 112 + 3 * 8);
  const uint32_t pdata_size = rd32(e_lfanew + 4 + 20 + 116 + 3 * 8);
  REQUIRE(pdata_rva != 0);
  REQUIRE(pdata_size >= 12);

  const uint16_t nsec = rd16(e_lfanew + 4 + 2);
  const uint16_t opt_size = rd16(e_lfanew + 4 + 16);
  const size_t sec_off = static_cast<size_t>(e_lfanew) + 4 + 20 + opt_size;
  auto rva_to_off = [&](uint32_t rva) -> size_t {
    for (uint16_t i = 0; i < nsec; ++i) {
      const size_t sh = sec_off + static_cast<size_t>(i) * 40;
      const uint32_t vsize = rd32(sh + 8);
      const uint32_t va = rd32(sh + 12);
      const uint32_t raw_size = rd32(sh + 16);
      const uint32_t raw_ptr = rd32(sh + 20);
      const uint32_t span = vsize > raw_size ? vsize : raw_size;
      if (rva >= va && rva < va + span) {
        return static_cast<size_t>(raw_ptr) + (rva - va);
      }
    }
    return static_cast<size_t>(-1);
  };

  const size_t pdata_off = rva_to_off(pdata_rva);
  REQUIRE(pdata_off != static_cast<size_t>(-1));
  const size_t n = pdata_size / 12;
  std::vector<uint32_t> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    const size_t rec = pdata_off + i * 12;
    if (rec + 12 > data.size()) {
      break;
    }
    const uint32_t begin = rd32(rec);
    const uint32_t end = rd32(rec + 4);
    const uint32_t unwind = rd32(rec + 8);
    if (begin == 0 || end <= begin) {
      continue;
    }
    if (unwind != 0) {
      const size_t uoff = rva_to_off(unwind);
      if (uoff != static_cast<size_t>(-1) && uoff < data.size()) {
        const unsigned flags = (static_cast<unsigned char>(data[uoff]) >> 3) & 0x1f;
        if (flags & 0x4) {
          continue; // UNW_FLAG_CHAININFO: continuation, not a function entry
        }
      }
    }
    out.push_back(begin);
  }
  REQUIRE(!out.empty());
  return out;
}

static void test_lua51_pdata_starts_are_span_entries() {
  auto path = repo_lua51();
  REQUIRE(std::filesystem::exists(path));
  auto res = nucleus_analyze_file(path);
  if (!res) {
    std::fprintf(stderr, "nucleus_analyze_file failed: %s\n", res.error().c_str());
    std::abort();
  }
  uint64_t image_base = res->image_base;
  if (image_base == 0) {
    auto base = pe_image_base(path);
    REQUIRE(base.has_value());
    image_base = *base;
  }
  const auto begins = pe_pdata_begin_rvas(path);
  size_t miss = 0;
  uint32_t first_miss = 0;
  for (uint32_t rva: begins) {
    const uint64_t va = image_base + rva;
    const uint64_t entry = res->table.containing(va);
    if (entry != va) {
      if (miss == 0) {
        first_miss = rva;
      }
      ++miss;
    }
  }
  const uint32_t isn = pe_export_rva(path, "lua_isnumber");
  const uint32_t toi = pe_export_rva(path, "lua_tointeger");
  REQUIRE(isn != 0);
  REQUIRE(toi != 0);
  REQUIRE(res->table.containing(image_base + isn) == image_base + isn);
  REQUIRE(res->table.containing(image_base + toi) == image_base + toi);

  std::printf("pdata starts=%zu nucleus_miss=%zu functions=%zu first_miss_rva=0x%x\n",
              begins.size(), miss, res->table.size(), first_miss);
  // Windows function starts live in .pdata, not PE exports. Every non-chained
  // pdata BeginAddress must be a FunctionTable span start.
  REQUIRE(miss == 0);
}


int main() {
  test_table_containing_unit();
  test_lua51_getstack_span();
  test_lua51_resume_containing();
  test_lua51_pdata_starts_are_span_entries();
  std::puts("test_nucleus_adapter: ok");
  return 0;
}
