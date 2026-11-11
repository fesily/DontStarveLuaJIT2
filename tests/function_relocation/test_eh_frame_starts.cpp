#include "NucleusAdapter.hpp"
#include "MemorySignature.hpp"
#include "GraphSeed.hpp"
#include "ModuleSections.hpp"
#include "support/fr_context_env.hpp"

#include <doctest/doctest.h>

#include <dlfcn.h>

#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using function_relocation::nucleus_analyze_file;

namespace {

    // Closes a dlopen handle on scope exit; close() reports the dlclose result.
    struct DlHandle {
        void *handle = nullptr;

        ~DlHandle() {
            if (handle != nullptr) dlclose(handle);
        }

        int close() {
            void *open = handle;
            handle = nullptr;
            return dlclose(open);
        }
    };

}// namespace

static std::filesystem::path repo_lua51_so() {
  std::filesystem::path p = "Mod/deps/liblua51.so";
  if (std::filesystem::exists(p)) {
    return p;
  }
  p = std::filesystem::path{".."} / "Mod" / "deps" / "liblua51.so";
  if (std::filesystem::exists(p)) {
    return p;
  }
  return "Mod/deps/liblua51.so";
}

static uint64_t elf_dynsym_value(const std::filesystem::path &path, const char *name) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(static_cast<bool>(f));
  std::vector<char> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  REQUIRE_GT(data.size(), 64);
  REQUIRE_EQ(data[0], 0x7f);
  REQUIRE_EQ(data[1], 'E');
  REQUIRE_EQ(data[2], 'L');
  REQUIRE_EQ(data[3], 'F');
  REQUIRE_EQ(data[4], 2); // ELF64

  auto rd16 = [&](size_t off) -> uint16_t {
    uint16_t v;
    std::memcpy(&v, data.data() + off, 2);
    return v;
  };
  auto rd32 = [&](size_t off) -> uint32_t {
    uint32_t v;
    std::memcpy(&v, data.data() + off, 4);
    return v;
  };
  auto rd64 = [&](size_t off) -> uint64_t {
    uint64_t v;
    std::memcpy(&v, data.data() + off, 8);
    return v;
  };

  const uint64_t e_shoff = rd64(40);
  const uint16_t e_shentsize = rd16(58);
  const uint16_t e_shnum = rd16(60);
  REQUIRE_GE(e_shentsize, 64);
  REQUIRE(e_shoff + static_cast<uint64_t>(e_shnum) * e_shentsize <= data.size());

  uint64_t dynsym_off = 0, dynsym_size = 0, dynsym_entsize = 0;
  uint32_t dynsym_link = 0;
  for (uint16_t i = 0; i < e_shnum; ++i) {
    const size_t sh = static_cast<size_t>(e_shoff) + static_cast<size_t>(i) * e_shentsize;
    const uint32_t type = rd32(sh + 4);
    if (type != 11) { // SHT_DYNSYM
      continue;
    }
    dynsym_off = rd64(sh + 24);
    dynsym_size = rd64(sh + 32);
    dynsym_link = rd32(sh + 40);
    dynsym_entsize = rd64(sh + 56);
    break;
  }
  REQUIRE_NE(dynsym_off, 0);
  REQUIRE_GE(dynsym_entsize, 24);
  REQUIRE_LT(dynsym_link, e_shnum);

  const size_t str_sh = static_cast<size_t>(e_shoff) + static_cast<size_t>(dynsym_link) * e_shentsize;
  const uint64_t str_off = rd64(str_sh + 24);
  const uint64_t str_size = rd64(str_sh + 32);
  REQUIRE_LE(str_off + str_size, data.size());
  const char *strtab = data.data() + str_off;

  const size_t n = static_cast<size_t>(dynsym_size / dynsym_entsize);
  for (size_t i = 0; i < n; ++i) {
    const size_t rec = static_cast<size_t>(dynsym_off) + i * static_cast<size_t>(dynsym_entsize);
    const uint32_t st_name = rd32(rec);
    const uint8_t st_info = static_cast<uint8_t>(data[rec + 4]);
    const uint64_t st_value = rd64(rec + 8);
    if ((st_info & 0xf) != 2) { // STT_FUNC
      continue;
    }
    if (st_name >= str_size) {
      continue;
    }
    if (std::strcmp(strtab + st_name, name) == 0) {
      return st_value;
    }
  }
  return 0;
}

TEST_CASE("test_eh_frame_starts/lua51_dump_yield_are_span_starts") {
  REQUIRE(ensure_reloc_context());
  auto path = repo_lua51_so();
  if (!std::filesystem::exists(path)) {
    std::fprintf(stderr, "FAIL missing %s\n", path.string().c_str());
  }
  REQUIRE(std::filesystem::exists(path));
  const uint64_t dump_va = elf_dynsym_value(path, "lua_dump");
  const uint64_t yield_va = elf_dynsym_value(path, "lua_yield");
  REQUIRE_NE(dump_va, 0);
  REQUIRE_NE(yield_va, 0);
  REQUIRE_NE(dump_va, yield_va);

  auto res = nucleus_analyze_file(path);
  if (!res) {
    std::fprintf(stderr, "nucleus_analyze_file failed: %s\n", res.error().c_str());
  }
  REQUIRE(static_cast<bool>(res));
  REQUIRE(res->table.containing(dump_va) == dump_va);
  REQUIRE(res->table.containing(yield_va) == yield_va);
  auto *sp_dump = res->table.span_containing(dump_va);
  auto *sp_yield = res->table.span_containing(yield_va);
  REQUIRE_NE(sp_dump, nullptr);
  REQUIRE_NE(sp_yield, nullptr);
  REQUIRE(sp_dump->start != sp_yield->start);
  REQUIRE(sp_dump->end <= dump_va + 0x80);

  std::printf("lua_dump: va=0x%llx end=0x%llx size=0x%llx functions=%zu\n",
              static_cast<unsigned long long>(dump_va),
              static_cast<unsigned long long>(sp_dump->end),
              static_cast<unsigned long long>(sp_dump->end - sp_dump->start),
              res->table.size());
  std::printf("lua_yield: va=0x%llx end=0x%llx size=0x%llx\n",
              static_cast<unsigned long long>(yield_va),
              static_cast<unsigned long long>(sp_yield->end),
              static_cast<unsigned long long>(sp_yield->end - sp_yield->start));
}

static void test_loaded_pic_lua_call(const std::string &path, void *library) {
    function_relocation::ModuleSections module{};
    REQUIRE(function_relocation::init_module_signature(path.c_str(), 0, module));
    auto table = nucleus_analyze_file(path);
    REQUIRE(table);
    REQUIRE(function_relocation::apply_nucleus_function_table(module, table->table, table->image_base));
    const auto caller = reinterpret_cast<uintptr_t>(dlsym(library, "luaL_checklstring"));
    const auto callee = reinterpret_cast<uintptr_t>(dlsym(library, "lua_tolstring"));
    REQUIRE_NE(caller, 0);
    REQUIRE_NE(callee, 0);
    auto *fn = module.find_function(caller);
    REQUIRE_NE(fn, nullptr);
    REQUIRE(fn->size != 0);
    const auto raw = function_relocation::collect_rel32_call_targets(caller, fn->size);
    const auto resolved = function_relocation::collect_rel32_call_targets(module, caller, fn->size);
    REQUIRE_EQ(raw.size(), resolved.size());
    bool saw_plt_call = false;
    for (size_t i = 0; i < raw.size(); ++i) saw_plt_call |= module.in_plt(raw[i]) && resolved[i] == callee;
    REQUIRE(saw_plt_call);
    REQUIRE(function_relocation::body_calls_entry(module, caller, fn->size, callee));
    REQUIRE(function_relocation::ensure_function_features(*fn));
    bool saw_feature_call = false;
    for (auto address: fn->blocks) {
        const auto &calls = module.address_blocks.at(address)->call_functions;
        saw_feature_call |= std::find(calls.begin(), calls.end(), callee) != calls.end();
    }
    REQUIRE(saw_feature_call);
    std::puts("loaded PIC luaL_checklstring -> lua_tolstring: GraphSeed/body/ScanCtx agree");
}

TEST_CASE("test_eh_frame_starts/loaded_pic_lua_call") {
    REQUIRE(ensure_reloc_context());
    const auto path = std::filesystem::absolute(repo_lua51_so()).string();
    DlHandle library{dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(library.handle, nullptr);
    test_loaded_pic_lua_call(path, library.handle);
    const auto entry = reinterpret_cast<uintptr_t>(dlsym(library.handle, "lua_gettop"));
    REQUIRE_NE(entry, 0);
    function_relocation::MemorySignature signature{"48 8B 47 10 48 2B 47 18", 7};
    signature.log = false;
    const auto raw = signature.scan(path.c_str());
    REQUIRE_NE(raw, 0);
    REQUIRE_EQ(signature.scan_function(path.c_str()), entry);
    REQUIRE_EQ(signature.pattern_offset, 7);
    REQUIRE_EQ(signature.scan(path.c_str()), raw);
    REQUIRE_EQ(library.close(), 0);
}
