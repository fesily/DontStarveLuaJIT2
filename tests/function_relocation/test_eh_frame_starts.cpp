#include "NucleusAdapter.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using function_relocation::nucleus_analyze_file;

#define REQUIRE(cond)                                                                          \
  do {                                                                                         \
    if (!(cond)) {                                                                             \
      std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);        \
      std::abort();                                                                            \
    }                                                                                          \
  } while (0)

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
  REQUIRE(data.size() > 64);
  REQUIRE(data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F');
  REQUIRE(data[4] == 2); // ELF64

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
  REQUIRE(e_shentsize >= 64);
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
  REQUIRE(dynsym_off != 0);
  REQUIRE(dynsym_entsize >= 24);
  REQUIRE(dynsym_link < e_shnum);

  const size_t str_sh = static_cast<size_t>(e_shoff) + static_cast<size_t>(dynsym_link) * e_shentsize;
  const uint64_t str_off = rd64(str_sh + 24);
  const uint64_t str_size = rd64(str_sh + 32);
  REQUIRE(str_off + str_size <= data.size());
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

static void test_lua51_dump_yield_are_span_starts() {
  auto path = repo_lua51_so();
  if (!std::filesystem::exists(path)) {
    std::fprintf(stderr, "FAIL missing %s\n", path.string().c_str());
    std::abort();
  }
  const uint64_t dump_va = elf_dynsym_value(path, "lua_dump");
  const uint64_t yield_va = elf_dynsym_value(path, "lua_yield");
  REQUIRE(dump_va != 0);
  REQUIRE(yield_va != 0);
  REQUIRE(dump_va != yield_va);

  auto res = nucleus_analyze_file(path);
  if (!res) {
    std::fprintf(stderr, "nucleus_analyze_file failed: %s\n", res.error().c_str());
    std::abort();
  }
  REQUIRE(res->table.containing(dump_va) == dump_va);
  REQUIRE(res->table.containing(yield_va) == yield_va);
  auto *sp_dump = res->table.span_containing(dump_va);
  auto *sp_yield = res->table.span_containing(yield_va);
  REQUIRE(sp_dump != nullptr);
  REQUIRE(sp_yield != nullptr);
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

int main() {
  test_lua51_dump_yield_are_span_starts();
  std::puts("test_eh_frame_starts: ok");
  return 0;
}
