#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <string>
#include <vector>

#include "log.h"
#include "options.h"
#include "loader.h"

#if defined(NUCLEUS_LOADER_PE_PARSE)
#include <pe-parse/parse.h>
#elif !defined(NUCLEUS_LOADER_NO_BFD)
#include <bfd.h>
#include <map>
#endif

const char *binary_types_descr[][2] = {
  {"auto", "Try to automatically determine binary format (default)"},
  {"raw" , "Raw binary (memory dump, ROM, network capture, ...)"},
  {"elf" , "Unix ELF"},
  {"pe"  , "Windows PE"},
  {NULL  , NULL}
};

const char *binary_arch_descr[][2] = {
  {"auto"    , "Try to automatically determine architecture (default)"},
  {"aarch64" , "aarch64 (experimental)"},
  {"arm"     , "arm (experimental)"},
  {"mips"    , "mips (experimental)"},
  {"ppc"     , "ppc: Specify ppc-32 or ppc-64 (default ppc-64, experimental)"},
  {"x86"     , "x86: Specify x86-16, x86-32 or x86-64 (default x86-64)"},
  {NULL      , NULL}
};


#if defined(NUCLEUS_LOADER_PE_PARSE)

/* Engineering surface: PE fill via pe-parse (no libbfd on Windows). */

struct PeSectionFillCtx {
  Binary *bin;
  int fail;
};

static int
pe_section_cb(void *user, const peparse::VA &secBase, const std::string &secName,
              const peparse::image_section_header &s,
              const peparse::bounded_buffer *data)
{
  auto *ctx = static_cast<PeSectionFillCtx *>(user);
  if (ctx->fail) {
    return 0;
  }

  const std::uint32_t chars = s.Characteristics;
  int sectype = Section::SEC_TYPE_NONE;
  if (chars & peparse::IMAGE_SCN_MEM_EXECUTE) {
    sectype = Section::SEC_TYPE_CODE;
  } else if ((chars & peparse::IMAGE_SCN_CNT_CODE) &&
             (chars & peparse::IMAGE_SCN_MEM_READ)) {
    sectype = Section::SEC_TYPE_CODE;
  } else if ((chars & peparse::IMAGE_SCN_MEM_READ) ||
             (chars & peparse::IMAGE_SCN_CNT_INITIALIZED_DATA) ||
             (chars & peparse::IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
    sectype = Section::SEC_TYPE_DATA;
  } else {
    return 0;
  }

  /* Prefer VirtualSize (in-memory). Fall back to raw size when VS is 0. */
  uint64_t size = s.Misc.VirtualSize;
  if (size == 0) {
    size = s.SizeOfRawData;
  }
  if (size == 0) {
    return 0;
  }

  const uint64_t raw_len =
      (data && data->buf) ? static_cast<uint64_t>(data->bufLen) : 0ULL;
  const uint64_t copy_n = size < raw_len ? size : raw_len;

  uint8_t *bytes = static_cast<uint8_t *>(calloc(1, static_cast<size_t>(size)));
  if (!bytes) {
    print_err("out of memory");
    ctx->fail = 1;
    return 0;
  }
  if (copy_n > 0) {
    memcpy(bytes, data->buf, static_cast<size_t>(copy_n));
  }
  /* Remainder size-copy_n already zero from calloc (VirtualSize > raw). */

  ctx->bin->sections.push_back(Section());
  Section *sec = &ctx->bin->sections.back();
  sec->binary  = ctx->bin;
  sec->name    = secName.empty() ? std::string("<unnamed>") : secName;
  sec->type    = static_cast<unsigned>(sectype);
  /* pe-parse IterSec secBase is already image VA (image_base + RVA). */
  sec->vma     = static_cast<uint64_t>(secBase);
  sec->size    = size;
  sec->bytes   = bytes;
  return 0;
}


static int
pe_export_cb(void *user, const peparse::VA &va, const std::string & /*mod*/,
             const std::string &func)
{
  auto *binp = static_cast<Binary *>(user);
  if (va == 0 || func.empty()) {
    return 0;
  }
  binp->symbols.push_back(Symbol());
  Symbol *sym = &binp->symbols.back();
  sym->type   = Symbol::SYM_TYPE_FUNC;
  sym->name   = func;
  sym->addr   = static_cast<uint64_t>(va);
  return 0;
}

static int
pe_va_in_code(Binary *bin, uint64_t va)
{
  for (auto &sec: bin->sections) {
    if (sec.type == Section::SEC_TYPE_CODE && sec.contains(va)) {
      return 1;
    }
  }
  return 0;
}

static void
pe_add_func_symbol(Binary *bin, uint64_t va, const char *name)
{
  if (va == 0) {
    return;
  }
  for (auto &s: bin->symbols) {
    if (s.addr == va && (s.type & Symbol::SYM_TYPE_FUNC)) {
      return;
    }
  }
  bin->symbols.push_back(Symbol());
  Symbol *sym = &bin->symbols.back();
  sym->type = Symbol::SYM_TYPE_FUNC;
  if (name && *name) {
    sym->name = name;
  }
  sym->addr = va;
}

/* x64 .pdata is the Windows analogue of ELF FUNC symbols / eh_frame starts.
 * Recursive/linear CFG still groups by CALL; split_at_known_entries (and
 * recursive BB seeds) consume these SYM_TYPE_FUNC addresses. Skip chained
 * unwind fragments (UNW_FLAG_CHAININFO) — those are continuations, not entries. */
static void
pe_load_pdata_symbols(peparse::parsed_pe *pe, Binary *bin, uint64_t image_base)
{
  if (bin->bits != 64) {
    return;
  }
  std::vector<std::uint8_t> raw;
  if (!peparse::GetDataDirectoryEntry(pe, peparse::DIR_EXCEPTION, raw) ||
      raw.size() < 12) {
    return;
  }
  const size_t n = raw.size() / 12;
  size_t added = 0;
  for (size_t i = 0; i < n; ++i) {
    std::uint32_t begin = 0, end = 0, unwind = 0;
    std::memcpy(&begin, raw.data() + i * 12, 4);
    std::memcpy(&end, raw.data() + i * 12 + 4, 4);
    std::memcpy(&unwind, raw.data() + i * 12 + 8, 4);
    if (begin == 0 || end <= begin) {
      continue;
    }
    const uint64_t va = image_base + begin;
    if (!pe_va_in_code(bin, va)) {
      continue;
    }
    if (unwind != 0) {
      std::uint8_t hdr = 0;
      if (peparse::ReadByteAtVA(pe, image_base + unwind, hdr)) {
        const unsigned flags = static_cast<unsigned>(hdr >> 3) & 0x1fu;
        if (flags & 0x4u) { /* UNW_FLAG_CHAININFO */
          continue;
        }
      }
    }
    pe_add_func_symbol(bin, va, "");
    ++added;
  }
  verbose(2, "PE pdata function starts: %zu (symbols now %zu)", added,
          bin->symbols.size());
}


static int
load_binary_pe_parse(std::string &fname, Binary *bin, Binary::BinaryType /*type*/)
{
  peparse::parsed_pe *pe = peparse::ParsePEFromFile(fname.c_str());
  if (!pe) {
    print_err("failed to open PE binary '%s' (%s)",
              fname.c_str(), peparse::GetPEErrString().c_str());
    return -1;
  }

  bin->filename = fname;
  bin->type     = Binary::BIN_TYPE_PE;
  bin->type_str = "pe";

  const std::uint16_t machine = pe->peHeader.nt.FileHeader.Machine;
  const std::uint16_t magic   = pe->peHeader.nt.OptionalMagic;

  if (machine == peparse::IMAGE_FILE_MACHINE_AMD64) {
    bin->arch     = Binary::ARCH_X86;
    bin->bits     = 64;
    bin->arch_str = "x86-64";
  } else if (machine == peparse::IMAGE_FILE_MACHINE_I386) {
    bin->arch     = Binary::ARCH_X86;
    bin->bits     = 32;
    bin->arch_str = "x86-32";
  } else if (machine == peparse::IMAGE_FILE_MACHINE_ARM64) {
    bin->arch     = Binary::ARCH_AARCH64;
    bin->bits     = 64;
    bin->arch_str = "aarch64";
  } else if (machine == peparse::IMAGE_FILE_MACHINE_ARM ||
             machine == peparse::IMAGE_FILE_MACHINE_ARMNT ||
             machine == peparse::IMAGE_FILE_MACHINE_THUMB) {
    bin->arch     = Binary::ARCH_ARM;
    bin->bits     = 32;
    bin->arch_str = "arm";
  } else {
    print_err("unsupported PE machine 0x%04x in '%s'", machine, fname.c_str());
    peparse::DestructParsedPE(pe);
    return -1;
  }

  std::uint64_t image_base = 0;
  std::uint32_t entry_rva  = 0;
  if (magic == peparse::NT_OPTIONAL_64_MAGIC) {
    image_base = pe->peHeader.nt.OptionalHeader64.ImageBase;
    entry_rva  = pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint;
  } else if (magic == peparse::NT_OPTIONAL_32_MAGIC) {
    image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
    entry_rva  = pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
  } else {
    print_err("unsupported PE optional magic 0x%04x in '%s'", magic, fname.c_str());
    peparse::DestructParsedPE(pe);
    return -1;
  }
  bin->entry = image_base + entry_rva;

  PeSectionFillCtx fill{bin, 0};
  peparse::IterSec(pe, pe_section_cb, &fill);
  if (fill.fail) {
    peparse::DestructParsedPE(pe);
    return -1;
  }

  peparse::IterExpVA(pe, pe_export_cb, bin);
  pe_load_pdata_symbols(pe, bin, image_base);

  if (bin->sections.empty()) {
    print_err("PE binary '%s' has no loadable sections", fname.c_str());
    peparse::DestructParsedPE(pe);
    return -1;
  }

  verbose(2, "PE binary '%s' arch=%s bits=%u sections=%zu symbols=%zu entry=0x%llx",
          fname.c_str(), bin->arch_str.c_str(), bin->bits, bin->sections.size(),
          bin->symbols.size(),
          static_cast<unsigned long long>(bin->entry));

  peparse::DestructParsedPE(pe);
  return 0;
}

#elif !defined(NUCLEUS_LOADER_NO_BFD)

static bfd*
open_bfd(std::string &fname)
{
  static int bfd_inited = 0;

  bfd *bin;

  if(!bfd_inited) {
    bfd_init();
    bfd_inited = 1;
  }

  bin = bfd_openr(fname.c_str(), NULL);
  if(!bin) {
    print_err("failed to open binary '%s' (%s)", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  if(!bfd_check_format(bin, bfd_object)) {
    print_err("file '%s' does not look like a binary object (%s), maybe load as raw?", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  /* Some versions of bfd_check_format pessimistically set a wrong_format
   * error before detecting the format, and then neglect to unset it once
   * the format has been detected. We unset it manually to prevent problems. */
  bfd_set_error(bfd_error_no_error);

  if(bfd_get_flavour(bin) == bfd_target_unknown_flavour) {
    print_err("unrecognized format for binary '%s' (%s)", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  verbose(2, "binary '%s' has format '%s'", fname.c_str(), bin->xvec->name);

  return bin;
}


int
load_symbols_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_symtab;
  Symbol *sym;

  bfd_symtab = NULL;

  n = bfd_get_symtab_upper_bound(bfd_h);
  if(n < 0) {
    print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_symtab = (asymbol**)malloc(n);
    if(!bfd_symtab) {
      print_err("out of memory");
      goto fail;
    }
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if(nsyms < 0) {
      print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_symtab[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_symtab[i]->name);
        sym->addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_symtab) free(bfd_symtab);

  return ret;
}


int
load_dynsym_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;
  Symbol *sym;

  bfd_dynsym = NULL;

  n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if(n < 0) {
    print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_dynsym = (asymbol**)malloc(n);
    if(!bfd_dynsym) {
      print_err("out of memory");
      goto fail;
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if(nsyms < 0) {
      print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_dynsym[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_dynsym) free(bfd_dynsym);

  return ret;
}


int
load_dynrelocs_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nrels, i;
  arelent **bfd_relocs;
  arelent *bfd_reloc;
  Symbol *sym;
  std::map<uint64_t, Symbol*> addr2sym;

  bfd_relocs = NULL;

  for(auto &s: bin->symbols) {
    addr2sym[s.addr] = &s;
  }

  n = bfd_get_dynamic_reloc_upper_bound(bfd_h);
  if(n < 0) {
    print_err("failed to read dynamic relocations (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_relocs = (arelent**)malloc(n);
    if(!bfd_relocs) {
      print_err("out of memory");
      goto fail;
    }
    nrels = bfd_canonicalize_dynamic_reloc(bfd_h, bfd_relocs, bfd_get_outsymbols(bfd_h));
    if(nrels < 0) {
      print_err("failed to read dynamic relocations (%s)", bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nrels; i++) {
      bfd_reloc = bfd_relocs[i];
      if(addr2sym.count(bfd_reloc->address)) {
        sym = addr2sym[bfd_reloc->address];
        if(bfd_reloc->sym_ptr_ptr && *bfd_reloc->sym_ptr_ptr) {
          sym->name = std::string((*bfd_reloc->sym_ptr_ptr)->name);
        }
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_relocs) free(bfd_relocs);

  return ret;
}


int
load_sections_bfd(bfd *bfd_h, Binary *bin)
{
  int bfd_flags, sectype;
  uint64_t vma, size;
  const char *secname;
  asection* bfd_sec;
  Section *sec;

  for(bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    // binutils ≥2.34 dropped (abfd,sec) getters; single-arg accessors only.
#if defined(bfd_get_section_flags)
    bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);
#else
    bfd_flags = bfd_section_flags(bfd_sec);
#endif

    vma     = bfd_section_vma(bfd_sec);
    size    = bfd_section_size(bfd_sec);
    secname = bfd_section_name(bfd_sec);
    if(!secname) secname = "<unnamed>";

    sectype = Section::SEC_TYPE_NONE;
    if(bfd_flags & SEC_CODE) {
      sectype |= Section::SEC_TYPE_CODE;
    } else if(bfd_flags & SEC_DATA) {
      sectype |= Section::SEC_TYPE_DATA;
    } else if(strcmp(secname, ".eh_frame_hdr") == 0) {
      /* Always keep GNU eh_frame_hdr bytes for FDE start seeding, even if
       * BFD did not tag the section SEC_DATA. */
      sectype |= Section::SEC_TYPE_DATA;
    } else {
      continue;
    }

    bin->sections.push_back(Section());
    sec = &bin->sections.back();

    sec->binary = bin;
    sec->name   = std::string(secname);
    sec->type   = sectype;
    sec->vma    = vma;
    sec->size   = size;
    sec->bytes  = (uint8_t*)malloc((size_t)size);
    if(!sec->bytes) {
      print_err("out of memory");
      return -1;
    }

    if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
      print_err("failed to read section '%s' (%s)", secname, bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}


/* DWARF exception-header encodings used by GNU .eh_frame_hdr (LSB). */
#define NUCLEUS_EH_PE_udata4  0x03
#define NUCLEUS_EH_PE_sdata4  0x0b
#define NUCLEUS_EH_PE_pcrel   0x10
#define NUCLEUS_EH_PE_datarel 0x30
#define NUCLEUS_EH_PE_omit    0xff

static int
elf_va_in_code(Binary *bin, uint64_t va)
{
  for(auto &sec: bin->sections) {
    if(sec.type == Section::SEC_TYPE_CODE && sec.contains(va)) {
      return 1;
    }
  }
  return 0;
}

static void
elf_add_func_symbol(Binary *bin, uint64_t va)
{
  if(va == 0) {
    return;
  }
  for(auto &s: bin->symbols) {
    if(s.addr == va && (s.type & Symbol::SYM_TYPE_FUNC)) {
      return;
    }
  }
  bin->symbols.push_back(Symbol());
  Symbol *sym = &bin->symbols.back();
  sym->type = Symbol::SYM_TYPE_FUNC;
  sym->addr = va;
}

/* Decode one GNU-encoded pointer at *off. field_va is the VA of the encoded
 * value (needed for pcrel). datarel_base is the .eh_frame_hdr VMA. */
static int
eh_decode_ptr(unsigned enc, const uint8_t *buf, size_t size, size_t *off,
              uint64_t field_va, uint64_t datarel_base, uint64_t *out)
{
  unsigned fmt;
  unsigned app;
  uint64_t v;
  uint64_t fva;

  if(enc == NUCLEUS_EH_PE_omit) {
    return -1;
  }
  fmt = enc & 0x0fu;
  app = enc & 0x70u;
  fva = field_va;
  v = 0;
  if(fmt == NUCLEUS_EH_PE_udata4) {
    uint32_t t;
    if(*off + 4 > size) {
      return -1;
    }
    memcpy(&t, buf + *off, 4);
    *off += 4;
    v = t;
  } else if(fmt == NUCLEUS_EH_PE_sdata4) {
    int32_t t;
    if(*off + 4 > size) {
      return -1;
    }
    memcpy(&t, buf + *off, 4);
    *off += 4;
    v = (uint64_t)(int64_t)t;
  } else {
    return -1;
  }
  if(app == NUCLEUS_EH_PE_pcrel) {
    v = fva + (uint64_t)(int64_t)v;
  } else if(app == NUCLEUS_EH_PE_datarel) {
    v = datarel_base + (uint64_t)(int64_t)v;
  } else if(app != 0) {
    return -1;
  }
  *out = v;
  return 0;
}

/* Linux analogue of pe_load_pdata_symbols: GNU .eh_frame_hdr binary-search
 * table of FDE initial_location → SYM_TYPE_FUNC. Stripped DST ELF has no
 * FUNC dynsyms for lua internals; FDE starts still split dump/yield-style
 * over-merged Nucleus bodies via split_at_known_entries. */
static void
elf_load_eh_frame_symbols(Binary *bin)
{
  Section *hdr = NULL;
  const uint8_t *buf;
  size_t size;
  size_t off;
  unsigned ehenc, cntenc, tabenc;
  uint64_t ehptr, count, loc, fde;
  size_t added;
  size_t i;

  if(bin->type != Binary::BIN_TYPE_ELF || bin->bits != 64) {
    return;
  }
  for(auto &sec: bin->sections) {
    if(sec.name == ".eh_frame_hdr" && sec.bytes && sec.size >= 12) {
      hdr = &sec;
      break;
    }
  }
  if(!hdr) {
    return;
  }
  buf = hdr->bytes;
  size = (size_t)hdr->size;
  if(buf[0] != 1) {
    return;
  }
  ehenc = buf[1];
  cntenc = buf[2];
  tabenc = buf[3];
  off = 4;
  if(eh_decode_ptr(ehenc, buf, size, &off, hdr->vma + 4, hdr->vma, &ehptr) < 0) {
    return;
  }
  (void)ehptr;
  if(eh_decode_ptr(cntenc, buf, size, &off, hdr->vma + off, hdr->vma, &count) < 0) {
    return;
  }
  added = 0;
  for(i = 0; i < (size_t)count; i++) {
    uint64_t loc_field = hdr->vma + off;
    if(eh_decode_ptr(tabenc, buf, size, &off, loc_field, hdr->vma, &loc) < 0) {
      break;
    }
    uint64_t fde_field = hdr->vma + off;
    if(eh_decode_ptr(tabenc, buf, size, &off, fde_field, hdr->vma, &fde) < 0) {
      break;
    }
    (void)fde;
    if(!elf_va_in_code(bin, loc)) {
      continue;
    }
    elf_add_func_symbol(bin, loc);
    ++added;
  }
  verbose(2, "ELF eh_frame_hdr function starts: %zu (symbols now %zu)", added,
          bin->symbols.size());
}


int
load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  (void)type;
  bfd_h = NULL;

  bfd_h = open_bfd(fname);
  if(!bfd_h) {
    goto fail;
  }

  bin->filename = std::string(fname);
  bin->entry    = bfd_get_start_address(bfd_h);

  bin->type_str = std::string(bfd_h->xvec->name);
  switch(bfd_h->xvec->flavour) {
  case bfd_target_elf_flavour:
    bin->type = Binary::BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin->type = Binary::BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    print_err("unsupported binary type (%s)", bfd_h->xvec->name);
    goto fail;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = std::string(bfd_info->printable_name);
  switch(bfd_info->arch) {
  case bfd_arch_i386:
    switch(bfd_info->mach) {
    case bfd_mach_i386_i386:
      bin->arch = Binary::ARCH_X86;
      bin->bits = 32;
      break;
    case bfd_mach_x86_64:
      bin->arch = Binary::ARCH_X86;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_arm:
    switch(bfd_info->mach) {
    case bfd_mach_arm_5T:
      bin->arch = Binary::ARCH_ARM;
      bin->bits = 32;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_aarch64:
    switch(bfd_info->mach) {
    case bfd_mach_aarch64:
    case bfd_mach_aarch64_ilp32:
      bin->arch = Binary::ARCH_AARCH64;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_mips:
    switch(bfd_info->mach) {
    case bfd_mach_mips16:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 16;
      break;
    case bfd_mach_mipsisa32r2:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 32;
      break;
    case bfd_mach_mipsisa64:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_powerpc:
    switch(bfd_info->mach) {
    case bfd_mach_ppc:
      bin->arch = Binary::ARCH_PPC;
      bin->bits = 32;
      break;
    case bfd_mach_ppc64:
      bin->arch = Binary::ARCH_PPC;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  default:
fail_arch:
    print_err("unsupported architecture (%s, [%u, %u])", bfd_info->printable_name, bfd_info->arch, bfd_info->mach);
    goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);

  if(load_sections_bfd(bfd_h, bin) < 0) goto fail;
  if(bin->type == Binary::BIN_TYPE_ELF) {
    elf_load_eh_frame_symbols(bin);
  }

  /* Apply relocations if necessary */
  if (bin->arch == Binary::ARCH_PPC) {
    load_dynrelocs_bfd(bfd_h, bin);
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_h) bfd_close(bfd_h);

  return ret;
}

#endif /* BFD path */


int
load_binary_raw(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  long fsize;
  FILE *f;
  Section *sec;

  f = NULL;

  bin->filename = std::string(fname);
  bin->type     = type;
  bin->type_str = std::string("raw");

  if(options.binary.arch == Binary::ARCH_NONE) {
    print_err("cannot determine binary architecture, specify manually");
    goto fail;
  }
  bin->arch     = options.binary.arch;
  bin->bits     = options.binary.bits;
  bin->arch_str = std::string(binary_arch_descr[(int)options.binary.arch][0]);
  bin->entry    = 0;

  if(!bin->bits) {
    switch(bin->arch) {
    case Binary::ARCH_X86:
      bin->bits = 64;
      break;
    default:
      break;
    }
  }

  bin->sections.push_back(Section());
  sec = &bin->sections.back();

  sec->binary = bin;
  sec->name   = std::string("raw");
  sec->type   = Section::SEC_TYPE_CODE;
  sec->vma    = options.binary.base_vma;

  f = fopen(fname.c_str(), "rb");
  if(!f) {
    print_err("failed to open binary '%s' (%s)", fname.c_str(), strerror(errno));
    goto fail;
  }

  fseek(f, 0L, SEEK_END);
  fsize = ftell(f);
  if(fsize <= 0) {
    print_err("binary '%s' appears to be empty", fname.c_str());
    goto fail;
  }

  sec->size  = (uint64_t)fsize;
  sec->bytes = (uint8_t*)malloc((size_t)fsize);
  if(!sec->bytes) {
    print_err("out of memory");
    goto fail;
  }

  fseek(f, 0L, SEEK_SET);
  if(fread(sec->bytes, 1, (size_t)fsize, f) != (size_t)fsize) {
    print_err("failed to read binary '%s'", fname.c_str());
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(f) {
    fclose(f);
  }

  return ret;
}


int
load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  if(type == Binary::BIN_TYPE_RAW) {
    return load_binary_raw(fname, bin, type);
  }
#if defined(NUCLEUS_LOADER_PE_PARSE)
  return load_binary_pe_parse(fname, bin, type);
#elif !defined(NUCLEUS_LOADER_NO_BFD)
  return load_binary_bfd(fname, bin, type);
#else
  print_err("no binary loader available for non-raw type");
  return -1;
#endif
}


void
unload_binary(Binary *bin)
{
  size_t i;
  Section *sec;

  for(i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if(sec->bytes) {
      free(sec->bytes);
      sec->bytes = NULL;
    }
  }
}
