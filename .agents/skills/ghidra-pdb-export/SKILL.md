---
name: ghidra-pdb-export
description: "Use when a stripped Windows binary analyzed in Ghidra needs a PDB for WinDbg/ETW/PerfView symbolization; no Ghidra writer, build via donor YAML + llvm-pdbutil and match the PE's RSDS identity."
---

# PDB from a Ghidra database

Ghidra has **no PDB writer** (only the reader: `pdb.exe`, `CreatePdbXmlFilesScript`).
Assemble one from Ghidra data + LLVM's `yaml2pdb`.

## Procedure

1. **Ghidra export** (`ghidra/DstExportPdb.java <sections.tsv> <publics.tsv>`):
   - sections: PE section headers parsed from the mapped headers at image base
     (`e_lfanew`@0x3C, `NumberOfSections`@pe+6, `SizeOfOptionalHeader`@pe+20,
     40-byte entries) → index, name, rva, vsize, rawsize, rawptr, characteristics.
   - publics: every non-external non-thunk function with source != DEFAULT → rva, name(true).
2. **Donor PDB** (once per machine):
   ```
   clang -g -gcodeview -c tiny.c -o tiny.obj
   lld-link /debug /pdb:donor.pdb /entry:main /subsystem:console /nodefaultlib tiny.obj
   llvm-pdbutil pdb2yaml --all donor.pdb > donor.yaml
   ```
3. **Patch YAML** (`tools/symmatch/make_pdb.py`): replaces `DbiStream.SectionHeaders`
   and `PublicsStream.Records` (Segment = 1-based section index, Offset = rva − section.rva),
   and rewrites `PdbStream`/`DbiStream` Age, `PdbStream.Guid`, `PdbStream.Signature`.
4. **Build**: `llvm-pdbutil yaml2pdb --pdb=<module>.pdb dst.yaml`.
5. **Verify**: `llvm-pdbutil dump --summary` (GUID/Age/Signature) and
   `dump --publics | grep -A1 <known symbol>` (addr = segment:offset).

## Non-negotiables

- **GUID/Age/Signature must equal the PE's CodeView record**: read `RSDS` from the
  debug directory (index 6; entries 28 bytes, Type==2; GUID at +4, Age at +20) and
  the PE TimeDateStamp. Mismatch → dbghelp rejects the PDB silently.
- The PDB must be named exactly like `basename` of the RSDS pdb path and sit next
  to the module or on the symbol path.
- **Quote every public name** in the YAML: names can start with a backtick
  (`` `eh_vector_destructor_iterator' ``), `::`, `<`, `~`, `$`. Unquoted → YAML tokenizer error.
- Section list indentation must match the donor (`  SectionHeaders:` + 4-space dash),
  otherwise yaml2pdb fails or drops sections.
- Publics are sorted by name in the file; keep that.

## Limitations

- Publics only: no types, locals or line numbers → good for stack/ETW attribution,
  not source-level debugging.
- Donor module records (`tiny.obj`) remain in the DBI stream; cosmetic only.
- Duplicate names (C++ overloads) become several publics at different addresses;
  `::` names are preserved verbatim.

## Environment notes (this workstation)

- `llvm-pdbutil`, `clang`, `lld-link` are in `C:\Program Files\LLVM\bin`; Git Bash
  cannot exec them (`error: command not found`) — use
  `powershell -NoProfile -Command "& 'C:\Program Files\LLVM\bin\llvm-pdbutil.exe' ..."`.
- `pdb2yaml` flags in LLVM 22: `--all`, `--dbi-stream`, `--publics-stream`,
  `--section-headers`; there is no `--pdb-stream` (use `dump --summary`).
