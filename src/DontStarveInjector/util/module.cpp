#pragma once

#include <Windows.h>
#include "module.hpp"

void module_enumerate_exports(HMODULE module,
                              FoundExportFunc func,
                              void *user_data) {
    const uint8_t *mod_base;
    const IMAGE_DOS_HEADER *dos_hdr;
    const IMAGE_NT_HEADERS *nt_hdrs;
    const IMAGE_DATA_DIRECTORY *entry;
    const IMAGE_EXPORT_DIRECTORY *exp;
    const uint8_t *exp_start, *exp_end;

    mod_base = (const uint8_t *) module;
    dos_hdr = (const IMAGE_DOS_HEADER *) module;
    nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
    entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exp = (const IMAGE_EXPORT_DIRECTORY *) (mod_base + entry->VirtualAddress);
    exp_start = mod_base + entry->VirtualAddress;
    exp_end = exp_start + entry->Size - 1;

    if (exp->AddressOfNames != 0) {
        const DWORD *name_rvas, *func_rvas;
        const WORD *ord_rvas;
        DWORD index;

        name_rvas = (const DWORD *) &mod_base[exp->AddressOfNames];
        ord_rvas = (const WORD *) &mod_base[exp->AddressOfNameOrdinals];
        func_rvas = (const DWORD *) &mod_base[exp->AddressOfFunctions];

        for (index = 0; index < exp->NumberOfNames; index++) {
            DWORD func_rva;
            const uint8_t *func_address;

            func_rva = func_rvas[ord_rvas[index]];
            func_address = &mod_base[func_rva];
            if (func_address < exp_start || func_address > exp_end) {
                ExportDetails details;

                details.type = ExportDetails::FUNCTION; /* TODO: data exports */
                details.name = (const char *) &mod_base[name_rvas[index]];
                details.address = (void *) (func_address);

                if (!func(&details, user_data))
                    return;
            }
        }
    }
}

void
module_enumerate_imports(HMODULE module,
                         FoundImportFunc func,
                         void *user_data) {
    const uint8_t *mod_base;
    const IMAGE_DOS_HEADER *dos_hdr;
    const IMAGE_NT_HEADERS *nt_hdrs;
    const IMAGE_DATA_DIRECTORY *entry;
    const IMAGE_IMPORT_DESCRIPTOR *desc;

    mod_base = (const uint8_t *) module;
    dos_hdr = (const IMAGE_DOS_HEADER *) module;
    nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
    entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    desc = (const IMAGE_IMPORT_DESCRIPTOR *) (mod_base + entry->VirtualAddress);

    for (; desc->Characteristics != 0; desc++) {
        ImportDetails details;
        const IMAGE_THUNK_DATA *thunk_data;

        if (desc->OriginalFirstThunk == 0)
            continue;

        details.type = ImportDetails::FUNCTION; /* FIXME: how can we tell? */
        details.name = NULL;
        details.module = (const char *) (mod_base + desc->Name);
        details.address = 0;
        details.slot = 0; /* TODO */

        thunk_data = (const IMAGE_THUNK_DATA *)
                (mod_base + desc->OriginalFirstThunk);
        for (; thunk_data->u1.AddressOfData != 0; thunk_data++) {
            if ((thunk_data->u1.AddressOfData & IMAGE_ORDINAL_FLAG) != 0)
                continue; /* FIXME: we ignore imports by ordinal */

            details.name = (const char *)
                    (mod_base + thunk_data->u1.AddressOfData + 2);

            if (!func(&details, user_data))
                return;
        }
    }
}
