#pragma once
#include <stdio.h>
#include <charconv>
#include <stdint.h>
static uintptr_t readGameVersion(const char* filename)
{
    auto version_fp = fopen(filename, "r");
    if (!version_fp)
        return -1;
    char buf[128];
    auto readed = fread(buf, sizeof(char), sizeof(buf) / sizeof(char), version_fp);
    fclose(version_fp);
    if (readed <= 0)
        return -1;
    uintptr_t version;
    auto ret = std::from_chars(buf, buf + readed, version);
    if (ret.ec != std::errc{})
        return -1;
    return version;
}