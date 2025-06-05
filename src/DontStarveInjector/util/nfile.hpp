#pragma once
#include <stdio.h>
#include <stdarg.h>
#include "file_interface.hpp"
/* use char file interface*/
struct normal_file_interface : file_interface {
    normal_file_interface(FILE *fp) : fp(fp) {
    }
    ~normal_file_interface() override {
        fclose();
    }

    int fclose() override {
        int ret = ::fclose(fp);
        fp = nullptr;
        return ret;
    }

    size_t fread(void *buf, size_t element_size, size_t count) override {
        return ::fread(buf, element_size, count, fp);
    }

    size_t fwrite(void const *buf, size_t element_size, size_t count) override {
        return ::fwrite(buf, element_size, count, fp);
    }

    int ferror() override { return ::ferror(fp);}

    int fscanf(char const *const _Format, ...) override {
        va_list args;
        va_start(args, _Format);
        int ret = ::vfscanf(fp, _Format, args);
        va_end(args);
        return ret;
    }

    char *fgets(char *buff, int maxcount) override {
        return ::fgets(buff, maxcount, fp);
    }
    int fseeko(off_t _Offset, int _Origin) override{
        return ::fseek(fp, _Offset, _Origin);
    }
    off_t ftello() override {
        return ::ftell(fp);
    }
    void clearerr() override {
        ::clearerr(fp);
    }

    int feof() override {
        return ::feof(fp);
    }

    static normal_file_interface* fopen(const char *path, const char *mode) {
        auto fp = ::fopen(path, mode);
        if (fp == nullptr) {
            return nullptr;
        }
        return new normal_file_interface{fp};
    }
    FILE *fp = nullptr;
};