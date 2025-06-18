#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <cassert>

#include "file_interface.hpp"
/* use wchat_t api for file on Windows*/
struct wFile_interface : file_interface {
    wFile_interface(FILE *fp, bool textmode) : fp(fp), textmode{textmode} {
    }
    ~wFile_interface() override {
        fclose();
    }

    int fclose() override {
        int ret = ::fclose(fp);
        fp = nullptr;
        return ret;
    }

    size_t fread(void *buf, size_t element_size, size_t count) override {
        assert(element_size == 1);
        if (element_size != 1) {
            return 0; // 不支持非字节读取
        }
        std::string read_buf(count * element_size, '\0');
        size_t read_count = ::fread(&read_buf[0], element_size, count, fp);
        if (read_count == 0) {
            return 0;
        }
        read_buf.resize(read_count);
        if (textmode) {
            return replaceCRLF(read_buf, (char *) buf, count);
        }
        memcpy_s(buf, count * element_size, read_buf.data(), read_count * element_size);
        return read_count;
    }

    size_t fwrite(void const *buf, size_t element_size, size_t count) override {
        assert(element_size == 1);
        if (element_size != 1) {
            return 0; // 不支持非字节读取
        }
        return ::fwrite(buf, element_size, count, fp);
    }

    int ferror() override { return ::ferror(fp); }

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
    int fseeko(off_t _Offset, int _Origin) override {
        return _fseeki64(fp, _Offset, _Origin);
    }
    off_t ftello() override {
        return _ftelli64(fp);
    }
    void clearerr() override {
        ::clearerr(fp);
    }

    int feof() override {
        return ::feof(fp);
    }

    FILE *fp = nullptr;
    bool textmode = false;

    static wFile_interface *fopen(const char *path, const char *mode) {
        auto m = std::string_view{mode};
        if (m.contains('t')) {
            return nullptr;// 不支持文本模式
        }
        bool textmode = !m.contains('b');
        std::string _m = textmode ? std::string{mode} + "b" : mode;


        auto fp = ::fopen(path, _m.c_str());
        if (fp == nullptr) {
            return nullptr;
        }
        return new wFile_interface{fp, textmode};
    }

    static size_t replaceCRLF(const std::string &str, char *buf, size_t buf_len) {
        size_t write_pos = 0;// 记录写入buf的位置
        for (size_t i = 0; i < str.length();) {
            // 检查是否为"\r\n"序列
            if (str[i] == '\r' && i + 1 < str.length() && str[i + 1] == '\n') {
                buf[write_pos++] = '\r';// 写入'\n'
                i += 2;                 // 跳过"\r\n"
            } else if (str[i] == '\n') {
                i++; // 如果是'\n'，则不写入
            } else {
                buf[write_pos++] = str[i];// 直接复制当前字符
                i += 1;
            }
        }
        return write_pos;// 返回写入的字节数
    }

};
