#pragma once
#include <windows.h>
#include <stdio.h>
#include <string>
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
        if (element_size != 1) {
            // 只支持字节大小的元素
            return 0;
        }
        // 分配宽字符缓冲区
        std::wstring wbuf(count, L'\0');
        // 读取宽字符
        size_t read_count = ::fread(&wbuf[0], sizeof(wchar_t), count, fp);
        if (read_count == 0) {
            return 0;
        }
        // 把wbuf中所有的\r\n转换成\r
        if (textmode) {
            for (size_t i = 0; i < read_count; ++i) {
                if (wbuf[i] == L'\r' && wbuf[i + 1] == L'\n') {
                    wbuf[i] = L'\n';
                    wbuf.erase(i + 1, 1);
                    --read_count;
                }
            }
        }
        // 将宽字符转换为多字节字符
        size_t converted = wcstombs(static_cast<char*>(buf), wbuf.c_str(), count);
        return converted == (size_t)-1 ? 0 : converted;
    }

    size_t fwrite(void const *buf, size_t element_size, size_t count) override {
        if (element_size != 1) {
            // 只支持字节大小的元素
            return 0;
        }
        // 将输入的 char 数据转为字符串
        std::string sbuf(static_cast<const char*>(buf), count);
        // 分配宽字符缓冲区
        std::wstring wbuf(count, L'\0');
        // 将多字节字符转换为宽字符
        size_t converted = mbstowcs(&wbuf[0], sbuf.c_str(), count);
        if (converted == (size_t)-1) {
            return 0;
        }
        // 写入宽字符到文件
        return ::fwrite(wbuf.c_str(), sizeof(wchar_t), converted, fp);
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

    static wFile_interface* fopen(const char *path, const char *mode) {
        auto wpath = toWstring(path);
        auto wmode = toWstring(mode);
        bool textmode = !wmode.contains('b');
       
        auto fp = _wfopen(wpath.c_str(), wmode.c_str());
        if (fp == nullptr) {
            return nullptr;
        }
        return new wFile_interface{fp, textmode};
    }
    template<UINT CodePage = CP_ACP>
    static std::wstring toWstring(const char *str) {
        
        int size_needed = MultiByteToWideChar(CodePage, 0, str, -1, nullptr, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CodePage, 0, str, -1, &wstr[0], size_needed);
        return wstr;
    }
    template<UINT CodePage = CP_ACP>
    static std::string toString(const wchar_t *wstr) {
        int size_needed = WideCharToMultiByte(CodePage, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CodePage, 0, wstr, -1, &str[0], size_needed, nullptr, nullptr);
        return str;
    }
};

