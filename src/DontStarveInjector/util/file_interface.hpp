#pragma once

#include <cstdint>

struct file_interface {
    using off_t = long long;

    virtual ~file_interface() {};

    virtual int fclose() = 0;

    virtual size_t fread(void *buf, size_t element_size, size_t count) = 0;

    virtual size_t fwrite(void const *buf, size_t element_size, size_t count) = 0;

    virtual int ferror() = 0;

    virtual int fscanf(char const *const _Format, ...) = 0;

    virtual char *fgets(char *buff, int maxcount) = 0;

    virtual int fseeko(off_t _Offset, int _Origin) = 0;

    virtual off_t ftello() = 0;

    virtual void clearerr() = 0;
};
