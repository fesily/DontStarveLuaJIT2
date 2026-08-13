#ifndef NUCLEUS_ENDIAN_H
#define NUCLEUS_ENDIAN_H

#include <stdint.h>

/* Explicit C linkage: cfg/disasm include this after frida-gum, which leaves
 * open extern "C" regions; definitions in endian.cc must match. */
#ifdef __cplusplus
extern "C" {
#endif

uint16_t read_le_i16(const uint16_t* data);
uint32_t read_le_i32(const uint32_t* data);
uint64_t read_le_i64(const uint64_t* data);

uint16_t read_be_i16(const uint16_t* data);
uint32_t read_be_i32(const uint32_t* data);
uint64_t read_be_i64(const uint64_t* data);

#ifdef __cplusplus
}
#endif

#endif /* NUCLEUS_ENDIAN_H */
