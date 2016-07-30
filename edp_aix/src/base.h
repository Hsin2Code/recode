#ifndef _BASE_H___
#define _BASE_H___
#include <stdint.h>
#include <stdio.h>
/* 字节序转换 */

#define BigLittleSwap16(A)        ((((uint16_t)(A) & 0xff00) >> 8) |      \
                                   (((uint16_t)(A) & 0x00ff) << 8))


#define BigLittleSwap32(A)        ((((uint32_t)(A) & 0xff000000) >> 24) | \
                                   (((uint32_t)(A) & 0x00ff0000) >> 8) |  \
                                   (((uint32_t)(A) & 0x0000ff00) << 8) |  \
                                   (((uint32_t)(A) & 0x000000ff) << 24))

#define BigLittleSwap64(A)        ((((uint64_t)(A) & 0xff00000000000000) >> 56) | \
                                   (((uint64_t)(A) & 0x00ff000000000000) >> 40) | \
                                   (((uint64_t)(A) & 0x0000ff0000000000) >> 24) | \
                                   (((uint64_t)(A) & 0x000000ff00000000) >> 8) | \
                                   (((uint64_t)(A) & 0x00000000ff000000) << 8) | \
                                   (((uint64_t)(A) & 0x0000000000ff0000) << 24) | \
                                   (((uint64_t)(A) & 0x000000000000ff00) << 40) | \
                                   (((uint64_t)(A) & 0x00000000000000ff) << 56))
/* 小端模式 */
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__

#define ENDIANS(A)        (A)
#define ENDIANL(A)        (A)

#endif

/* 大端模式 */
#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__

#define ENDIANS(A)        BigLittleSwap16(A)
#define ENDIANL(A)        BigLittleSwap32(A)

#endif
/* 数据黏贴函数 */
char *
datacat(char *data, const char *fmt, ...)__attribute__((format(printf,2,3)));

#endif
