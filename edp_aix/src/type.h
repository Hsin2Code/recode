#ifndef _TYPE_H__
#define _TYPE_H__
#include <stdint.h>
#include <stddef.h>

#define UNIT_SIZE 64
#define LINE_SIZE 256
#define BUFF_SIZE 1024
#define DATA_SIZE 2048

#define OK 0
#define FAIL ~0x0

typedef int8_t    CHAR;
typedef int16_t   SHORT;
typedef int32_t   INT;
typedef int32_t   BOOL;
typedef int32_t   LONG;
typedef uint8_t   UCHAR;
typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint16_t  USHORT;
typedef uint32_t  UINT;
typedef uint32_t  ULONG;
typedef uint32_t  DWORD;
typedef DWORD *    LPVOID;

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


#endif
