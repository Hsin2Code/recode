#ifndef _TYPE_H__
#define _TYPE_H__
#include <stdint.h>
#include <stddef.h>

#define LINE_SIZE 256
#define BUFF_SIZE 1024


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


#endif
