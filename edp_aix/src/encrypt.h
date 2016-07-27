#ifndef _ENCRYPT_H___
#define _ENCRYPT_H___

#include "type.h"


/* 加密函数V1 */
uint32_t
encrypt_v1(DWORD key,LPVOID src, LPVOID dest, DWORD len, DWORD offset);
/* 解密函数V1 */
uint32_t
decrypt_v1(DWORD key,LPVOID src, LPVOID dst, DWORD len, DWORD offset);
/* 计算CRC */
ULONG CRC32(ULONG StartCRC,BYTE *Addr, ULONG Size);
ULONG CRC32Raw(ULONG StartCRC,BYTE *Addr, ULONG Size);
#endif
