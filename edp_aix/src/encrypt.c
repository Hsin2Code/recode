#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "encrypt.h"
/* 置换矩阵 */
BYTE m_key[24]=
{
    0xCB,0xB6,0xD8,0xBF,
    0xBB,0xB1,0xD8,0xBF,
    0xE0,0xBC,0xBB,0xC4,
    0xC1,0xC6,0xB4,0xD4,
    0xC5,0xD0,0xB1,0xB1,
    0xA9,0xBE,0xB1,0xB1
};
/* 加密函数V1 */
uint32_t
encrypt_v1(DWORD key,LPVOID src, LPVOID dst, DWORD len, DWORD offset)
{
    if(src == NULL || src == NULL)
        return FAIL;
    BYTE m_tmp[sizeof(m_key)];
    memcpy(m_tmp, m_key, sizeof(m_key));

    DWORD *pkey = (DWORD*)m_tmp, m_count, i;
    m_count = sizeof(m_key) / sizeof(DWORD);
    for(i = 0; i < m_count; i++) {
        *pkey ^=key; pkey++;
    }
    m_count = offset % sizeof(m_tmp);
    for(i = 0; i < len; i++) {
        ((BYTE*)dst)[i] = ((BYTE*)src)[i] ^ m_tmp[m_count];
        //下一个
        m_count++;
        if(m_count == sizeof(m_key))
        {
            m_count=0;
        }
    }
    return OK;
}
/* 解密函数V1 */
uint32_t
decrypt_v1(DWORD key,LPVOID src, LPVOID dst, DWORD len, DWORD offset)
{
    return encrypt_v1(key, src, dst, len, offset);
}
/* crc计算函数 */
ULONG CRCTab[256];
void CRCInit()
{
    int I,J;
    ULONG C;
    for(I=0;I<256;I++) {
        for (C=I,J=0;J<8;J++) {
            C=(C & 1) ? (C>>1)^0xEDB88320L : (C>>1);
        }
        CRCTab[I]=C;
    }
}
ULONG CRC32(ULONG StartCRC,BYTE *Addr, ULONG Size)
{
    CRCInit();
    ULONG I;
    for(I=0; I<Size; I++) {
        StartCRC = CRCTab[(BYTE)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
    }

    return StartCRC;
}
ULONG CRC32Raw(ULONG StartCRC,BYTE *Addr, ULONG Size)
{
    StartCRC ^= 0xffffffffL;
    ULONG I;
    for(I=0; I<Size; I++) {
        StartCRC = CRCTab[(BYTE)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
    }
    StartCRC ^= 0xffffffffL;
    return StartCRC;
}
