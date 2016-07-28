#ifndef _COMINT_H___
#define _COMINT_H___
#include "type.h"

/* 获取通讯加密密钥 */
uint32_t
get_encrypt_key(int sock, uint32_t *key);

#endif
