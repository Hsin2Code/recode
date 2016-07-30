#ifndef _COMMON_H___
#define _COMMON_H___
#include "type.h"

struct netcard_t {
    char ip[16];
    char mac[16];
    char gw[16];
    char mask[16];
    char dns[16];
    char name[16];
};



/* 干掉字符串中的'\n' '\t' '\r' '\f' '\v' ' ' */
char *
trim_str(char * str);
/* 获取本地网卡信息 */
uint32_t
get_netcard_info(struct netcard_t *netcard);


#endif
