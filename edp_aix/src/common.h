#ifndef _COMMON_H___
#define _COMMON_H___
#include "type.h"

struct netcard_t {
    char ip[16];
    char gw[16];
    char mask[16];
    char dns[16];
    char mac[24];
    char name[40];
};


char*
get_tag_val(const char *data, const char * beg, const char * end, char *val);
/* 干掉字符串中的'\n' '\t' '\r' '\f' '\v' ' ' */
char *
trim_str(char * str);

/* 数据黏贴函数 */
char *
datacat(char *data, const char *fmt, ...)__attribute__((format(printf,2,3)));

/* 获取本地网卡信息 */
uint32_t
get_netcard_info(struct netcard_t *netcard);

/* 获取本地时间 */
void
get_local_time(char *strtime);

#endif
