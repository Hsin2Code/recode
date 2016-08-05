#ifndef _COMMON_H___
#define _COMMON_H___
#include "type.h"

#define _UNIX_ 1

struct netcard_t
{
    char name[UNIT_SIZE];
    char mac[UNIT_SIZE];
    char ip[UNIT_SIZE];
    char broadcast[UNIT_SIZE];
    char mask[UNIT_SIZE];
    struct netcard_t *next;
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
get_local_netcard(struct netcard_t * head);

/* 获取本地时间 */
void
get_local_time(char *strtime);

#endif
