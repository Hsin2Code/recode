#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include "common.h"
#include "type.h"

/* 获取从beg开始到end结束的字符串值 */
char*
get_tag_val(const char *data, const char * beg, const char * end, char *val)
{
    char *beg_mrk = strlen(beg) + strstr(data, beg);
    if(beg_mrk == NULL)
        return NULL;
    char *end_mrk = strstr(beg_mrk, end);
    if(end_mrk == NULL)
        strcpy(val, beg_mrk);
    else {
        strncpy(val, beg_mrk, end_mrk - beg_mrk);
        /* 尽头的张望 */
        val[end_mrk - beg_mrk] ='\0';
    }
    return val;
}

/* 干掉字符串中的'\n' '\t' '\r' '\f' '\v' ' ' */
char *
trim_str(char * str) {
    char * tmp = str, *ret = str;
    while(*str != '\0') {
        if(isspace(*str))
            str++;
        else
            *tmp++ = *str++;
    }
    *tmp = '\0';
    return ret;
}

/* 数据黏贴函数 */
char *
datacat(char *data, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char tmp[LINE_SIZE] = {0};
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    strcat(data, tmp);
    va_end(ap);
    return data;
}

/* 获取本地网卡信息 */
uint32_t
get_netcard_info(struct netcard_t *netcard)
{
    strcpy(netcard->ip, "192.168.133.113");
    strcpy(netcard->mac, "xx:xx:xx:xx:xx:xx");
    strcpy(netcard->mask, "255.255.255.0");
    strcpy(netcard->gw, "192.168.133.113");
    strcpy(netcard->dns, "8.8.8.8");
    return OK;
}

/* 获取本地时间 */
void
get_local_time(char *strtime)
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep);
    sprintf(strtime, "%d-%02d-%02d %02d:%02d:%02d",
            (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday,
            p->tm_hour, p->tm_min, p->tm_sec);
}
