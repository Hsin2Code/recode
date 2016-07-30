#include <string.h>
#include <ctype.h>
#include "common.h"
#include "type.h"

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
