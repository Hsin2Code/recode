#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
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
#ifdef _UNIX_

static uint32_t
get_local_netcard(struct netcard_t * head)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if( sockfd < 0) {
        perror("Create socket failed!");
        return FAIL;
    }
    char buffer[BUFF_SIZE] = {0};
    struct ifconf ifc;
    ifc.ifc_len = BUFF_SIZE;
    ifc.ifc_ifcu.ifcu_buf = buffer;
    if( ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl err!");
        return FAIL;
    }
    struct netcard_t * tmp = NULL;
    /* 定义并初始化接下来要使用的变量 */
    char * ptr = buffer,* cptr = NULL;
    while(ptr < buffer + ifc.ifc_len) {
        struct ifreq * ifr = (struct ifreq *)ptr;
        int len = sizeof(struct sockaddr) > ifr->ifr_addr.sa_len ?
            sizeof(struct sockaddr) : ifr->ifr_addr.sa_len;
        ptr += sizeof(ifr->ifr_name) + len; /* for next one in buffer */

        struct ifreq ifrcopy = *ifr;
        ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy);
        if(ifrcopy.ifr_flags & IFF_LOOPBACK)
            continue;           /* 跳过回环地址 */
        if(!(ifrcopy.ifr_flags & IFF_UP))
            continue;           /* 跳过未启用地址 */
        if(ifr->ifr_addr.sa_family != AF_LINK)
            continue;           /* 跳过无用地址 */

        tmp = (struct netcard_t *)malloc(sizeof(struct netcard_t));
        /* 获取网卡名称 */
        strcpy(tmp->name, ifrcopy.ifr_name);

        /* 获取MAC地址 */
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
        strcpy(tmp->mac, (char *)ether_ntoa((struct ether_addr *)LLADDR(sdl)));

        /* 获取IP地址 */
        if(ioctl(sockfd, SIOCGIFADDR, &ifrcopy) == 0)
            strcpy(tmp->ip, inet_ntoa(((struct sockaddr_in*)&(ifrcopy.ifr_addr))->sin_addr));

        /* 获取并打印广播地址 */
        if(ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy) == 0)
            strcpy(tmp->broadcast,inet_ntoa(((struct sockaddr_in*)&(ifrcopy.ifr_addr))->sin_addr));

        /* 获取并打印子网掩码 */
        if(ioctl(sockfd,SIOCGIFNETMASK, &ifrcopy) == 0)
            strcpy(tmp->mask ,inet_ntoa(((struct sockaddr_in*)&(ifrcopy.ifr_addr))->sin_addr));
        head->next = tmp;
        head = tmp;
    }
    head->next = NULL;
    close(sockfd);
    if(tmp != NULL)
        return OK;
    else
        return FAIL;
}
#endif
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
