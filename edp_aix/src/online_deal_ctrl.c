#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "type.h"
#include "common.h"
#include "socket.h"
#include "journal.h"
#include "register.h"
#include "protocol.h"
#include "localdb.h"
#include "online_deal_ctrl.h"

static char last_offline_time[UNIT_SIZE];

static char addr1[UNIT_SIZE];
static char addr2[UNIT_SIZE];

static uint32_t interval;
static uint32_t detect_door;
static uint32_t addr_door;
/* 限定使用的网段 */
static uint32_t ip_start;
static uint32_t ip_end;



enum stat{
    ONLINE,
    OFFLINE,
    LIMIT,
};

static uint32_t
import_xml(char *xml_data) {
    char tmp[UNIT_SIZE] = {0};
    detect_door = atoi(get_tag_val(xml_data, " AllowClientDetect=\"", "\" ", tmp));
    addr_door = atoi(get_tag_val(xml_data, " UseDetectWAN=\"", "\" ", tmp));
    interval = atoi(get_tag_val(xml_data, " DetectIntervalTime=\"", "\" ", tmp));
    if(interval < 5 || interval > 86400)
        interval = 5;
    get_tag_val(xml_data, " WANIP1=\"", "\" ", addr1);
    get_tag_val(xml_data, " WANIP2=\"", "\" ", addr2);
    get_tag_val(xml_data, " AccessIPRange=\"", "\" ", tmp);
    char * idx = strchr(tmp, '-');
    if(idx != NULL) {
        ip_end = ntohl(inet_addr(idx + 1));
        *idx = '\0';
        ip_start = ntohl(inet_addr(tmp));
    }else {
        ip_end = FAIL;
    }
    return OK;
}
static uint32_t
report_log(enum stat st)
{
    char sztime[UNIT_SIZE] = {0};
    get_local_time(sztime);
    char log[BUFF_SIZE] = {0};
    uint16_t type = FIND_DAILUP;
    uint16_t what = 0;
    sprintf(log,"StartTime=%s\r\nEndTime=%s\r\nRouteTable=%s\r\nclassaction=%d\r\nriskrank=%d",
            last_offline_time,sztime,"192.168.133.1",Illegal_Behavior,Event_Alarm);
    switch(st) {
    case LIMIT:{
        /* ip 不在限定范围中 */
    }
    case ONLINE: {
        /* 内外网 */
        what = FIND_DAILUPING;
        break;
    }
    case OFFLINE:{
        /* 外网 */
        what = FIND_DAILUPED;
        break;
    }
    }
    LOG_RUN("上报数据到本地数据库\n");
    db_ins_report(type, what, log);
    get_local_time(last_offline_time);
    return OK;
}

static uint32_t
detect_addr(const char * addr) {
    char ip[UNIT_SIZE] = {0};
    uint16_t port = 0;
    strcpy(ip, addr);

    char *idx = strstr(ip, "http://");
    if(idx != NULL)
        get_tag_val(addr, "http://", "/", ip);
    idx = strchr(ip, ':');
    if(idx != NULL) {
        port = atoi(idx+1);
        *idx = '\0';
    }else {
        port = 80;
    }

    struct sockaddr_in addr_in;
    struct hostent *host;
    if(inet_aton(ip, &(addr_in.sin_addr)) == 0) {
        //name?
        host = gethostbyname(ip);
        if(host == NULL) {
            LOG_RUN("错误的域名 or 太复杂\n");
            return FAIL;
        }
        strcpy(ip, inet_ntoa(*((struct in_addr *)host->h_addr)));
    }
    LOG_RUN("the new IP is %s\n", ip);
    int sock;
    if(create_client_socket(&sock, ip, port)) {
        LOG_RUN("连接不通 %s\n", addr);
        return FAIL;
    }
    LOG_RUN("可以连通 %s\n", addr);
    close_socket(sock);
    return OK;
}
/* 同时连接内外网 */
/* 仅在外网中 */
uint32_t
online_deal_ctrl_init(void *arg) {
    import_xml((char *)arg);
    get_local_time(last_offline_time);
    return OK;
}
uint32_t
online_deal_ctrl_work(void) {
    static uint32_t time_meter;
    if(detect_door == 0) {
        LOG_RUN("探测门未开...\n");
        return OK;
    }
    time_meter += 5;
    if(interval <= time_meter) {
        char addr[UNIT_SIZE] = {0};
        uint16_t port = 0;
        get_srv_addr(addr, &port);
        datacat(addr, ":%u", port);
        uint32_t result = FAIL;
        if(addr_door) {
            LOG_RUN("探测专用地址\n");
            result &= detect_addr(addr1);
            LOG_RUN("探测通用地址\n");
            result &= detect_addr(addr2);
        }else {
            result &= detect_addr(DEFAULT_ADDR);
        }
        if(result == OK) {
            LOG_RUN("目前在外网中,探测是否在内网中...\n");
            if(detect_addr(addr) == OK) {
                LOG_RUN("在内网中...\n");
                report_log(ONLINE);
            }else {
                LOG_RUN("不在内网中...\n");
                report_log(OFFLINE);
            }
        }else {
            if(ip_end != FAIL) {
                ;                       /* 是否在限定IP段 */
                report_log(LIMIT);
            }
        }
        time_meter = 0;
    }
    return OK;
}
uint32_t
online_deal_ctrl_uninit() {
    return OK;
}
