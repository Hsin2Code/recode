#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "protocol.h"
#include "socket.h"
#include "comint.h"
#include "type.h"
#include "register.h"
#include "common.h"
#include "journal.h"

extern struct reg_info_t _reg_info;
/* 策略名称 */
const char * policy_target[POLICY_TYPE_COUNT] = {"ONLINE-DEAL-CONTROL"};

/* 策略标签转枚举 */
static enum policy_type
type_from_target(const char * target) {
    enum policy_type type;
    for(type = 0; type < POLICY_TYPE_COUNT; type++) {
        if(strcmp(target, policy_target[type]) == 0)
            return type;
    }
    return POLICY_TYPE_COUNT;
}

/* 构造数据 */
static uint32_t
package_data(char * data, struct netcard_t* netcard)
{
    datacat(data, "MACAddress0=%s\r\n", "xxx");
    datacat(data, "IPAddress0=%s\r\n", "192.168.133.113");
    datacat(data, "MACCount=1\r\nIPCount=1\r\n");
    datacat(data, "IPReport=%s|%s|%s|%s*84C9B2A7E124|%s#\r\n",
            _reg_info.reg_mac, netcard->ip, netcard->mask, netcard->gw, netcard->dns);
    datacat(data, "DeviceIdentify=%d\r\n", _reg_info.reg_id);
    datacat(data, "SysUserName=%s\r\n", "hsin");
    datacat(data, "LogonOnUserName=%s\r\n", "hsin");
    datacat(data, "LangId=%s\r\n", "zh_CN.UTF-8");
    datacat(data, "ActiveIPAddress=%s\r\n", _reg_info.reg_ip);
    return strlen(data);
}

/* 获取策略概况 */
static uint32_t
pull_policy_gen(char *buf)
{
    /* 连接服务器 */
    int sock;
    if(create_client_socket(&sock, _reg_info.srv_ip, _reg_info.srv_port)) {
        close_socket(sock);
        return FAIL;
    }
    /* 获取加密密钥 */
    DWORD key;
    if(get_encrypt_key(sock, &key)) {
        close_socket(sock);
        return FAIL;
    }
    key = 0;
    /* 获取本地网卡信息 */
    struct netcard_t netcard;
    get_netcard_info(&netcard);
    /* 构造请求数据 */
    char pkt[DATA_SIZE] = {0};
    struct packet_t *p_pkt = (struct packet_t *)pkt;
    package_data(p_pkt->data, &netcard);
    DWORD pkt_len = strlen(p_pkt->data) + sizeof(struct head_t);

    p_pkt->head.type = ENDIANS(DOWNLOAD_POLICY);
    p_pkt->head.what = ENDIANS(DETECT_POLICY);
    p_pkt->head.key = ENDIANL(key);
    p_pkt->head.pkt_len = ENDIANL(pkt_len);
    /* 发送数据 */
    if(send_pkt(sock, p_pkt)) {
        LOG_ERR("Send 请求策略数据失败!\n");
        close_socket(sock);
        return FAIL;
    }
    p_pkt = NULL;
    /* 接收数据 */
    if(recv_pkt(sock, &p_pkt)) {
        LOG_ERR("Recv 策略概况数据失败!\n");
        close_socket(sock);
        free(p_pkt);
        return FAIL;
    }
    close_socket(sock);
    /* 判断返回信息 */
    LOG_MSG("%u,%u\n", ENDIANL(p_pkt->head.flag), ENDIANS(p_pkt->head.type));
    if(ENDIANL(p_pkt->head.flag) != VRV_FLAG) {
        LOG_ERR("Recv ret flag error\n");
        free(p_pkt);
        return FAIL ;
    }
    DWORD data_len = ENDIANL(p_pkt->head.pkt_len) - sizeof(struct head_t);
    memcpy(buf, p_pkt->data, data_len);
    free(p_pkt);
    return OK;
}

/* 获取从beg开始到end结束的字符串值 */
static char*
get_tag_val(const char *data, const char * beg, const char * end, char *val)
{
    char *beg_mrk = strlen(beg) + strstr(data, beg);
    if(beg_mrk == NULL)
        return NULL;
    char *end_mrk = strstr(beg_mrk, end);
    if(end_mrk == NULL)
        strcpy(val, beg_mrk);
    else
        strncpy(val, beg_mrk, end_mrk - beg_mrk);
    /* 尽头的张望 */
    val[end_mrk - beg_mrk] ='\0';
    return val;
}
/* 获取策略概况列表 */
static uint32_t
get_policy_list(char *buf, struct policy_gen_t *list)
{
    char tmp[UNIT_SIZE] = {0};
    char tag[UNIT_SIZE] = {0};
    uint32_t count = atoi(get_tag_val(buf, POLICY_COUNT_TAG, ".", tmp));
    uint32_t i = 0;
    for(i = 0; i < count; i++) {
        sprintf(tag, "_ID%u=", i);
        list[i].id = atoi(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_FUNC%u=", i);
        list[i].type = type_from_target(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_CRC%u=", i);
        list[i].crc = atoi(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_FLG%u=", i);
        list[i].flag = atoi(get_tag_val(buf, tag, ".", tmp));
    }
    return OK;
}
static uint32_t
down_policy2db(const char *content)
{
    int sock;
    /* 创建客户端套接字 */
    if(create_client_socket(&sock, _reg_info.srv_ip, _reg_info.srv_port)) {
        LOG_ERR("Create client socket error!\n");
        return FAIL;
    }
    /* 获取加密密钥 */
    uint32_t key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close_socket(sock);
        return FAIL;
    }
    /* 构造通用数据 */
    char pkt[DATA_SIZE] = {0};
    struct packet_t *p_pkt = (struct packet_t *)pkt;
    struct netcard_t netcard;
    package_data(p_pkt->data, &netcard);
    /* 粘贴需要上报数据 */
    strcat(p_pkt->data, content);
    DWORD pkt_len = strlen(p_pkt->data) + sizeof(struct head_t);
    p_pkt->head.type = ENDIANS(DOWNLOAD_POLICY);
    p_pkt->head.what = ENDIANS(GET_POLICY);
    p_pkt->head.key = ENDIANL(key);
    p_pkt->head.pkt_len = ENDIANL(pkt_len);
    /* 发送数据 */
    if(send_pkt(sock, p_pkt)) {
        LOG_ERR("Send 请求策略数据失败!\n");
        close_socket(sock);
        return FAIL;
    }
    /* 接收数据 */
    if(recv_pkt(sock, &p_pkt)) {
        LOG_ERR("Recv 策略概况数据失败!\n");
        close_socket(sock);
        free(p_pkt);
        return FAIL;
    }
    close_socket(sock);
    /* 判断返回信息 */
    LOG_MSG("%u,%u\n", ENDIANL(p_pkt->head.flag), ENDIANS(p_pkt->head.type));
    if(ENDIANL(p_pkt->head.flag) != VRV_FLAG) {
        LOG_ERR("Recv ret flag error\n");
        free(p_pkt);
        return FAIL ;
    }
    /* 把策略 存入数据库 */
    char tmp[UNIT_SIZE] = {0};
    char tag[UNIT_SIZE] = {0};
    uint32_t i = 0,count = atoi(get_tag_val(p_pkt->data, "_COUNT=", ".", tmp));
    for(i = 0; i < count; i++) {
        char xml[DATA_SIZE];
        sprintf(tag, "P_CONTENT%u=", i);
        get_tag_val(p_pkt->data, tag, "._", xml);
        sprintf(tag, "_FUNC%u=", i);
        get_tag_val(p_pkt->data, tag, ".", tmp);
        strcat (tmp, ".xml");
        trim_str(tmp);
        FILE* pf = fopen(tmp, "w+");
        fwrite(xml, strlen(xml), 1, pf);
        fclose(pf);
    }
    free(p_pkt);
    return OK;
}
/* 拉取策略并存入数据库 */
uint32_t
pull_policy(char *buf)
{
    int ret = 0;
    /* 获取策略概况 */
    if(pull_policy_gen(buf)) {
        LOG_MSG("获取策略概况失败..\n");
        return FAIL;
    }
    LOG_MSG("策略概况:\n--------------------\n%s--------------------\n", buf);
    trim_str(buf);
    char tmp[UNIT_SIZE] = {0};
    uint32_t count = atoi(get_tag_val(buf, POLICY_COUNT_TAG, ".", tmp));
    LOG_MSG("Policy Count = %u\n", count);
    if(count == 0) {
        return FAIL;
    }
    /* 分配临时空间 避免malloc,小心栈溢出 */
    struct policy_gen_t list[count];
    memset(list, 0, count *sizeof(struct policy_gen_t));
    /* 把策略概要 整理为列表 */
    ret = get_policy_list(buf, list);
    if(ret) {
        LOG_MSG("Analytical Policys Gen List Failed!");
        return FAIL;
    }
    char id_str[LINE_SIZE] = {0};
    char flag_str[LINE_SIZE] = {0};
    uint32_t i = 0;
    for(i = 0; i < count; i++) {
        /* 过滤掉不支持的策略 */
        if(list[i].type == POLICY_TYPE_COUNT)
            continue;
        /* 过滤掉未变化的策略 */
        LOG_MSG("Delete unused policy\n");
        datacat(id_str, "%u,", list[i].id);
        datacat(flag_str, "%u,", list[i].flag);
    }
    /* 需要下载的策略 */
    char content[LINE_SIZE] = {0};
    datacat(content, "Policys=%s\r\n", id_str);
    datacat(content, "FLG=%s\r\n", flag_str);
    printf("--------------\n%s\n--------------\n", content);
    /* 下载策略到数据库 */
    LOG_MSG("Begin download policy to database\n");
    down_policy2db(content);
    return OK;
}

/* 上报函数 */
uint32_t
send_audit_log(const char *data, char* ip, uint32_t port)
{
    int sock;
    /* 创建客户端套接字 */
    if(create_client_socket(&sock, ip, port)) {
        LOG_ERR("Create client socket error!\n");
        return FAIL;
    }
    /* 获取加密密钥 */
    uint32_t key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close_socket(sock);
        return FAIL;
    }
    /* 构造通用数据 */
    char pkt[DATA_SIZE] = {0};
    struct packet_t *p_pkt = (struct packet_t *)pkt;
    struct netcard_t netcard;
    package_data(p_pkt->data, &netcard);
    /* 粘贴需要上报数据 */
    strcat(p_pkt->data, data);
    DWORD pkt_len = strlen(p_pkt->data) + sizeof(struct head_t);
    printf("%s",p_pkt->data);
    p_pkt->head.type = ENDIANS(AGENT_RPTAUDITLOG);
    p_pkt->head.what = ENDIANS(AUDITLOG_REQUEST);
    p_pkt->head.key = ENDIANL(key);
    p_pkt->head.pkt_len = ENDIANL(pkt_len);
    /* 发送数据 */
    if(send_pkt(sock, p_pkt)) {
        LOG_ERR("Send 请求策略数据失败!\n");
        close_socket(sock);
        return FAIL;
    }
    /* 接收数据 */
    if(recv_pkt(sock, &p_pkt)) {
        LOG_ERR("Recv 策略概况数据失败!\n");
        close_socket(sock);
        free(p_pkt);
        return FAIL;
    }
    close_socket(sock);
    /* 判断返回信息 */
    LOG_MSG("%u,%u\n", ENDIANL(p_pkt->head.flag), ENDIANS(p_pkt->head.type));
    if(ENDIANL(p_pkt->head.flag) != VRV_FLAG) {
        LOG_ERR("Recv ret flag error\n");
        free(p_pkt);
        return FAIL ;
    }
    free(p_pkt);
    return OK;
}

/* 心跳函数 */
uint32_t
do_heart_beat(char* ip, uint16_t port)
{
    int sock;
    /* 创建客户端套接字 */
    if(create_client_socket(&sock, ip, port)) {
        LOG_ERR("Create client socket error!\n");
        return FAIL;
    }
    /* 获取加密密钥 */
    uint32_t key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close_socket(sock);
        return FAIL;
    }
    char data[BUFF_SIZE] = {0};
    /* 获取本地网卡信息 */
    struct netcard_t netcard;
    get_netcard_info(&netcard);
    package_data(data, &netcard);
    DWORD pkt_len = sizeof(struct head_ex_t) + strlen(data);
    char buf[pkt_len];
    struct packet_ex_t *pkt = (struct packet_ex_t *)buf;
    pkt->head.type = ENDIANS(AGENT_GETCONFIG_STRING);
    pkt->head.what = ENDIANS(0);
    pkt->head.key = ENDIANL(key);
    pkt->head.data_crc = ENDIANL(0);
    pkt->head.address = ENDIANL(0);
    pkt->head.pkt_len = ENDIANL(pkt_len);
    memcpy(pkt->data, data, strlen(data));
    if(send_pkt_ex(sock, pkt)) {
        LOG_ERR("Send register info error!\n");
        close_socket(sock);
        return FAIL;
    }
    /* 接收返回信息 */
    if(recv_pkt_ex(sock, &pkt)) {
        LOG_ERR("Recv register info ret error!\n");
        close_socket(sock);
        return FAIL;
    }
    close_socket(sock);
    LOG_MSG("Recv flag = %u type = %d\n", ENDIANL(pkt->head.flag), ENDIANS(pkt->head.type));
    /* 判断返回信息 */
    if(ENDIANL(pkt->head.flag) != VRV_FLAG) {
        LOG_ERR("Recv ret flag error\n");
        free(pkt);
        return FAIL ;
    }
    free(pkt);
    return OK;
}
