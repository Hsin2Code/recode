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
#include "localdb.h"

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
package_data(char * data)
{
    datacat(data, "MACAddress0=%s\r\n", _reg_info.reg_mac);
    datacat(data, "IPAddress0=%s\r\n", _reg_info.reg_ip);
    datacat(data, "MACCount=1\r\nIPCount=1\r\n");
    datacat(data, "IPReport=%s|%s|%s|%s*84C9B2A7E124|8.8.8.8#\r\n",
            _reg_info.reg_mac, _reg_info.reg_ip,
            _reg_info.reg_mask,_reg_info.reg_gw);
    datacat(data, "DeviceIdentify=%d\r\n", _reg_info.reg_id);
    datacat(data, "SysUserName=%s\r\n", "root");
    datacat(data, "LogonOnUserName=%s\r\n", "root");
    datacat(data, "LangId=%s\r\n", "zh_CN.UTF-8");
    datacat(data, "ActiveIPAddress=%s\r\n", _reg_info.reg_ip);
    return strlen(data);
}

/* 获取策略概况 */
static uint32_t
pull_policy_gen(char *buf)
{
    LOG_MSG("----------------拉取策略概况 开始----------------\n");
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
//    key = 0;

    /* 构造请求数据 */
    char pkt[DATA_SIZE] = {0};
    struct packet_t *p_pkt = (struct packet_t *)pkt;
    package_data(p_pkt->data);
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
    LOG_MSG("----------------拉取策略概况 结束----------------\n");
    return OK;
}

/* 下载更新策略 */
static uint32_t
down_policy2db(const char *content)
{
    LOG_MSG("----------------下载更新策略 开始----------------\n");
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
    package_data(p_pkt->data);
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
    struct policy_gen_t gen;
    memset(&gen, 0, sizeof(gen));
    for(i = 0; i < count; i++) {
        char xml[DATA_SIZE];
        sprintf(tag, "P_CONTENT%u=", i);
        get_tag_val(p_pkt->data, tag, "._", xml);
        sprintf(tag, "_ID%u=", i);
        gen.id = atoi(trim_str(get_tag_val(p_pkt->data, tag, ".", tmp)));
        sprintf(tag, "_FUNC%u=", i);
        gen.type = type_from_target(trim_str(get_tag_val(p_pkt->data, tag, ".", tmp)));
        sprintf(tag, "_CRC%u=", i);
        gen.crc = atoi(trim_str(get_tag_val(p_pkt->data, tag, ".", tmp)));
        db_update_policy(&gen, xml);
    }
    LOG_MSG("----------------下载更新策略 结束----------------\n");
    free(p_pkt);
    return OK;
}
/* 拉取策略并存入数据库 */
uint32_t
pull_policy(void)
{
    LOG_MSG("----------------拉取策略主函数 开始----------------\n");
    char buf[BUFF_SIZE] = {0};
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
    char tag[UNIT_SIZE] = {0};
    uint32_t i, j;
    /* 过滤掉未变化的策略 */
    struct policy_gen_t list[count];
    for(i = 0; i < count; i++) {
        sprintf(tag, "_FUNC%u=", i);
        list[i].type = type_from_target(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_CRC%u=", i);
        list[i].crc = atoi(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_ID%u=", i);
        list[i].id = atoi(get_tag_val(buf, tag, ".", tmp));
        sprintf(tag, "_FLG%u=", i);
        list[i].flag = atoi(get_tag_val(buf, tag, ".", tmp));
    }
    char id_str[LINE_SIZE] = {0};
    char flag_str[LINE_SIZE] = {0};
    struct policy_gen_t gen;
    memset(&gen, 0, sizeof(gen));
    for(j = 0; j < POLICY_TYPE_COUNT; j++) {
        gen.type = j;
        for(i = 0; i < count; i++) {
            if(list[i].type == j) {
                if(db_que_policy(&gen, NULL)) {
                    ;//break;
                }
                /* CRC不一样更新策略 */
                if(gen.crc != list[i].crc) {
                    datacat(id_str, "%u,", list[i].id);
                    datacat(flag_str, "%u,", list[i].flag);
                }else {
                    LOG_MSG("%s CRC未变化无需重新拉去...\n", policy_target[j]);
                    db_ctrl_policy(&gen, 0);//启用
                }
                i += count;
            }
        }
        if(i <= count) {
            LOG_MSG("i= %u count = %u ---> %s 禁用策略...\n", i, count, policy_target[gen.type]);
            db_ctrl_policy(&gen, 1);//禁用
        }
    }
    if(strlen(id_str) == 0) return FAIL;
    /* 更新下载的策略 */
    char content[LINE_SIZE] = {0};
    datacat(content, "Policys=%s\r\n", id_str);
    datacat(content, "FLG=%s\r\n", flag_str);
    LOG_MSG("拉取以下策略"                                      \
            "--------------\n%s\n--------------\n", content);
    /* 更新策略到数据库 */
    LOG_MSG("Begin download policy to database\n");
    if(down_policy2db(content))
        return FAIL;
    LOG_MSG("----------------拉取策略主函数 结束----------------\n");
    return OK;
}

/* 上报函数 */
uint32_t
send_audit_log(uint16_t type, uint16_t what, const char *data)
{
    LOG_MSG("----------------上报审计信息 开始----------------\n");
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
    package_data(p_pkt->data);
    /* 粘贴需要上报数据 */
    strcat(p_pkt->data, data);
    DWORD pkt_len = strlen(p_pkt->data) + sizeof(struct head_t);
//    printf("%s",p_pkt->data);
    p_pkt->head.type = ENDIANS(type);
    p_pkt->head.what = ENDIANS(what);
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
    LOG_MSG("----------------上报审计信息 结束----------------\n");
    return OK;
}

/* 心跳函数 */
uint32_t
do_heart_beat(char* ip, uint16_t port)
{
    LOG_MSG("----------------心跳 开始----------------\n");
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
    /* 构造通用数据 */
    package_data(data);
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
    LOG_MSG("----------------心跳 结束----------------\n");
    return OK;
}
