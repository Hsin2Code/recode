#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "protocol.h"
#include "register.h"
#include "journal.h"
#include "type.h"
#include "base.h"
#include "socket.h"

/* 注册函数 */
static uint32_t
register_info(uint32_t type, char *buf, char *value)
{
    char tmp[LINE_SIZE] = {0};
    sprintf(tmp, "DBField%d=DeptName\r\nDBValue%d=%s\r\n", type, type, value);
    strcat(buf, tmp);
    return OK;
}

uint32_t
do_register(char *ip, uint16_t port)
{
    char * ip_str = "192.168.133.113";
    uint32_t dev_id = 8888888;

    char buf[BUFF_SIZE] = {0};
    char tmp[LINE_SIZE] = {0};
    register_info( 0, buf, "hsin");        /* 姓名 */
    register_info( 1, buf, "beixinyuan");  /* 部门 */
    register_info( 2, buf, "wangluo");     /* 办公室 */
    register_info( 3, buf, "101");         /* 门排号 */
    register_info( 4, buf, "123456789");   /* 电话 */
    register_info( 5, buf, "123@123.com"); /* 邮箱 */
    register_info( 6, buf, "AIXtest");     /* 保留字段 */
    register_info( 7, buf, "710100");      /* 邮编？ */
    strcat(buf, "DBFieldCount=8\r\n");
    strcat(buf, "SelectNicInfo=xxx.xxx.xxx.xxx/000c29d6b5d9\r\n");
    strcat(buf, "WebServerIP=192.168.131.94\r\n");
    strcat(buf, "MACAddress0=xx-xx-xx-xx-xx-xx\r\n");
    sprintf(tmp, "IPAddress0=%s\r\n", ip_str);
    strcat(buf, tmp);
    strcat(buf, "MACCount=1\r\nIPCount=1\r\n");
    sprintf(tmp, "DeviceIdentify=%u\r\n", dev_id);
    strcat(buf, tmp);
    strcat(buf, "ComputerName=fake computer name\r\n");
    strcat(buf, "EdpRegVersion=3.3.3.3\r\n");
    strcat(buf, "OSVersion=2.6\r\n");
    strcat(buf, "OSType=GNU/Linux\r\n");
    LOG_ERR("builde basic register info success\n");

    /* 创建客户端套接字 */
    int sock;
    if(create_client_socket(&sock, ip, port)) {
        LOG_ERR("Create client socket error!\n");
        return FAIL;
    }
    /* 获取加密密钥 */
    DWORD key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close(sock);
        return FAIL;
    }
    printf("key = %u\n", key);
    DWORD pkt_len = sizeof(struct head_ex_t) + strlen(buf);
    struct packet_ex_t *pkt = (struct packet_ex_t *)malloc(pkt_len);
    pkt->head.type = ENDIANS(REG_DEVICE_STRING);
    pkt->head.what = ENDIANS(0);
    pkt->head.key = ENDIANL(key);
    pkt->head.data_crc = ENDIANL(0);
    pkt->head.address = ENDIANL(0);
    pkt->head.pkt_len = ENDIANL(pkt_len);
    memcpy(pkt->data, buf, strlen(buf));
    if(send_pkt_ex(sock, pkt)) {
        LOG_ERR("Send register info error!\n");
        close(sock);
        return FAIL;
    }
    free(pkt);
    /* 接收返回信息 */
    if(recv_pkt_ex(sock, &pkt)) {
        LOG_ERR("Recv register info ret error!\n");
        close(sock);
        return FAIL;
    }
    close(sock);
    LOG_MSG("Recv flag = %u type = %d\n", ENDIANL(pkt->head.flag), ENDIANS(pkt->head.type));
     /* 判断返回信息 */
    if(ENDIANL(pkt->head.flag) != VRV_FLAG || ENDIANS(pkt->head.type) != EX_OK) {
        if(ENDIANL(pkt->head.flag) != VRV_FLAG)
            LOG_ERR("Recv ret flag error\n");
        if (ENDIANS(pkt->head.type) != EX_OK )
            LOG_ERR("Recv ret type error\n");
        free(pkt);
        return FAIL ;
    }
    free(pkt);
    return OK;
}
