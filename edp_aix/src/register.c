#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "protocol.h"
#include "register.h"
#include "journal.h"
#include "type.h"
#include "common.h"
#include "socket.h"
#include "localdb.h"

extern struct reg_info_t _reg_info;

/* 注册函数的小弟 */
static uint32_t
register_info(char *data, uint32_t num , char* key, char *value)
{
    datacat(data, "DBField%d=%s\r\nDBValue%d=%s\r\n", num, key, num, value);
    return OK;
}
/* 注册函数 */
uint32_t
send_register(void)
{
    char buf[BUFF_SIZE] = {0};
    register_info(buf, 0, "UserName", _reg_info.reg_user); /* 姓名 */
    register_info(buf, 1, "DeptName", _reg_info.reg_com);  /* 单位 */
    register_info(buf, 2, "OfficeName", _reg_info.reg_dep); /* 办公室 */
    register_info(buf, 3, "RoomNumber", _reg_info.reg_addr); /* 计算机所在地 */
    register_info(buf, 4, "Tel", _reg_info.reg_tel);        /* 电话 */
    register_info(buf, 5, "Email", _reg_info.reg_mail);     /* 邮箱 */
    register_info(buf, 6, "Reserved2", _reg_info.reg_note); /* 保留字段 */
    register_info(buf, 7, "FloorNumber", "88888888"); /* 邮编? */
    strcat(buf, "DBFieldCount=8\r\n");
    strcat(buf, "SelectNicInfo=xxx.xxx.xxx.xxx/000c29d6b5d9\r\n");
    datacat(buf, "WebServerIP=%s\r\n", _reg_info.srv_ip);
    datacat(buf, "MACAddress0=%s\r\n",_reg_info.reg_mac);
    datacat(buf, "IPAddress0=%s\r\n", _reg_info.reg_ip);
    strcat(buf, "MACCount=1\r\nIPCount=1\r\n");
    datacat(buf, "DeviceIdentify=%u\r\n", _reg_info.reg_id);
    datacat(buf, "ComputerName=%s\r\n",_reg_info.reg_dev);
    datacat(buf, "EdpRegVersion=%s\r\n", VERSION);
    datacat(buf, "OSVersion=%s\r\n", "6.1");
    datacat(buf, "OSType=%s\r\n", _reg_info.reg_os);
    LOG_MSG("build basic register info success\n");
    printf("%s",buf);
    /* 创建客户端套接字 */
    int sock;
    if(create_client_socket(&sock, _reg_info.srv_ip, _reg_info.srv_port)) {
        LOG_ERR("Create client socket error!\n");
        return FAIL;
    }
    /* 获取加密密钥 */
    DWORD key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close_socket(sock);
        return FAIL;
    }
    LOG_MSG("key = %u\n", key);
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
        close_socket(sock);
        return FAIL;
    }
    free(pkt);
    /* 接收返回信息 */
    if(recv_pkt_ex(sock, &pkt)) {
        LOG_ERR("Recv register info ret error!\n");
        close_socket(sock);
        return FAIL;
    }
    close_socket(sock);
    LOG_MSG("Recv flag = %u type = %d\n", ENDIANL(pkt->head.flag), ENDIANS(pkt->head.type));
    /* 判断返回信息 */
    if(ENDIANL(pkt->head.flag) != VRV_FLAG || ENDIANS(pkt->head.type) != EX_OK) {
        if(ENDIANL(pkt->head.flag) != VRV_FLAG)
            LOG_ERR("Recv ret flag error\n");
        if(ENDIANS(pkt->head.type) != EX_OK )
            LOG_ERR("Recv ret type error\n");
        free(pkt);
        return FAIL ;
    }
    free(pkt);
    return OK;
}
/* 注册之小弟 人机交互 */
static uint32_t
interaction(uint32_t required, const char *msg, char *value)
{
    char buf[LINE_SIZE] = {0};
    printf("%s\nEDP# ",msg);
    scanf("%s",buf);
    do{
        if(strlen(buf) > FIELD_SIZE-1)
            printf("(你输入的信息有误，或过长..请重新输入)\n");
        else if(required && (strlen(buf) == 0))
            printf("(你输入的信息不能为空.)\n");
        else
            break;//跳出
        printf("%s\nEDP# ",msg);
        scanf("%s",buf);
    }while(1);
    if(strlen(buf) == 0)
        strcpy(value, "null");
    strcpy(value, buf);
    return OK;
}
/* 测试使用 */
uint32_t
dbug_register() {
    memset(&_reg_info, 0, sizeof(struct reg_info_t));
    strcpy(_reg_info.reg_ip, "192.168.133.106");
    strcpy(_reg_info.reg_mac, "xx-xx-xx-xx-xx-xx");
    _reg_info.reg_id = 7777777;
    _reg_info.srv_port = DEFAULT_PORT;
    strcpy(_reg_info.srv_ip, "192.168.133.145");
    strcpy(_reg_info.reg_com, "beixinyuan");
    strcpy(_reg_info.reg_dep, "wangluo");
    strcpy(_reg_info.reg_addr, "xian");
    strcpy(_reg_info.reg_user, "hsin");
    strcpy(_reg_info.reg_tel, "88888888");
    strcpy(_reg_info.reg_mail, "123.com");
    strcpy(_reg_info.reg_note, "AIXtest");
    strcpy(_reg_info.reg_dev, "AIX6.1");
    strcpy(_reg_info.reg_os, "AIX");

    if(OK == send_register()) {
        if(db_ins_register_info(&_reg_info)) {
            printf("##### 注册信息入库失败 #####\n");
            printf("请启动 /opt/edp/edp_client 重新注册\n");
            exit(0);
        }else {
            printf("######### 注册成功 #########\n");
        }
    }else {
        printf("######### 注册失败 #########\n");
        printf("请启动 /opt/edp/edp_client 重新注册\n");
        exit(0);
    }
    return OK;
}

/* 注册交互函数 */
uint32_t
do_register()
{
    memset(&_reg_info, 0, sizeof(struct reg_info_t));
    int sock;
    _reg_info.srv_port = DEFAULT_PORT;
    printf("##########################\n");
    printf("# 开始AIX EDP客户端注册  #\n");
    printf("##########################\n");
    printf("注: *号标记为必填\n");
    do {
        interaction(1, "请输入服务器IP(eg:xxx.xxx.xxx.xxx) *.", _reg_info.srv_ip);
        printf("开始检测服务器IP是否能联通......\n");
        if(OK == create_client_socket(&sock, _reg_info.srv_ip, _reg_info.srv_port)){
            close_socket(sock); /* 忘了关...吃亏了，妈蛋 */
            break;
        }
        printf("(服务器IP无法连通.....)\n");
    }while(1);
    printf("选取注册网卡(待开发...)\n");
    printf("注册IP写死:192.168.133.113 devid写死:88888888\n");
    strcpy(_reg_info.reg_ip, "192.168.133.113");
    strcpy(_reg_info.reg_mac, "xx:xx:xx:xx:xx:xx");
    _reg_info.reg_id = 88888888;
    interaction(1 ,"请输入单位名称. *", _reg_info.reg_com);
    interaction(1 ,"请输入部门名称. *", _reg_info.reg_dep);
    interaction(1 ,"请输入计算机所在地(eg:陕西西安) *.", _reg_info.reg_addr);
    interaction(1 ,"请输入使用人名称 *.", _reg_info.reg_user);
    interaction(1 ,"请输入使用人电话 *.", _reg_info.reg_tel);
    interaction(0 ,"请输入使用人邮箱.", _reg_info.reg_mail);
    interaction(0 ,"请输入备注信息.", _reg_info.reg_note);
    _reg_info.reg_id = 7777777;//暂时写死
    strcpy(_reg_info.reg_dev, "AIX 6.1");
    strcpy(_reg_info.reg_os, "AIX");

    if(OK == send_register()) {
        if(db_ins_register_info(&_reg_info)) {
            printf("##### 注册信息入库失败 #####\n");
            printf("请启动 /opt/edp/edp_client 重新注册\n");
            exit(0);
        }else {
            printf("######### 注册成功 #########\n");
        }
    }else {
        printf("######### 注册失败 #########\n");
        printf("请启动 /opt/edp/edp_client 重新注册\n");
        exit(0);
    }
    return OK;
}


/* 获取注册服务器地址 */
uint32_t
get_srv_addr(char *ip, uint16_t *port)
{
    strcpy(ip, _reg_info.srv_ip);
    *port = _reg_info.srv_port;
    return OK;
}
