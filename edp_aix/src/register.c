#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "register.h"
#include "journal.h"
#include "type.h"
#include "common.h"
#include "socket.h"
#include "localdb.h"

extern struct reg_info_t _reg_info;

/* 检测网卡是否在某个IP端 */
uint32_t
detect_reg_ip(uint32_t ip_start, uint32_t ip_end)
{
    uint32_t ip = ntohl(inet_addr(_reg_info.reg_ip));
    if(ip_start < ip && ip < ip_end)
        return OK;
    return FAIL;
}
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
    LOG_MSG("------------------上报注册数据 开始--------------\n");
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
    LOG_MSG("%s\n",buf);
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
    LOG_MSG("------------------上报注册数据 结束--------------\n");
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

/* 选择一个网卡 */
uint32_t
choose_one_netcard(struct netcard_t *head, char *name)
{
    struct netcard_t *tmp, *next;
    next = head->next;
    do {
        tmp = next;
        if(strcmp(tmp->name, name) == 0) {
            strcpy(head->name, tmp->name);
            strcpy(head->ip, tmp->ip);
            strcpy(head->mac, tmp->mac);
            strcpy(head->broadcast, tmp->broadcast);
            strcpy(head->mask, tmp->mask);
            return OK;
        }
        next = tmp->next;
    }while(next != NULL);
    return FAIL;
}

static uint32_t
calc_dev_id(const char * mac) {
    int a,b,c,d,e,f;
    sscanf(mac, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f);
    if((a | b | c | d | e | f) == 0) {
        return FAIL;
    }
    return ((((uint32_t)(a) & 0x000000ff)) |                            \
            (((uint32_t)(b) << 16 & 0x00ff0000)) |                      \
            (((uint32_t)(e) << 8  & 0x0000ff00)) |                      \
            (((uint32_t)(f) << 24 &  0xff000000)));
}
/* 注册交互函数 */
uint32_t
do_register()
{
    LOG_MSG("------------------交互注册 开始--------------\n");
    memset(&_reg_info, 0, sizeof(struct reg_info_t));
    int sock;
    _reg_info.srv_port = DEFAULT_PORT;
    printf("##########################\n");
    printf("# 开始AIX EDP客户端注册  #\n");
    printf("##########################\n");
    printf("注: *号标记为必填\n");
    do {
        interaction(1, "请输入服务器IP(eg:xxx.xxx.xxx.xxx) *.", _reg_info.srv_ip);
        printf("开始检测服务器IP是否能联通......");
        if(OK == create_client_socket(&sock, _reg_info.srv_ip, _reg_info.srv_port)){
            close_socket(sock); /* 忘了关...吃亏了，妈蛋 */
            printf("[连接成功]\n");
            break;
        }
        printf("[连接失败]\n(请检查服务器IP地址并重新输入.....)\n");
    }while(1);
    struct netcard_t netcard_head;
    struct netcard_t *tmp, *next;
    if(get_local_netcard(&netcard_head)) {
        LOG_ERR("获取本地网卡失败\n");
        printf("本地无激活可用网卡,请配置网卡之后再注册!\n");
        exit(0);
    }
    next = netcard_head.next;
    printf("请选择注册网卡(输入网卡名称):\n");
    printf("name IPv4 address    MAC address      netmask         broadcast\n");
    do {
        tmp = next;
        printf("%s  %s %s %s %s\n",
               tmp->name, tmp->ip, tmp->mac, tmp->broadcast, tmp->mask);
        next = tmp->next;
    }while(next != NULL);
    char buf[UNIT_SIZE];
    printf("EDP# ");
    scanf("%s", buf);
    while(choose_one_netcard(&netcard_head, buf)) {
        printf("请输入正确的网卡名...\nEDP# ");
        scanf("%s", buf);
    }
    strcpy(_reg_info.reg_ip, netcard_head.ip);
    strcpy(_reg_info.reg_mac, netcard_head.mac);
    strcpy(_reg_info.reg_mask, netcard_head.mask);
    strcpy(_reg_info.reg_gw, netcard_head.broadcast);
    _reg_info.reg_id = calc_dev_id(netcard_head.mac);
    LOG_MSG("Get dev only ID is %u\n", _reg_info.reg_id);
    next = netcard_head.next;
    do{
        free(next);
        next = next->next;
    }while(next != NULL);

    interaction(1 ,"请输入单位名称. *", _reg_info.reg_com);
    interaction(1 ,"请输入部门名称. *", _reg_info.reg_dep);
    interaction(1 ,"请输入计算机所在地(eg:陕西西安) *.", _reg_info.reg_addr);
    interaction(1 ,"请输入使用人名称 *.", _reg_info.reg_user);
    interaction(1 ,"请输入使用人电话 *.", _reg_info.reg_tel);
    interaction(0 ,"请输入使用人邮箱.", _reg_info.reg_mail);
    interaction(0 ,"请输入备注信息.", _reg_info.reg_note);

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
    LOG_MSG("------------------交互注册 结束--------------\n");
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
