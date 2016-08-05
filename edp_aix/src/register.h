#ifndef _REGISTER_H___
#define _REGISTER_H___

#include "type.h"

#define VERSION "1.0.0.1"

#define REGISTERED           1  /* 已经注册 */

#define DEFAULT_PORT         88 /* 默认通信服务端口 */
struct reg_info_t{
    uint32_t reg_id;
    char reg_ip[FIELD_SIZE];
    char reg_mac[FIELD_SIZE];
    char reg_mask[FIELD_SIZE];
    char reg_gw[FIELD_SIZE];
    char reg_com[FIELD_SIZE];
    char reg_dep[FIELD_SIZE];
    char reg_addr[FIELD_SIZE];
    char reg_user[FIELD_SIZE];
    char reg_tel[FIELD_SIZE];
    char reg_mail[FIELD_SIZE];
    char reg_note[FIELD_SIZE];
    char reg_os[FIELD_SIZE];
    char reg_dev[FIELD_SIZE];
    char srv_ip[FIELD_SIZE];
    uint16_t srv_port;
};

/* 测试使用 */
uint32_t
dbug_register(void);

/* 注册函数 */
uint32_t
do_register(void);

/* 从配置文件中获取注册信息 */
uint32_t
get_register_info(struct reg_info_t *reg_info);

/* 获取服务器地址 */
uint32_t
get_srv_addr(char *ip,uint16_t *port);

/* 获取注册服务器地址 */
uint32_t
get_srv_addr(char *ip, uint16_t *port);
/* 检测注册IP是否在范围内 */

uint32_t
detect_reg_ip(uint32_t ip_start, uint32_t ip_end);

#endif
