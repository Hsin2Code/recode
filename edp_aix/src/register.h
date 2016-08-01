#ifndef _REGISTER_H___
#define _REGISTER_H___

#include <stdint.h>

struct reg_info_t
{
    char srv_ip[16];
    char reg_ip[16];
    char reg_mac[16];
    char clt_ver[16];
    uint16_t srv_port;
    uint32_t reg_id;
};

/* 注册函数 */
uint32_t
do_register(char *ip, uint16_t port);

/* 从配置文件中获取注册信息 */
uint32_t
get_register_info(struct reg_info_t *reg_info);



#endif
