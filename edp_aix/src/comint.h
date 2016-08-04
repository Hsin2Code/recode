#ifndef _COMINT_H___
#define _COMINT_H___
#include "type.h"

#define POLICY_COUNT_TAG  "_COUNT="
#define STRITEM_TAG_END   "\r\n"
#define POLICY_END_TAG    "</vrvscript>" /* 策略XML结束标志 */


struct policy_gen_t {
    DWORD id;
    DWORD crc;
    DWORD type;
    DWORD flag;
    /* DWORD func; */
};



/* 策略类型枚举值 */
enum policy_type {
    /* 本次只针对违规外联 */
    ONLINE_DEAL_CTRL,
    /* 最大策略数 */
    POLICY_TYPE_COUNT,
};
/* 获取策略概况 */
uint32_t
pull_policy(void);
/* 心跳函数 */
uint32_t
do_heart_beat(char* ip, uint16_t port);
/* 上报函数 */
uint32_t
send_audit_log(uint16_t type, uint16_t what, const char *data);

#endif
