#ifndef _COMINT_H___
#define _COMINT_H___
#include "type.h"


struct policy_gist_t {
    void *send_str;
    void *recv_str;
};
struct policy_gen_t {
    int id;

};

struct netcard_t {
    char ip[16];
    char mac[16];
    char gw[16];
    char mask[16];
    char name[16];
};


/* 策略类型枚举值 */
enum policy_type {
    /* 本次只针对违规外联 */
    ONLINE_DEAL_CTRL,
    /* 最大策略数 */
    POLICY_TYPE_COUNT,
};

#endif
