#ifndef _ONLINE_DEAL_CTRL_H___
#define _ONLINE_DEAL_CTRL_H___
#include "type.h"

#define DEFAULT_ADDR "www.baidu.com"


uint32_t
online_deal_ctrl_init(void *arg);

uint32_t
online_deal_ctrl_work();

uint32_t
online_deal_ctrl_uninit();
#endif
