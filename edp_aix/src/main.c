#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "socket.h"
#include "journal.h"
#include "comint.h"
#include "common.h"
#include "protocol.h"
#include "base.h"
#include "register.h"
#include "comint.h"
#include "tpool.h"
/* 全局变量 必须全部放置在这里 */
struct reg_info_t _reg_info;


/* 心跳线程 */
void *thread_heart_beat(void *arg)
{
    do_heart_beat(_reg_info.srv_ip, _reg_info.srv_port);
    return NULL;
}
/* 获取策略线程 */
void *thread_pull_policy(void *arg)
{
    return NULL;
}
int main(int argc,char **argv) {
    /* 创建线程池 */
    tpool_t *tpool = tpool_create(4);
    if(tpool == NULL) {
        LOG_MSG("tpool_create failed...\n");
        return FAIL;
    }

    /* 注册 */
    //    do_register("192.168.133.143", 88);
    while(1){
        /* 需要一个状态机控制 */
        /* 心跳 */
        tpool_task_add(tpool,thread_heart_beat,NULL);
        sleep(10);
        /* 获取策略 */
        tpool_task_add(tpool,thread_pull_policy,NULL);
        sleep(10);
        /* 执行策略 */
        sleep(10);
    }
    tpool_destroy(tpool);
    return OK;
}
