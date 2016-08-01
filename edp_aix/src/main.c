#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "sqlite3.h"
#include "socket.h"
#include "journal.h"
#include "comint.h"
#include "common.h"
#include "protocol.h"
#include "register.h"
#include "comint.h"
#include "thpool.h"
/* 全局变量 必须全部放置在这里 */
struct reg_info_t _reg_info;


/* 心跳线程 */
void *
thread_heart_beat(void *arg)
{
    do_heart_beat(_reg_info.srv_ip, _reg_info.srv_port);
    return NULL;
}
/* 获取策略线程 */
void *
thread_pull_policy(void *arg)
{
    char buf[BUFF_SIZE] = {0};
    pull_policy(buf);
    return NULL;
}

void
policy_scheduling(threadpool *thpool)
{

}

int
main(int argc,char **argv) {
    /* 创建线程池 */
    threadpool thpool = thpool_init(10);
    sqlite3 *db = NULL;
    sqlite3_open("local.db", &db);

    if(thpool == NULL) {
        LOG_MSG("thpool_create failed...\n");
        return FAIL;
    }
    get_register_info(&_reg_info);
    /* 注册 */
    if(do_register("192.168.133.143", 88))
        LOG_ERR("register failed\n");
    int i = 10000;
    while(i--){
        /* 需要一个状态机控制 */
        /* 心跳 */
        thpool_add_work(thpool, thread_heart_beat, NULL);
        //tpool_task_add(tpool,thread_heart_beat,NULL);
        //sleep(10);
        /* 获取策略 */
        thpool_add_work(thpool, thread_pull_policy, NULL);
        //sleep(10);
        /* 执行策略 */
        //policy_scheduling(thpool);
        //sleep(10);
    }
    thpool_wait(thpool);
    thpool_destroy(thpool);
    return OK;
}
