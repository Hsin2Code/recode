#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

#include "localdb.h"
#include "sqlite3.h"
#include "socket.h"
#include "journal.h"
#include "comint.h"
#include "common.h"
#include "protocol.h"
#include "register.h"
#include "comint.h"
#include "thpool.h"
#include "online_deal_ctrl.h"
#include "main.h"
/* 全局变量 必须全部放置在这里 */
struct reg_info_t _reg_info;

/* 心跳线程 */
static void *
thread_heart_beat(void *arg)
{
    while(1) {
        do_heart_beat(_reg_info.srv_ip, _reg_info.srv_port);
        sleep(30);
    }
    return NULL;
}
/* 获取策略线程 */
static void *
thread_pull_policy(void *arg)
{
    while(1) {
        pull_policy();
        sleep(30);
    }
    return NULL;
}

static void *
thread_do_main(void *arg)
{
    uint32_t crc_list[POLICY_TYPE_COUNT] = {0};
    char xml[DATA_SIZE] = {0};
    struct policy_gen_t gen;
    while(1) {
        db_que_policy(&gen, xml);
        if(gen.flag != 1) {
            if(crc_list[gen.type] != gen.crc) {
                printf("初始化策略\n");
                online_deal_ctrl_uninit();
                online_deal_ctrl_init(xml);
                crc_list[gen.type] = gen.crc;
            }
            online_deal_ctrl_work();
        }
        sleep(5);
    }
    return NULL;
}
static void *
thread_send_report(void *arg)
{
    while(1) {
        /* 上报数据 */
        db_send_report();
        sleep(30);
    }
    return NULL;
}
/* 防止僵尸进程 */
void sig_chld(int signo)
{
    if(signo == SIGCHLD) {
        int stat;
        pid_t pid = wait(&stat);
        LOG_ERR("守护进程挂了变戏法喽...%d...\n", pid);
        return;
    }
}
int
main(int argc,char **argv)
{
    if(db_conn()) {
        LOG_MSG("连接数据库失败\n");
        return FAIL;
    }
    /* 未注册则 注册 */
    if(db_que_register_info(&_reg_info) != REGISTERED) {
        db_init();
        do_register();
        //dbug_register();
    }
    if(fork() != 0) exit(0);    /* parent  */
    if(setsid() == -1) {
        printf("setsid failed\n");
        exit(-1);
    }
    int stdfd = open ("/dev/null", O_RDWR);
    dup2(stdfd, STDOUT_FILENO);
    dup2(stdfd, STDERR_FILENO);
    chdir("/opt/edp/bin/");
    int ppid = getpid();
    int cpid = fork();
    if(cpid == 0) {
        if(setsid() == -1) {
            exit(-1);
        }
        sprintf(argv[0], "watchv");
        while(1) {
            sleep(5);
            int ret = kill(ppid ,0);
            if(ret != 0) {
                system("./edp_client");
                sleep(3);
                exit(0);
            }
        }
    }
    signal(SIGCHLD, &sig_chld);
    pthread_t tid_beat = 0, tid_policy = 0;
    pthread_t tid_main = 0, tid_report = 0;
    while(1){
        /* 需要一个状态机控制 */
        /* 获取策略 */
        if(tid_policy == 0) {
            pthread_create(&tid_policy, NULL, thread_pull_policy, NULL);
            LOG_RUN("获取策略线程创建成功\n");
        }else{
            /* 监测线程是否存在 */
            if(ESRCH == pthread_kill(tid_policy, 0))
                tid_beat = 0;
        }
        sleep(2);
        /* 执行策略 */
        if(tid_main == 0) {
            pthread_create(&tid_main, NULL, thread_do_main, NULL);
            LOG_RUN("执行策略线程创建成功\n");
        }else{
            /* 监测线程是否存在 */
            if(ESRCH == pthread_kill(tid_main, 0))
                tid_beat = 0;
        }
        sleep(2);
        /* 心跳 */
        if(tid_beat == 0) {
            pthread_create(&tid_beat, NULL, thread_heart_beat, NULL);
            LOG_RUN("心跳线程创建成功\n");
        }else{
            /* 监测线程是否存在 */
            if(ESRCH == pthread_kill(tid_beat, 0))
                tid_beat = 0;
        }
        sleep(2);
        /* 上报审计 */
        if(tid_report == 0) {
            pthread_create(&tid_report, NULL, thread_send_report, NULL);
            LOG_RUN("上报审计线程创建成功\n");
        }else{
            /* 监测线程是否存在 */
            if(ESRCH == pthread_kill(tid_report, 0))
                tid_beat = 0;
        }
        int ret = kill(cpid ,0);
        if(ret != 0) {
            system("./edp_client");
            exit(0);
        }
    }
    db_close();
    return OK;
}

/* 创建定时器 */
/* 创建线程池 */
/* threadpool thpool = thpool_init(4); */
/* if(thpool == NULL) { */
/*     LOG_MSG("thpool_create failed...\n"); */
/*     return FAIL; */
/* } */
/* thpool_wait(thpool); */
/* thpool_destroy(thpool); */
