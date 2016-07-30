#include <stdio.h>
#include <stdlib.h>
#include "tpool.h"

/* 工作者线程，从任务链表中取出任务并执行 */
static void*
thread_routine(void *arg)
{
    tpool_task_t *work;
    tpool_t *tpool = (tpool_t *)arg;
    while(1) {
        /* 如果线程池没有被销毁且没有任务要执行，则等待 */
        pthread_mutex_lock(&tpool->queue_lock);
        while(!tpool->queue_head && !tpool->shutdown) {
            pthread_cond_wait(&tpool->queue_ready, &tpool->queue_lock);
        }
        if(tpool->shutdown && !tpool->queue_head) {
            pthread_mutex_unlock(&tpool->queue_lock);
            pthread_exit(NULL);
        }
        work = tpool->queue_head;
        tpool->queue_head = tpool->queue_head->next;
        pthread_mutex_unlock(&tpool->queue_lock);
        /* 这里还可以取返回值 */
        work->routine(work->arg);
        free(work);
    }
    return NULL;
}

/* 创建线程池 */
tpool_t*
tpool_create(size_t max_thr_num)
{
    size_t i;
    tpool_t *tpool = calloc(1, sizeof(tpool_t));
    if(!tpool) {
        perror("calloc tpool...");
        return NULL;
    }
    /* 初始化 */
    tpool->shutdown = 0;
    tpool->max_thr_num = max_thr_num;
    tpool->queue_head = NULL;
    if(pthread_mutex_init(&tpool->queue_lock, NULL) != 0) {
        perror("pthread_mutex_init...");
        free(tpool);
        return NULL;
    }
    if(pthread_cond_init(&tpool->queue_ready, NULL) != 0) {
        perror("pthread_cond_init...");
        free(tpool);
        return NULL;
    }
    /* 创建工作线程 */
    tpool->thr_id = calloc(max_thr_num, sizeof(pthread_t));
    if(!tpool->thr_id) {
        perror("calloc thr_id...");
        free(tpool);
        return NULL;
    }
    for(i = 0; i < max_thr_num; i++) {
        if(pthread_create(&tpool->thr_id[i], NULL, thread_routine, (void*)tpool ) != 0 ) {
            perror("pthread_create");
            tpool_destroy(tpool);
            return NULL;
        }
    }
    return tpool;
}

/* 销毁线程池 */
void
tpool_destroy(tpool_t *tpool)
{
    size_t i;
    tpool_task_t *member;

    if(tpool->shutdown) {
        return;
    }
    tpool->shutdown = 1;
    /* 通知所有正在等待的线程 */
    pthread_mutex_lock(&tpool->queue_lock);
    pthread_cond_broadcast(&tpool->queue_ready);
    pthread_mutex_unlock(&tpool->queue_lock);
    for(i = 0; i < tpool->max_thr_num; i++) {
        pthread_join(tpool->thr_id[i], NULL);
    }
    /* 释放资源 */
    free(tpool->thr_id);
    while(tpool->queue_head) {
        member = tpool->queue_head;
        tpool->queue_head = tpool->queue_head->next;
        free(member);
    }
    pthread_mutex_destroy(&tpool->queue_lock);
    pthread_cond_destroy(&tpool->queue_ready);

    free(tpool);
}

/* 向线程添加任务 */
size_t
tpool_task_add(tpool_t *tpool, callback_t routine, void *arg)
{
    tpool_task_t *work, *member;
    if(!routine) {
        fprintf(stderr,"Invalid argument...");
        return -1;
    }
    /* 如果线程池关机则不再添加 */
    if(tpool->shutdown) {
        fprintf(stderr,"thread pool shutdown...");
        return -1;
    }
    /* 添加任务到队列中 */
    work = malloc(sizeof(tpool_task_t));
    if(!work) {
        perror("malloc work failed...");
        return -1;
    }
    work->routine = routine;
    work->arg = arg;
    work->next = NULL;
    pthread_mutex_lock(&tpool->queue_lock);
    member = tpool->queue_head;
    if(!member) {
        tpool->queue_head = work;
    } else {
        while(member->next) {
            member = member->next;
        }
        member->next = work;
    }
    /* 通知所有工作者线程，有任务添加 */
    pthread_cond_signal(&tpool->queue_ready);
    pthread_mutex_unlock(&tpool->queue_lock);

    return 0;
}
