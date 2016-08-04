#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "register.h"
#include "sqlite3.h"
#include "localdb.h"
#include "journal.h"
#include "comint.h"
#include "type.h"

static sqlite3 *db = NULL;

/********************  数据库操作封装 ******************/
/* 连接数据库 */
uint32_t
db_conn()
{
    int ret = sqlite3_open(LOCALDB_PATH, &db);
    if( ret != SQLITE_OK){
        LOG_DB("Error open database: %s\n", sqlite3_errmsg(db));
        return FAIL;
    }
    return OK;
}

/* 数据库初始化 */
uint32_t
db_init()
{
    /* 创建策略存储表 */
    const char *sql_policy = "create table tbl_policy("      \
        "type INTEGER PRIMARY KEY,"                          \
        "id INTEGER,"                                        \
        "crc INTEGER,"                                       \
        "flag INTEGER,"                                      \
        "data TEXT)";
    const char * sql_audit = "create table tbl_report("                 \
        "id INTEGER PRIMARY KEY,"                                       \
        "type INTEGER,"                                                 \
        "what INTEGER,"                                                 \
        "data TEXT,"                                                    \
        "time TimeStamp NOT NULL DEFAULT (datetime('now','localtime')))";//CURRENT_TIMESTAMP
    const char * sql_register = "create table tbl_register("      \
        "reg_id INTEGER,"                                         \
        "reg_ip TEXT,"                                            \
        "reg_mac TEXT,"                                           \
        "reg_dev TEXT,"                                           \
        "reg_com TEXT,"                                           \
        "reg_dep TEXT,"                                           \
        "reg_addr TEXT,"                                          \
        "reg_user TEXT,"                                          \
        "reg_tel TEXT,"                                           \
        "reg_mail TEXT,"                                          \
        "reg_note TEXT,"                                          \
        "reg_os TEXT,"                                            \
        "srv_ip TEXT,"                                            \
        "srv_port INTEGER)";
    char *err_msg = NULL;
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_exec(db, sql_policy, NULL, 0, &err_msg);
    if( ret != SQLITE_OK ){
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }

    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    ret = sqlite3_exec(db, sql_audit, NULL, 0, &err_msg);
    if( ret != SQLITE_OK ){
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }

    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    ret = sqlite3_exec(db, sql_register, NULL, 0, &err_msg);
    if( ret != SQLITE_OK ){
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }

    /* 初始化表 */
    uint32_t i = 0;
    char sql_tmp[LINE_SIZE];
    for(i = 0; i < POLICY_TYPE_COUNT; i++) {
        sprintf(sql_tmp,"INSERT INTO tbl_policy VALUES('%u','0','0','0','NULL')", i);
        sqlite3_exec(db, sql_tmp, NULL, 0, &err_msg);
    }
    return OK;
}
/* 插入审计日志 */
uint32_t
db_ins_report(uint32_t type, uint32_t what, char *data)
{
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("INSERT INTO tbl_report(type,what,data) VALUES('%u','%u','%s')",
                                type, what, data);
    /* printf("%s\n",sql); */
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
    return OK;
}
/* 上报数据库的数据 */
uint32_t
db_send_report()
{
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("SELECT * from tbl_report where "       \
                                "time = (SELECT min(time) from tbl_report)");
    char ** p_result = NULL;
    int n_row, n_col;
//    printf("%s\n",sql);
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_get_table(db, sql,&p_result,&n_row,&n_col,&err_msg);
    LOG_DB("exec %s\nret row = %d, column = %d\n", sql, n_row, n_col);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
    if(n_row <= 0) return OK;
    int i;
    for(i = 1; i < n_row + 1; i++) {
        send_audit_log(atoi(p_result[i * n_col + 1]),
                       atoi(p_result[i * n_col + 2]),
                       p_result[i * n_col + 3]);
    }
    sql = sqlite3_mprintf("DELETE from tbl_report where time = '%s'", p_result[n_col + 4]);
    sqlite3_free_table(p_result);  //使用完后务必释放为记录分配的内存，否则会内存泄漏;
    LOG_DB("exec %s\n", sql);
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
    return db_send_report();
}

/* 更新 */
uint32_t
db_update_policy(struct policy_gen_t *gen, char *policy)
{
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("UPDATE tbl_policy SET id='%u',crc='%u',flag='%u',data='%s' WHERE type='%u'",
                                gen->id, gen->crc, gen->flag, policy, gen->type);
    /* printf("%s\n",sql); */
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
    return OK;
}
/* 启停策略 */
uint32_t
db_ctrl_policy(struct policy_gen_t *gen, uint32_t flag)
{
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("UPDATE tbl_policy SET flag = '%u' WHERE type = '%u'",
                                flag, gen->type);
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
    return OK;
}
/* 查 */
uint32_t
db_que_policy(struct policy_gen_t *gen, char *policy)
{
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("SELECT * from tbl_policy WHERE type ='%u'", gen->type);
    char ** p_result;
    int n_row, n_col;
//    printf("%s\n",sql);
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_get_table(db, sql,&p_result,&n_row,&n_col,&err_msg);
    LOG_DB("exec %s\nret row = %d, column = %d\n", sql, n_row, n_col);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
#if 0
    for(int i = 0 ;i < n_row + 1; i++) {
        for(int j = 0; j < n_col; j++)
            printf("%s\t", p_result[i * n_col + j]);
        printf("\n");
    }
#endif
    if(n_row > 0) {
        gen->type = atoi(p_result[n_col + 0]);
        gen->id =atoi(p_result[n_col + 1]);
        gen->crc = atoi(p_result[n_col + 2]);
        gen->flag = atoi(p_result[n_col + 3]);
        if(policy != NULL) {
            strcpy(policy, p_result[n_col + 4]);
        }
    }
    sqlite3_free_table(p_result);  //使用完后务必释放为记录分配的内存，否则会内存泄漏
    return OK;
}
/* 插入注册信息 */
uint32_t
db_ins_register_info(struct reg_info_t *reg_info) {
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("INSERT INTO tbl_register VALUES('%u','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%u')",
                                reg_info->reg_id, reg_info->reg_ip,
                                reg_info->reg_mac, reg_info->reg_dev,
                                reg_info->reg_com, reg_info->reg_dep,
                                reg_info->reg_addr, reg_info->reg_user,
                                reg_info->reg_tel, reg_info->reg_mail,
                                reg_info->reg_note, reg_info->reg_os,
                                reg_info->srv_ip, reg_info->srv_port);
    /* printf("%s\n",sql); */
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
     return OK;
}
/* 查询注册信息 */
uint32_t
db_que_register_info(struct reg_info_t *reg_info) {
    char *err_msg = NULL;
    char *sql = sqlite3_mprintf("SELECT * from tbl_register");
    char ** p_result;
    int n_row, n_col;
//    printf("%s\n",sql);
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_get_table(db, sql,&p_result,&n_row,&n_col,&err_msg);
    LOG_DB("exec %s\nret row = %d, column = %d\n", sql, n_row, n_col);
    sqlite3_free(sql);
    if( ret != SQLITE_OK ) {
        LOG_DB("Error SQL: %s\n", err_msg);
        sqlite3_free(err_msg);
        return FAIL;
    }
#if 0
    for(int i = 0 ;i < n_row + 1; i++) {
        for(int j = 0; j < n_col; j++)
            printf("%s\n", p_result[i * n_col + j]);
        printf("\n");
    }
#endif
    uint32_t i = 0;
    if(n_row > 0 && reg_info != NULL) {
        reg_info->reg_id = atoi(p_result[n_col + i++]);
        strcpy(reg_info->reg_ip,p_result[n_col + i++]);
        strcpy(reg_info->reg_mac,p_result[n_col + i++]);
        strcpy(reg_info->reg_dev,p_result[n_col + i++]);
        strcpy(reg_info->reg_com,p_result[n_col + i++]);
        strcpy(reg_info->reg_dep,p_result[n_col + i++]);
        strcpy(reg_info->reg_addr,p_result[n_col + i++]);
        strcpy(reg_info->reg_user,p_result[n_col + i++]);
        strcpy(reg_info->reg_tel,p_result[n_col + i++]);
        strcpy(reg_info->reg_mail,p_result[n_col + i++]);
        strcpy(reg_info->reg_note,p_result[n_col + i++]);
        strcpy(reg_info->reg_os,p_result[n_col + i++]);
        strcpy(reg_info->srv_ip,p_result[n_col + i++]);
        reg_info->srv_port = atoi(p_result[n_col + i++]);
        LOG_DB("查询注册数据 %u", --i);
        sqlite3_free_table(p_result);
        return REGISTERED;
    }
    sqlite3_free_table(p_result);  //使用完后务必释放为记录分配的内存，否则会内存泄漏
    return OK;
}
/* 关闭数据库 */
uint32_t
db_close()
{
    sqlite3_busy_timeout(db, 30*1000); //最长等待30m
    int ret = sqlite3_close(db);
    if ( ret == SQLITE_BUSY ){
        LOG_DB("Error close database\n");
        return FAIL;
    }
    return OK;
}
