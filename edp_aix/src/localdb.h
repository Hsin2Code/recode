#ifndef _LOCALDB_H___
#define _LOCALDB_H___
#include "sqlite3.h"
#include "type.h"
#include "comint.h"
#include "register.h"

#define LOCALDB_PATH "/opt/edp_vrv/bin/local.db"


/* 连接数据库 */
uint32_t
db_conn();

/* 数据库初始化 */
uint32_t
db_init();

/* 更新 */
uint32_t
db_update_policy(struct policy_gen_t *gen, char *policy);

/* 启停策略 */
uint32_t
db_ctrl_policy(struct policy_gen_t *gen, uint32_t flag);

/* 查 */
uint32_t
db_que_policy(struct policy_gen_t *gen, char *policy);

/* 插入审计日志 */
uint32_t
db_ins_report(uint32_t type, uint32_t what, char *data);

/* 上报数据库中的数据 */
uint32_t
db_send_report();

/* 插入注册信息 */
uint32_t
db_ins_register_info(struct reg_info_t *reg_info);
/* 查询注册信息 */
uint32_t
db_que_register_info(struct reg_info_t *reg_info);

/* 关闭数据库 */
uint32_t
db_close();

#endif
