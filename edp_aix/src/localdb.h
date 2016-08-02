#ifndef _LOCALDB_H___
#define _LOCALDB_H___
#include "sqlite3.h"
#include "type.h"
#include "comint.h"
#define LOCALDB_PATH "./local.db"


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

/* 关闭数据库 */
uint32_t
db_close();

#endif
