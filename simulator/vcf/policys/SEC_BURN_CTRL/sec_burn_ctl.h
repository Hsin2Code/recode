/**
 * sec_burn_ctl.h
 *
 *  Created on: 2015-1-15
 *      Author: liu
 *   该文件是安全刻录策略类对应的头文件；
 */

#ifndef SEC_BURN_CTL_H_
#define SEC_BURN_CTL_H_

#include <map>
#include <list>
#include "../policysExport.h"

using namespace std;

/**
 *宏定义
 */
#define RET_ERR_OOM (2)
#define RET_ERR (1)
#define RET_SUCCESS (0)

#define LEN_FILE_NAME 256
#define LEN_STR_CD_DEV_MODEL 256 
#define LEN_STR_CD_PROPERTY 256 
#define LEN_STR_CD_DEV_NAME 256 

#if defined(HW_X86) || defined(HW_ARM64)
#define LEN_STR_MD5 256 
#endif//HW_X86

/**
 *定义刻录结果枚举类型
 */
typedef enum
{
    CDBURN_INIT = -1,
    CDBURN_OK = 0,
    CDBURN_CANCELLED = 1,
    CDBURN_MAX = 2
} enum_cdburn_ret;

#if defined(HW_X86) || defined(HW_ARM64)
typedef enum
{
    CDBURN_STAT_INIT = -1,
    CDBURN_STAT_CHECKSUM_FILE,
    CDBURN_STAT_GEN_ISO_IMAGE,
    CDBURN_STAT_CHECKSUM_IMAGE,
    CDBURN_STAT_LIB_BURN,
    CDBURN_STAT_MAX = 10
}enum_cdbrun_state;

struct file_check_st
{
    char file_name[LEN_FILE_NAME + 1];
    char md5_val[LEN_STR_MD5 + 1];
};
#endif//HW_X86

/**
 *用于外部调用的函数声明。
 */
extern bool sec_burn_ctl_init(void);
extern bool sec_burn_ctl_worker(CPolicy *pPolicy, void *pParam);
extern void sec_burn_ctl_uninit(void);

/**
 *安全刻录控制类定义
 */
class CSecBurnCtl: public CPolicy{
public:
	CSecBurnCtl();
	virtual ~CSecBurnCtl();

public:
	virtual bool import_xml(const char*);
	virtual void copy_to(CPolicy * pDest);

public:
    map<string, string> xmlitem;
    list<string> whitelist, blacklist, wordlist, filelist, pathlist;
    enum_cdburn_ret burn_ret;
};
#endif /* SEC_BURN_CTL_H_ */
