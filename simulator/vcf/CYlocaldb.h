/*
 * CYlocaldb.h
 *
 *  Created on: 2014-12-23
 *      Author: sharp
 */

#ifndef CYLOCALDB_H_
#define CYLOCALDB_H_

#include "ldbdefine.h"

///本地数据库类，当前不支持多线程。
class CYlocaldb {
public:
	CYlocaldb();
	virtual ~CYlocaldb();
public:
	bool       db_Open(const char * pname,const char * pfilename);
	bool	   db_isOpen() ;
	void       db_Close();

	///同步到磁盘
	void       commit() ;
	bool       db_Attach();
	void       db_Dettch(int flag = (dbCOMMIT|dbDESTORYCONTEXT));

	///插入
	int		   insert(en_localTbl tbl,  void *  pData);
	///查询
	///pOutArray 类型和tbl有关系  std::vector<T>  T 为对应表的结构
	int        select(en_localTbl tbl , void *  pOutArray,const char * pszQuery = 0);
	///查询表符合条件的记录个数
	int        getTblcnt(en_localTbl tbl,const char * pszQuery = 0);
	///删除
	void       remove(en_localTbl tbl , int id);
	///
	void       remove(en_localTbl tbl,const char * pFilter);
	///更新
	bool       update(en_localTbl tbl, void *  pData);
	///更新
	bool       update(en_localTbl tbl, void *  pData ,const char * pFilter);
};

#endif /* CYLOCALDB_H_ */
