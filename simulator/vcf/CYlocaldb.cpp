/*
 * CYlocaldb.cpp
 *
 *  Created on: 2014-12-23
 *      Author: sharp
 */

#include "CYlocaldb.h"
#include <vector>


extern  dbDatabase      m_db;

/*REGISTER_IN(T_localcfg,&m_db);
REGISTER_IN(T_localog,&m_db);
REGISTER_IN(T_localasset,&m_db);
REGISTER_IN(T_policy,&m_db);*/
REGISTER(T_localcfg);
REGISTER(T_localog);
REGISTER(T_localasset);
REGISTER(T_policy);
REGISTER(T_lasset_soft);
REGISTER(T_Tipslog);

///资产类型描述
const  char * g_asset_desc[asset_count] = {
		"硬盘","光驱","处理器","主板","内存","显卡","键盘","声音,视频和游戏控制器","鼠标和其他指针设备","网卡","软盘驱动器","系统插槽",
		"USB接口类型","网卡速率","内存使用情况","硬盘使用情况"};


#define SELECT_MACRO(x,y)   \
		   std::vector<x>  * pArray = (std::vector<x>  *)pOutArray ;\
	      pArray->clear();\
	      dbCursor<x>  cursor ;\
		  if(y) {\
			  dbQuery q ;\
			  q.add(y);\
			  if(cursor.select(q) > 0) {\
				  do {\
					  pArray->push_back(*(cursor.get()));\
				  } while(cursor.next());\
			  }\
		  } else {\
			  if(cursor.select() > 0) {\
				  do {\
				 	  pArray->push_back(*(cursor.get()));\
				 } while(cursor.next());\
			  }\
		  } return pArray->size();

template<class T>
int  get_Tblcnt(T & refT  , const char * pfilter) {
	if(pfilter) {
		dbQuery q;
		q.add(pfilter);
		return refT.select(q);
	} else {
		return  refT.select();
	}
}



template<class T>
void  _remove(T & refT  , int id) {
	dbQuery q;
	q = "id = ",id ;
	if(refT.select(q) > 0) {
		do{
			refT.remove();
		} while (refT.next());
	}
}

template<class T>
void  _remove(T & refT  , const char * pfilter) {
	if(pfilter==NULL) {
		if(refT.select() > 0) {
			do{
				refT.remove();
		    } while (refT.next());
		}
	} else {
		dbQuery q;
		q.add(pfilter);
		if(refT.select(q) > 0) {
			do{
				refT.remove();
			} while (refT.next());
		}
	}
}

bool	   CYlocaldb::db_isOpen() {
	return m_db.isOpen();
}

void       CYlocaldb::commit() {
	if(m_db.isOpen()) {
		m_db.commit();
	}
}


CYlocaldb::CYlocaldb() {
	// TODO Auto-generated constructor stub

}

CYlocaldb::~CYlocaldb() {
	db_Close();
}

bool  CYlocaldb::db_Open(const char * pname, const char * pfilename) {
	if(!m_db.open(pname,pfilename)) {
		return false ;
	}

	dbQuery q ;
	q = "name =",LDB_VERSION ;
	dbCursor<T_localcfg> cur ;
	if(cur.select(q) == 0) {

		///数据库版本
		T_localcfg cfg ;
		cfg.name = LDB_VERSION ;
		cfg.vals = LDB_VERSION_VAL ;
		insert(tbl_config,&cfg);

		///是否注册
		cfg.name = LDB_REGISTER;
		//cfg.vals = LDB_FALSE_VAL ;
		cfg.vals = LDB_TRUE_VAL;
		insert(tbl_config,&cfg);

		///注册IP
		cfg.name = LDB_REGIP;
		cfg.vals = "";
		insert(tbl_config,&cfg);

		///注册MAC
		cfg.name = LDB_REGMAC;
		cfg.vals = "";
		insert(tbl_config,&cfg);

		///服务器地址
		cfg.name = LDB_SRVIP ;
		cfg.vals = "";
		insert(tbl_config,&cfg);

		///是否一直断网
		cfg.name = LDB_OFFL_ALAWAYS ;
		cfg.vals = "0";
		insert(tbl_config,&cfg);

		///注册的网卡名
		cfg.name = LDB_REGNIC ;
		cfg.vals = "";
		insert(tbl_config,&cfg);

		///注册字符串
		cfg.name = LDB_REGGUISTR ;
		cfg.vals = "";
		insert(tbl_config,&cfg);

		///服务器类型
		cfg.name = LDB_SRVTYPE ;
		cfg.vals = "1";
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_USER_NAME;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_COMP_NAME;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_DEP_NAME;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_MACH_LOC;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_ASSERT_NO;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_EMAIL;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_PHONE;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

		cfg.name = LDB_VAS_CFG_DESC;
		cfg.vals = ""; 
		insert(tbl_config,&cfg);

        /*default to 0 unreg*/
		cfg.name = LDB_VAS_CFG_IS_REG;
		cfg.vals = "0"; 
		insert(tbl_config,&cfg);

        cfg.name = LDB_BIND_IP;
		cfg.vals = "";
		insert(tbl_config,&cfg);

        cfg.name = LDB_BIND_MAC;
		cfg.vals = "";
		insert(tbl_config,&cfg);

        cfg.name = LDB_BIND_GW;
		cfg.vals = "";
		insert(tbl_config,&cfg);

        cfg.name = LDB_BIND_MASK;
		cfg.vals = "";
		insert(tbl_config,&cfg);

        cfg.name = LDB_BIND_PCRC;
		cfg.vals = "";
		insert(tbl_config,&cfg);

	} else {
		T_localcfg * pCfg = cur.get();;
		printf("有版本，进行对比 %s\n",pCfg->vals);
		if(strcmp(pCfg->vals,LDB_VERSION_VAL) != 0){
			///进行版本判断，返回不同的值
		}
	}
	m_db.commit();
	return true ;
}

void  CYlocaldb::db_Close() {
	if(m_db.isOpen()) {
		m_db.close();
	}
}

bool  CYlocaldb::db_Attach() {
	if(!m_db.isOpen()) {
		return false ;
	}
	m_db.attach();
	return  true;
}

void  CYlocaldb::db_Dettch(int flag) {
	if(!m_db.isOpen()) {
		return ;
	}
	m_db.detach(flag);
}

///更新
bool  CYlocaldb::update(en_localTbl tbl,void *  pData ,const char * pFilter) {
	 if(!m_db.isOpen() || pFilter == NULL ) {
		 return -1 ;
	 }

	 switch(tbl) {
	 case tbl_asset_soft: {
			 dbCursor<T_lasset_soft> cursor(dbCursorForUpdate);
			 dbQuery q;
			 q.add(pFilter);
			 T_lasset_soft * pAsset = (T_lasset_soft * )pData ;
			 if(cursor.select(q)) {
				cursor->pName = pAsset->pName;
				cursor->pVer = pAsset->pVer ;
				cursor->pTime = pAsset->pTime ;
			 } else {
				 return false ;
			 }
			 cursor.update();
			 return true ;
		 }
	 case tbl_log:
	 case tbl_asset: {
			 dbCursor<T_localasset> cursor(dbCursorForUpdate);
			 dbQuery q;
			 q.add(pFilter);
			 T_localasset * pAsset = (T_localasset * )pData ;
			 if(cursor.select(q)) {
				cursor->type = pAsset->type;
				cursor->pContent = pAsset->pContent ;
			 } else {
				 return false ;
			 }
		     cursor.update();
		     return true ;
		 }
	 case tbl_config:
	 case tbl_policy:
	 case tbl_tipslog:
		 break ;
	 }
	 return false ;
}

///更新
bool  CYlocaldb::update(en_localTbl tbl, void *  pData) {
	 if(!m_db.isOpen()) {
		 return -1 ;
	 }

	 switch(tbl) {
	 case tbl_tipslog: { ///提示日志不存在更新

			 break ;
	 }
	 case tbl_asset_soft: {
			 dbCursor<T_lasset_soft> cursor(dbCursorForUpdate);
			 T_lasset_soft * pAsset = (T_lasset_soft * )pData ;
			 dbQuery q;
			 q = "id = ",pAsset->id ;
			 if(cursor.select(q)) {
				cursor->pName = pAsset->pName;
				cursor->pVer = pAsset->pVer ;
				cursor->pTime = pAsset->pTime ;
				cursor.update();
			 } else {
				 return false ;
			 }
			 break ;
	 }
	 case tbl_asset: {
			 dbCursor<T_localasset> cursor(dbCursorForUpdate);
			 T_localasset * pAsset = (T_localasset * )pData ;
			 dbQuery q;
			 q = "id = ",pAsset->id ;
			 if(cursor.select(q)) {
				cursor->type = pAsset->type;
				cursor->pContent = pAsset->pContent ;
				cursor.update();
			 } else {
				 return false ;
			 }
			 break ;
		 }
	 case tbl_config: {
			 dbCursor<T_localcfg> cursor(dbCursorForUpdate);
			 T_localcfg * pcfg = (T_localcfg * )pData ;
			 dbQuery q;
			 q = "name = ",pcfg->name;
			 if(cursor.select(q)) {
				 cursor->vals = pcfg->vals;
				 cursor.update();
			 } else {
				 return false ;
			 }
			 break ;
		 }
	 case tbl_policy: {
			 dbCursor<T_policy> cursor(dbCursorForUpdate);
			 T_policy * pP = (T_policy * )pData ;
			 dbQuery q;
		     q = "id = ",pP->id ;
			 if(cursor.select(q)) {
				cursor->pid =  pP->pid;
				cursor->type = pP->type ;
				cursor->crc =  pP->crc ;
				cursor->pContent = pP->pContent ;
				cursor.update();
			 } else {
				 return false ;
			 }
			 break ;
		 }
	 default:
		 return false ;
	 }
	 m_db.precommit();
	 return true ;
}
///
int   CYlocaldb::getTblcnt(en_localTbl tbl,const char * pszQuery) {
	if(!m_db.isOpen()) {
	   return -1 ;
	}
	switch(tbl) {
	case tbl_tipslog: {
		dbCursor<T_Tipslog> cursor;
		return get_Tblcnt(cursor,pszQuery);
	}
	case tbl_asset_soft: {
		dbCursor<T_lasset_soft> cursor;
		return get_Tblcnt(cursor,pszQuery);
	}
	case tbl_log:
	{
		dbCursor<T_localog> cursor;
		return get_Tblcnt(cursor,pszQuery);
	}
	case tbl_asset:
	{
		dbCursor<T_localasset> cursor;
		return get_Tblcnt(cursor,pszQuery);
	}
	case tbl_config: {
		dbCursor<T_localcfg> cursor;
		return get_Tblcnt(cursor,pszQuery);
	}
	case tbl_policy: {
		dbCursor<T_policy> cursor;
		printf("======================d=========\n");
		return get_Tblcnt(cursor,pszQuery);
	}
	}
	return 0 ;
}

///查询
int   CYlocaldb::select(en_localTbl tbl , void *  pOutArray,const char * pszQuery) {
    if(!m_db.isOpen()) {
	    return -1 ;
    }

   switch(tbl) {
    case tbl_tipslog: {
			  SELECT_MACRO(T_Tipslog,pszQuery)
         }
    case tbl_asset_soft: {
    	      SELECT_MACRO(T_lasset_soft,pszQuery)
         }
    case tbl_log:     {
		      SELECT_MACRO(T_localog,pszQuery)
	     }
    case tbl_asset:   {
			  SELECT_MACRO(T_localasset,pszQuery)
	     }
    case tbl_config : {
			  SELECT_MACRO(T_localcfg,pszQuery)
	     }
    case tbl_policy: {
    	      SELECT_MACRO(T_policy,pszQuery)
		}
    }
  return  0 ;
}

///
void  CYlocaldb::remove(en_localTbl tbl,const char * pFilter) {
	if(!m_db.isOpen()) {
		return  ;
	}
	switch(tbl) {
	case tbl_tipslog: {
			dbCursor<T_Tipslog> cursor(dbCursorForUpdate);
			_remove(cursor,pFilter);
			break ;
	}
	case tbl_asset_soft: {
			dbCursor<T_lasset_soft> cursor(dbCursorForUpdate);
			_remove(cursor,pFilter);
			break ;
		}
	case tbl_log: {
			dbCursor<T_localog> cursor(dbCursorForUpdate);
		    _remove(cursor,pFilter);
			break ;
		}
	case tbl_asset: {
			dbCursor<T_localasset> cursor(dbCursorForUpdate);
			_remove(cursor,pFilter);
			break ;
		}
	case tbl_config : {
			dbCursor<T_localcfg> cursor(dbCursorForUpdate);
			_remove(cursor,pFilter);
			break;
		}
	case tbl_policy : {
			dbCursor<T_policy> cursor(dbCursorForUpdate);
			_remove(cursor,pFilter);
			break;
		}
	}
	m_db.precommit();
	return  ;
}

///删除
void  CYlocaldb::remove(en_localTbl tbl , int id) {
	if(!m_db.isOpen()) {
		return  ;
	}
	switch(tbl) {
	case tbl_tipslog: {
			dbCursor<T_Tipslog> cursor(dbCursorForUpdate);
			_remove(cursor,id);
	}
	case tbl_asset_soft: {
			dbCursor<T_lasset_soft> cursor(dbCursorForUpdate);
			_remove(cursor,id);
	}
	case tbl_log: {
			dbCursor<T_localog> cursor(dbCursorForUpdate);
		    _remove(cursor,id);
			break ;
		}
	case tbl_asset: {
			dbCursor<T_localasset> cursor(dbCursorForUpdate);
			_remove(cursor,id);
			break ;
		}
	case tbl_config : {
			dbCursor<T_localcfg> cursor(dbCursorForUpdate);
			_remove(cursor,id);
			break;
		}
	case tbl_policy : {
			dbCursor<T_policy> cursor(dbCursorForUpdate);
			_remove(cursor,id);
			break;
		}
	}
	m_db.precommit();
	return  ;
}


///插入
int  CYlocaldb::insert(en_localTbl tbl,  void *  pData) {
	if(!m_db.isOpen() || pData == NULL) {
		return  -1;
	}
	///改基类此功能没用起来，先屏蔽
	/*T_base * pBasae = (T_base *)pData ;
	if(pBasae->get_Type() != tbl) {
		return -1 ;
	}*/

	int id = 0 ;
	switch(tbl) {
	case tbl_tipslog: {
			T_Tipslog * pLog = (T_Tipslog *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break ;
	}
	case tbl_asset_soft: {
			T_lasset_soft * pLog = (T_lasset_soft *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break;
	}
	case tbl_log : {
			T_localog * pLog = (T_localog *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break ;
		}
	case tbl_asset : {
			T_localasset * pLog = (T_localasset *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break ;
		}
	case tbl_config: {
			T_localcfg * pLog = (T_localcfg *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break ;
		}
	case tbl_policy: {
			T_policy * pLog = (T_policy *)pData;
			m_db.insert(*pLog);
			id = pLog->id ;
			break ;
		}
	}
	m_db.precommit();
	return id ;
}

