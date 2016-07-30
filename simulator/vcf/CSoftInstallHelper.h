/*
 * CSoftInstallHelper.h
 *
 *  Created on: 2015-1-16
 *      Author: sharp
 */

#ifndef CSOFTINSTALLHELPER_H_
#define CSOFTINSTALLHELPER_H_
#include <vector>
#include <map>
#include <string>


///安装软件结构体
struct  tag_SoftInstall {
	std::string version ;
	std::string time ;
};

///安装软件结构体，用于上报时使用
struct  tag_SoftInstallEx {
	std::string name ;
	std::string version ;
	std::string time ;
};

enum  {
	ins_soft_new  = 1 ,
	ins_soft_del  = 2 ,
	ins_soft_modify = 3 ,
};

///求文件的哈希值
std::string ins_soft_hash(const char * name,const char * version);

/**
 * KEY为哈希值
 */
typedef std::map<std::string ,tag_SoftInstall>  CSoftinstallmap ;

class CSoftInstallHelper {
public:
	CSoftInstallHelper();
	virtual ~CSoftInstallHelper();

	///初始化
	bool     Init();
	///与原来的对比
	void     Check(CSoftinstallmap & oldmap,   ///原来的旧的信息
			std::vector<tag_SoftInstallEx> & add_vt, ///
			std::vector<tag_SoftInstallEx> & del_vt,
			std::vector<tag_SoftInstallEx> & modify_vt);
private:
	CSoftinstallmap     m_newMap ;
};

#endif /* CSOFTINSTALLHELPER_H_ */
