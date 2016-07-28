/*
 * CSoftInstallHelper.cpp
 *
 *  Created on: 2015-1-16
 *      Author: sharp
 */

#include "CSoftInstallHelper.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include "cli_config.h"
#include "common.h"


//using namespace YCommonTool ;
#define  SINSTALL_TMP_FILE "installsoft.tmp"
//#define  SHOW_F_LOG

std::string ins_soft_hash(const char * name,const char * version) {
    char buf[256];
    std::string s;
    std::stringstream str(s);

    memset(buf,'\0',sizeof(buf));
    strncat(buf,name,strlen(name));
    strncat(buf,version,strlen(version));

    register unsigned int h;
    register unsigned char *p;
    for(h=0, p = (unsigned char *)buf; *p ; p++)
         h = 31 * h + *p;

    str << h;
    return str.str();
}

struct install_time
{
    char date[128];
    char day[128];
    char time[128];
} ;

static  int  get_soft_info(std::string & file, CSoftinstallmap & map) {
	map.clear();
	FILE *fp = fopen(file.c_str(), "r");
	if(NULL == fp) {
	    return 0;
	}
	
#ifdef PKG_DEB
    SM_LOG() << "get package DEB info";
    int package_len =  strlen("Package") ;
	int ver_len  =  strlen("Version");
    int pri_len   = strlen("Priority") ;
    char    buf[256] = "";
	char  * index    = NULL ;
	std::string name ;
	/*
	 * 逐行读取软件信息文件，逐个分析其中的内容如果存在指定字符，保存
	 * 到结构体中，再将其加入到全局容器中
	 */
	memset(buf, '\0', sizeof(buf));
	tag_SoftInstall   install;
	name.assign(256,'\0');
	install.version.assign(256,'\0');
	install.time.assign(512,'\0');
    install_time install_t ;
	char * pName = const_cast<char *>(name.c_str());
	char * pVer  = const_cast<char *>(install.version.c_str());
	char * pTime = const_cast<char *>(install.time.c_str());

	tag_SoftInstall tmp ;
	///是否合格，可以加入。
	bool   binvalidate = true ;
	while (fgets(buf, sizeof(buf), fp)) {
	    ///每个软件的最后一行都是描述
		if(strncmp("Description",buf,11) == 0) {
			if(binvalidate) {
#ifdef SHOW_F_LOG
				printf("name = %s , version = %s , time = %s\n",name.c_str(),install.version.c_str(),install.time.c_str());
#endif
				CSoftinstallmap::iterator iter = map.find(pName);
				if(iter == map.end()) {
					tmp.version = pVer ;
					tmp.time = pTime   ;
					map[pName] = tmp   ;
				} else {
                    SM_LOG() << "already exist soft: " << pName ;
				}
			} else {
#ifdef SHOW_F_LOG
				printf("--name = %s , version = %s , time = %s\n",name.c_str(),install.version.c_str(),install.time.c_str());
#endif
			}
			binvalidate = true ;
			continue;
		}
		if((index = strstr(buf, "Package")) != NULL) {
			index += package_len;
			if((index = strstr(index, ":")) != NULL){     //防止其他位置出现关键字选项
				sscanf(index + 1, "%s", pName);
			}
			continue ;
		}
		if((index = strstr(buf, "Version")) != NULL) {
			index += ver_len;
			if((index = strstr(index, ":")) != NULL) {
				sscanf(index + 1, "%s", pVer);
			}
			continue ;
		}
        		/*
		 * 若是系统软件,用户接口,开发库的信息则不存入容器中
		 */
		if((index = strstr(buf, "Priority")) != NULL) {
			index += pri_len;
			if(((index = strstr(index, ":")) != NULL)) {
				//以下条件可根据情况增删
				 if((strstr(index+1, "required") != NULL)
								 || (strstr(index+1, "standard") != NULL)) {
					 binvalidate = false ;
				}
			}
		}
	}
#else
	///先求出长度
	int name_len =  strlen("Name") ;
	int ver_len  =  strlen("Version");
	int insDate_len = strlen("Install Date") ;
	int group_len   = strlen("Group") ;

	char    buf[256] = "";
	char  * index    = NULL ;

	std::string name ;
	/*
	 * 逐行读取软件信息文件，逐个分析其中的内容如果存在指定字符，保存
	 * 到结构体中，再将其加入到全局容器中
	 */
	memset(buf, '\0', sizeof(buf));
	tag_SoftInstall   install;
	name.assign(256,'\0');
	install.version.assign(256,'\0');
	install.time.assign(512,'\0');

	install_time install_t ;
	char * pName = const_cast<char *>(name.c_str());
	char * pVer  = const_cast<char *>(install.version.c_str());
	char * pTime = const_cast<char *>(install.time.c_str());
	tag_SoftInstall tmp ;
	///是否合格，可以加入。
	bool   binvalidate = true ;
	while (fgets(buf, sizeof(buf), fp)) {
		if(buf[0] == '*')  { ///注释
			continue ;
		}
		if(buf[12] != ':') {
			continue ;
		}
		///每个软件的最后一行都是描述
		if(strncmp("Description",buf,11) == 0) {
			if(binvalidate) {
#ifdef SHOW_F_LOG
				printf("name = %s , version = %s , time = %s\n",name.c_str(),install.version.c_str(),install.time.c_str());
#endif

				tmp.version = pVer ;
				tmp.time = pTime ;
				map[pName] = tmp;
			} else {
#ifdef SHOW_F_LOG
				printf("--name = %s , version = %s , time = %s\n",name.c_str(),install.version.c_str(),install.time.c_str());
#endif
			}
			binvalidate = true ;
			continue;
		}
		if((index = strstr(buf, "Name")) != NULL) {
			index += name_len;
			if((index = strstr(index, ":")) != NULL){     //防止其他位置出现关键字选项
				sscanf(index + 1, "%s", pName);
			}
			continue ;
		}
		if((index = strstr(buf, "Version")) != NULL) {
			index += ver_len;
			if((index = strstr(index, ":")) != NULL) {
				sscanf(index + 1, "%s", pVer);
			}
			continue ;
		}
		if((index = strstr(buf, "Install Date")) != NULL) {
			index += insDate_len;
			memset(&install_t,0,sizeof(install_t));
			if((index = strstr(index, ":")) != NULL) {
				sscanf(index + 1, "%s%s%s", install_t.date,install_t.day,
						install_t.time);
				sprintf(pTime,"%s %s %s",install_t.date,install_t.day,install_t.time);
			}
			continue ;
		}
		/*
		 * 若是系统软件,用户接口,开发库的信息则不存入容器中
		 */
		if((index = strstr(buf, "Group")) != NULL) {
			index += group_len;
			if(((index = strstr(index, ":")) != NULL)) {
				//以下条件可根据情况增删
				 if((strstr(index+1, "System Environment") != NULL)
								 || (strstr(index+1, "User Interface") != NULL)
								 || (strstr(index+1, "Development/Libraries") != NULL)) {
					 binvalidate = false ;
				}
			}
		}
	}
#endif
	fclose(fp);
	return map.size();
}

CSoftInstallHelper::CSoftInstallHelper() {


}

CSoftInstallHelper::~CSoftInstallHelper() {

}


int get_rpm_all(std::string & file) {
    int ret;
    //确保开机启动时rpm查询到的信息是中文的
    std::string rpmcmd = "export LANG=zh_CN.UTF-8;rpm -qa|xargs rpm -qi>";
    rpmcmd = rpmcmd + file;
    ret = system(rpmcmd.c_str());
    if(-1 == ret) {
        return 0;
    }
    return 1;
}

///初始化
bool  CSoftInstallHelper::Init() {

	std::string  fileName;
#ifdef PKG_DEB
    SM_LOG() << "MACRO TO DEB";
    fileName = "/var/lib/dpkg/status";
#else
    SM_LOG() << "MACRO TO RPM";
    fileName = SINSTALL_TMP_FILE;
	if(!get_rpm_all(fileName)) {
		return false ;
	}

#endif
	get_soft_info(fileName,m_newMap);
#ifdef PKG_RPM
	remove(fileName.c_str());
#endif

	return true ;
}
///
void  CSoftInstallHelper::Check(CSoftinstallmap & oldmap,   ///原来的旧的信息
			std::vector<tag_SoftInstallEx> & add_vt, ///
			std::vector<tag_SoftInstallEx> & del_vt,
			std::vector<tag_SoftInstallEx> & modify_vt)
{
	tag_SoftInstallEx tmp ;
	///先找增加的
	CSoftinstallmap::iterator iternew = m_newMap.begin();
	while(iternew != m_newMap.end()) {
		CSoftinstallmap::iterator iterold = oldmap.find(iternew->first);
		///在老的里面找不到
		if(iterold == oldmap.end()) {
			tmp.name = iternew->first ;
			tmp.version = iternew->second.version;
			tmp.time = iternew->second.time;
			add_vt.push_back(tmp);
		} else { ///在老的里面能找到， 那就是修改了
			if(iterold->second.version != iternew->second.version
					|| iterold->second.time != iternew->second.time) {
				tmp.name = iternew->first ;
				tmp.version = iternew->second.version;
				tmp.time = iternew->second.time;
				modify_vt.push_back(tmp);
			}
		}
		iternew++ ;
	}
	///再找删除的， 老的在新的里面找不间 ， 就是删除了
	CSoftinstallmap::iterator iterold = oldmap.begin();
	while(iterold != oldmap.end()) {
		CSoftinstallmap::iterator  iternew = m_newMap.find(iterold->first);
		///没找到， 删除了
		if(iternew == m_newMap.end()) {
			tmp.name = iterold->first ;
			tmp.version = iterold->second.version;
			tmp.time = iterold->second.time;
			del_vt.push_back(tmp);
		}
		iterold++ ;
	}
}
