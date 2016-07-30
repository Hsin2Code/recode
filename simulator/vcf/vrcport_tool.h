/*
 * vrcport_tool.h
 *
 *  Created on: 2015-1-4
 *      Author: sharp
 */

#ifndef VRCPORT_TOOL_H_
#define VRCPORT_TOOL_H_
#include <string>
#include <vector>
#include <string.h>
#include <map>
using namespace  std ;

typedef struct network_info{
	char ip[16];
	char mac[16];
	char gateway[16];
	char sub_mask[16];
	char eth_name[16];
	//if need,added later
} net_info;

///策略概述
struct tag_vrv_policyGen {
	int id   ;
	string func ;
	unsigned int crc ;
	int    type ;
	int flg  ;
	tag_vrv_policyGen() {
		id = 0 ;
		func = "";
		crc = 0 ;
		flg = 0 ;
	}
};



///策略XML结束标志
#define    POLICY_END_TAG  "</vrvscript>"

///获取策略内容
bool       get_PolicyContent(int i,std::string  & src , string & xml , int & startpos);


///从字符串中获取需要下载的策略信息
int        get_policylist_fromGeneral(std::string & general ,
		std::vector<tag_vrv_policyGen> & _array);


///获取设备ID
int        get_device_indetify(char *buf,int bufsize,string & strmac);

///获取网络上报附加信息
int        get_pkt_app_info(string  & info,
							string  & nic,
							string  & regip,
							string  & retmac);


///对获取的策略概况进行过滤
void       filter_PolicyGen(std::map<unsigned int , int> & crcmap ///老的策略CRCMAP
		,std::map<unsigned int , int> & crcmapEx ///老的策略CRCMAP
		,std::vector<tag_vrv_policyGen>  &  addArray ///传入获取的概况，输出需要下载的策略
		,std::vector<unsigned int> & delArray ///删除策略的CRC列表
		,std::vector<unsigned int> & unApplyArray ///取消应用的策略列表
		);

///获取日志头
int        get_logHeader(char * buffer
		    ,std::string  &  regip,  ///注册IP
		    std::string  &  regmac, ///注册MAC
		    std::string  &  id, ///ID
		    std::string  &  sysuser) ;


///获取标识值
bool       getVal_fromTarget(char * pval,const char * pTar , const char * pSrc,int maxlen);

#endif /* VRCPORT_TOOL_H_ */
