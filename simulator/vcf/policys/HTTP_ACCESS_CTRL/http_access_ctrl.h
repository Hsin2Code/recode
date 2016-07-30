/*
 * http_access_ctrl.h
 *
 *  Created on: 2015-1-17
 *      Author: sharp
 */

#ifndef HTTP_ACCESS_CTRL_H_
#define HTTP_ACCESS_CTRL_H_
#include "../policysExport.h"
#include <string>


extern bool  http_access_ctrl_init();
extern bool  http_access_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  http_access_ctrl_uninit();



class  CPolicyHttpAccessctrl :    public CPolicy {
public :
	CPolicyHttpAccessctrl() {
		enPolicytype  type = HTTP_ACCESS_CTRL ;
		set_type(type);
	}
	~CPolicyHttpAccessctrl() {

	}
public:
	virtual  bool   import_xml(const char * pxml);
	virtual  void   copy_to(CPolicy * pDest) ;
private:
	///控制类型
	property_def(Acmode,int);
	property_def(webList,std::vector<std::string>);
	///HTTPS 是否启用
	property_def(httpsEnable,bool);
	property_def(httpsList,std::vector<std::string>);
};


#endif /* HTTP_ACCESS_CTRL_H_ */
