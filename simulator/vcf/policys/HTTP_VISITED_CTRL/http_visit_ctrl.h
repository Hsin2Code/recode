/*
 * CPolicyHttpVisitctrl.h
 *
 *  Created on: 2015-1-12
 *      Author: sharp
 */

#ifndef CPOLICYHTTPVISITCTRL_H_
#define CPOLICYHTTPVISITCTRL_H_
#include "../policysExport.h"
#include <stdio.h>
#include <string>

///上网审计函数定义
extern bool  http_visit_ctrl_init();
extern bool  http_visit_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  http_visit_ctrl_uninit();
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
///因特网访问审计
class   CPolicyHttpVisitctrl : public CPolicy {
public :
	CPolicyHttpVisitctrl() {
		enPolicytype  type = HTTP_VISIT_CTRL ;
		set_type(type);
	}
	virtual ~CPolicyHttpVisitctrl() {

	}
public:
	virtual  bool   import_xml(const char * pxml)  {
		if(pxml == NULL) {
			return false ;
		}

		CMarkup  xml ;
		if(!xml.SetDoc(pxml)) {
			return false ;
		}

		std::string  weblist ;
		std::string  keylist ;
		if(xml.FindElem("vrvscript")) {
			xml.IntoElem();
			while(xml.FindElem("item")) {
				weblist = xml.GetAttrib("WEBList");
				keylist = xml.GetAttrib("KeyWordList");
				m_Uplog = atoi(xml.GetAttrib("UpRegionService").c_str());
				m_rcLocal = atoi(xml.GetAttrib("WriteLocalFile").c_str());
				m_Audit = atoi(xml.GetAttrib("AuditMode").c_str()) ;
				m_Allowtip = atoi(xml.GetAttrib("KeyWordTipAllow").c_str());
				m_Tips =  xml.GetAttrib("KeyWordTip");
			}
			xml.OutOfElem();
		}

		if(weblist.size() !=0) {
			m_urlArray.clear();
			YCommonTool::split_new(weblist,m_urlArray,";");
		}
		if(keylist.size() !=0) {
			m_keyArray.clear();
			///由于网页编码基本都为 UTF-8,需要转码，比较的时候就不用转码了。
			YCommonTool::split_new(keylist,m_keyArray,";");
		}
		transkey_to_utf8();

		///最后调用父类的获取公用数据的函数
		return CPolicy::import_xmlobj(xml) ;
	}

	virtual  void   copy_to(CPolicy * pDest) {
		if(pDest->get_type() != HTTP_VISIT_CTRL) {
			return ;
		}
		CPolicyHttpVisitctrl * pCtrl = (CPolicyHttpVisitctrl *)pDest;
		pCtrl->m_urlArray = m_urlArray ;
		pCtrl->m_Uplog = m_Uplog;
		pCtrl->m_rcLocal = m_rcLocal;
		pCtrl->m_Audit = m_Audit ;
		pCtrl->m_keyArray = m_keyArray ;
		pCtrl->m_Allowtip = m_Allowtip;
		pCtrl->m_Tips = m_Tips;

		CPolicy::copy_to(pDest);
	}
private:
	void   transkey_to_utf8();
public:

	///网页URL列表
	std::vector<std::string>  m_urlArray ;
	std::vector<std::string>  m_keyArray ;

	property_def(Audit,int)
	///日志上传
	property_def(Uplog,int)
	///日志写本地
	property_def(rcLocal,int)
	///是否提示
	property_def(Allowtip,int)
	///提示
	property_def(Tips,std::string)
};


#endif /* CPOLICYHTTPVISITCTRL_H_ */
