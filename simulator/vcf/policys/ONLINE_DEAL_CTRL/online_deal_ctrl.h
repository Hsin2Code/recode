/*
 * online_deal_ctrl.h
 *
 *  Created on: 2015-2-4
 *      Author: sharp
 */

#ifndef ONLINE_DEAL_CTRL_H_
#define ONLINE_DEAL_CTRL_H_
#include "../policysExport.h"

extern bool  online_deal_ctrl_init();
extern bool  online_deal_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  online_deal_ctrl_uninit();

#define  ONLINE_DEAL_CTRL_INTERVAL    (10*1000)

class   CPolicyOnlinedealctrl : public CPolicy {
public:
	struct tag_Item {
		/**
		 * 处理方式
		 */
		int mode ;
		int shutDownTime ;
		std::string Prompt;
		std::string Prompt2;
		std::string Prompt4;
		std::string Prompt8;
		std::string Prompt16;

		void  convert();
	};
public:
	CPolicyOnlinedealctrl() {
		enPolicytype  type = ONLINE_DEAL_CTRL ;
		set_type(type);
	}
	virtual ~CPolicyOnlinedealctrl() {

	}
public:
	virtual  bool  import_xml(const char * pxml) ;
	virtual  void  copy_to(CPolicy * pDest);
private:
	void     xml_item1(CMarkup & xml);
	void     xml_item2(CMarkup & xml);
	void     xml_item3(CMarkup & xml);
private:
	///是否允许探测 非零为允许策略运行
	property_def(allowDetect,int)
	///探测间隔
	property_def(DetectInterVal,int)
	///采用探测外网的方法 非零为使用外网探测
	property_def(UseDetectWan,int)
	///外网探测参数
	property_def(Wanip1,std::string)
	property_def(Wanipchar1,std::string)
	property_def(Wanip2,std::string)
	property_def(Wanipchar2,std::string)
	///IP区间
	property_def(IPStart,std::string)
	property_def(IPEnd,std::string)
	property_def(detectNum,int)
	///禁止使用IE代理上网 非零的话执行
	property_def(disEnableProxy,int)
	property_def(disEnableProxyConn,int)
	///被永久阻断后，重启后提示
	property_def(RebootPrompt,std::string)
	///是否允许特殊的号码拨号
	property_def(EnableSpecCode,int)
	property_def(EnableSpecNumber,std::string)

	///检测代理外联
	property_def(Detectproxy,int)
	///检测UDP
	property_def(DetectUdp,int)

	///是否保存外联数据包
	property_def(IsSavepacket,int)

	/**
	 * 同时在内外网 XML  DisobeyMode0="0"
	 * tag_Item::mode 取值含义
	 * 0 ：不处理
	 * 1 ：断开网络并关机(重启恢复) shutDownTime有效
	 * 2 ：断开网络(重启恢复)
	 * 4 ：仅提示 Prompt 有效
	 * 8 ：断开网络并关机(需解锁) shutDownTime有效
	 */
	property_def(lanAndwan,tag_Item)
	/**
	 * 同时在内外网 XML  DisobeyMode1="1"
	 * tag_Item::mode 取值含义
	 * 0 ：不处理
	 * 1 ：断开网络并关机(重启恢复) shutDownTime有效
	 * 2 ：断开网络(重启恢复)
	 * 4 ：仅提示 Prompt 有效
	 * 8 ：接回内网后进行安全检查
	 * 16：断开网络并关机(需解锁) shutDownTime有效
	 */
	property_def(onlyWan,tag_Item)
};

#endif /* ONLINE_DEAL_CTRL_H_ */
