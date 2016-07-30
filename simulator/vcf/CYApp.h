/**
 * CYApp.h
 *
 *  Created on: 2014-11-26\n
 *      Author: sharp\n
 */

#ifndef CYAPP_H_
#define CYAPP_H_

#include "msgdisp.h"
/*
 * 系统保留消息号
 * 子类主消息通道自定义的消息号必须大于 YAPP_CMD_MAX 小于 0xffff
 */
enum  {
	YAPP_CMD_QUIT,  //主线程退出
	YAPP_CMD_TIMER, //定时器消息

	YAPP_CMD_MAX = 1000,
};

///定时器最大数量
const int  max_timer_cnt = 256 ;

/**
 *   YAPP_CMD_TIMER 使用
 */
///提供应用程序的基本功能模块，定时器，主消息通道，各通道之间同步异步消息通讯。
class CYApp: public IMsgdispatcher {
	///定时器结构
	struct tag_timerinfo {
		///定时器ID
		int        id       ;
		///间隔单位毫秒
		int        interval ;//参数列表
		///参数
		void *     pparam   ;
		///记录时间（毫秒）
		long int   lastexec  ;
		///是否循环
		bool       bloop ;
		///是否启用
		volatile  char       buse  ;
		///定时器ID计数
		static    int  gtimerId ;
		tag_timerinfo() {
			id = 0 ;
			interval = 0 ;
			pparam = (void *)0;
			lastexec = 0 ;
			bloop = true ;
			buse = 0;
		}
	};
	typedef std::map<int , tag_timerinfo>   CtimerMap ;

public:
	CYApp(int argc, char ** argv, int ntrd = 2);
	CYApp(int ntrd = 1);
	virtual ~CYApp();

	/**
	 * 友元函数，帮助CYAPP类进入统一的消息处理成员函数\n
	 * @Author: Sharp.y\n
	 * @Description:　消息的回调函数\n
	 * @Params: (1) cmd : 消息号，自定义　(2) pbuffer: 参数结构体指针　(3) len 结构体长度 (4) 附加参数 ,(5) 发送者的通道ID\n
	 * @Returns : 布尔值，　当前没有特殊意义。\n
	 */
	friend bool    cyapp_msgwork_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id);
	friend void  * cyapp_timer(void * pparam);
	friend bool    cyapp_timermsg_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id);
public :
	/**
	 * 初始化App实例
	 */
	virtual bool    InitInstances();
	/**
	 * 退出实例
	 */
	virtual  int    ExitInstances(int extid);
	/**
	 *  应用程序进入执行
	 */
	int             exec();
	/**
	 * @退出APP
	 */
	void            quit();
	/**
	 * 设置定时器函数\n
	 * @interval   定时器间隔，单位豪秒, 最小间隔10毫秒，小于10豪秒的按10毫秒执行\n
	 * @pParam     定时器带的参数\n
	 * @bloop      是否循环，为fasle的时候只执行一次，为true的时候循环执行\n
	 * @returns    返回值为定时器ID
	 */
	int             set_Timer(unsigned int interval , void * pParam , bool bloop = true);
	/**
	 * 杀掉一个定时器函数\n
	 * @id      set_Timer返回ID
	 * @returns 返回  set_Timer传入的参数pParam,如果时动态申请的内存， 可以释放.
	 */
	void       *    kill_timer(int id);
	/**
	 * 获取TIMER的参数
	 * @id      set_Timer返回的ID
	 * @returns 返回set_Timer传入的pParam。
	 */
	const void  *   getTimerParam(int id);
	/**
	 * 获取TIMER参数
	 * @returns 返回定时器是否循环。
	 */
	bool            timer_Isloop(int id);
	/**
	 * 同步发送消息
	 * 消息执行完毕后才返回。
	 * 各参数及返回值的意义参考 父类sendtoDispatcher
	 */
	bool            sendmsg(int id ,
			unsigned short cmd ,
			PVOID pData,
			int len);

	/**
	 * 异步发送消息
	 * 消息投递出去立即返回。
	 * 参数及返回值参考 父类sendtoDispatcher
	 */
	bool      postmsg(int id,
			unsigned short cmd ,
			PVOID pData ,
			int len ,
			int sendid = 0);
public:
	/**
	 * @获取应用程序路径
	 */
	const std::string  &  getMoudlepath() {
		return m_strModulePath ;
	}
	/**
	 * @获取应用程序名称
	 */
	const std::string  &  getMoudlename() {
		return m_strModuleName ;
	}

	///获取主消息执行通道ID
	int      getMainChannelID() {
		return m_nMainChannel ;
	}
protected:
	/**
	 * @参考上面友元函数定义
	 */
	virtual  bool         msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id);
	/**
	 * 定时器消息执行函数，扔到子类去执行
	 * id 为set_Timer 返回的ID
	 * */
	virtual  bool         timer_proc(int id){ return true ;}
	/**
	 * @参考上面友元函数定义
	 */
	bool                  timer_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id);

private:
	/**
	 * 获取APP自身运行绝对路径
	 * @param name返回程序的名称
	 * @returns 返回程序运行目录路径
	 */
	std::string           get_AppabspathAndName(std::string & name);
	/**
	 * 构造函数一些初始化的赋值
	 */
	void                  yapp_construction();
	/**
	* @定时器判断函数
	* 判断是否改调用定时器消息，并且通知主消息通道执行。
	* */
	void    *             cyapp_timer_helper();
protected:
	///参数列表， 以后在用
	std::list<std::string>  m_argList;
	///主消息处理通道ID号
	int                     m_nMainChannel  ;
	///定时器处理通道
	int                     m_nTimerChannel ;
private:

	///信号集合
	sigset_t                m_runset ;
	///应用程序目录绝对路径
	std::string             m_strModulePath;
	///应用程序名称
	std::string             m_strModuleName;
	///定时器线程ID
	pthread_t               m_timtrd;
	///定时器线程运行标志
	volatile      bool      m_btimerRuning;
	///定时器数据MAP
	CtimerMap               m_timerMap ;
	///定时器锁
	PVOID                   m_pTimerLock ;
	///定时器数组
	tag_timerinfo           m_timerArray[max_timer_cnt] ;
	///使用的数组
	short                   m_userTimer[max_timer_cnt];
	///使用的定时器个数
	int                     m_nUsercnt ;
};

#endif /* CYAPP_H_ */
