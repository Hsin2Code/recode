/**
 * CVCFApp.h
 *
 *  Created on: 2014-12-1\n
 *      Author: sharp\n
 *  说明:  该类为国产终端应用程序类\n
 *  VCF =  vrv  client frame\n
 */

#ifndef CVCFAPP_H_
#define CVCFAPP_H_

#include "CYApp.h"
#include "common/CYlog.h"
#include "../include/MCInterface.h"
#include "CIMCSrv.h"
#include "CNetEngine.h"
#include "CYlocaldb.h"
#include "VCFCmdDefine.h"
#include "CPolicyManager.h"
#include "CAuditlogFilter.h"
#include "CEventNotify.h"
#include "CMyIptables.h"

#define  SELF_DEBUG
#undef SELF_DEBUG

#define  IPTABLE_RULE_FILE "/usr/sbin/.iptables"

using namespace YCommonTool ;

///上传定时器间隔 1分钟
const int   c_iUploadlog_interval =  60*1000 ;
///主动链接服务器更新策略间隔 30秒
const int   c_iUploadPolicy_interval = 30 * 1000 ;
///心跳间隔
const int   c_iHeartbeat_interval = 30 * 1000;
///检查是否终端登录定时器
const int   c_iDeskToplogin_interval = 2 * 1000;
///自身监控定时器30秒执行一次
const int   c_iCheckSelf_interval = 30*1000;
///守护进程探测间隔 5秒探测一次
const int   c_iCheckWatchV = 5*1000;


/**
 *  VCF主要进程类，提供应用程序与各种模块之间的消息通道和资源存储。
 */
class CVCFApp :  public CYApp ,
    public INetEngineSinkinterface ,
    public IMCSrvsinkinterface,
    public IVCFAppSendinterface,
    public IVCFPolicyCtrlinterface,
    public ILocalogInterface,
    public ILocalCfginterface,
    public IEventNotifyInterface {
public:
    CVCFApp();
    virtual ~CVCFApp();
public :///[virtual : ILocalCfginterface]
	/**
	 * 获取本地配置
         */
    virtual  bool  get_lconfig(en_lcfg_key key , std::string & val);
    /**
     * 设置本地配置
     */
    virtual  bool  set_lconfig(en_lcfg_key key , const std::string & val);
    virtual  bool  get_offlstat() {
        return  m_bcurOffline;
    }
    virtual  time_t get_UpTime() {
        return m_startTime ;
    }
    virtual  bool  is_WinSrv() {
        return m_bwinSrv ;
    }
public:
    /// 友元函数
    /**
     * 进程间通讯友元函数，主要是作为调用VCFAPP类本身的处理函数而用
     */
    friend   bool     IMC_msg_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id) ;
    ///日志消息处理
    friend   bool     Upload_msg_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id);
    ///策略执行消息
    friend   bool     policy_msg_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id);
public:///[virtual : IVCFAppSendinterface]
    ///发送消息到日志执行通道
    bool              sendto_Uplog(unsigned short cmd,void * pdata, int len,bool bsync = false);
    ///发送消息到进程间消息通道
    bool              sendto_Imc(unsigned short cmd,void * pdata, int len,bool bsync = false);
    ///发送消息到主线程通道
    bool              sendto_Main(unsigned short cmd,void * pdata, int len,bool bsync = false);
    ///发送消息到策略处理通道
    bool              sendto_pl4Exec(unsigned short cmd,void * pdata, int len,bool bsync = false);
public:/// [virtual : INetEngineSinkinterface]
    /**
     * 获取参数
     */
    virtual std::string  get_Param(std::string & key);
    /**
     *  @brief 相应服务器发来的的消息，服务器主动连接上来的。
     */
    virtual bool         recvnetmsg(enNetRmsg msg , void * pData , int len);

    ///本地向外链接成功事件,error = 0 链接成功
    virtual bool         onConnect(int error);

    ///关闭事件 close_by_remote 表示是否远端先关闭
    virtual bool         onClose(SOCKET skt, bool close_by_remote) ;

    ///接收事件
    ///返回值为false关闭远程链接
    virtual bool         onAccept(SOCKET skt,struct sockaddr_in * pAddr);

public:///[virtual : ILocalogInterface]
    virtual void         loglog(const char *  plog)  {
        m_runlog.log_log("%s",plog);
    }

    /// trace log
    virtual void         log_trace(const char *  plog) {
        m_log[1].log_log("%s\n",plog) ;}
    /// debug log
    virtual void         log_debug(const char *  plog) {
        m_log[0].log_log("%s\n",plog) ;}
    /// notice log
    virtual void         log_notice(const char *  plog) {
        m_log[2].log_log("%s\n",plog) ;}
    /// warn
    virtual void         log_warning(const char *  plog) {
        m_log[3].log_log("%s\n",plog) ;}
    /// error
    virtual void         log_error(const char *  plog) {
        m_log[4].log_log("%s\n",plog) ;}
public:///[virtual : IEventNotifyInterface]
    ///注册消息
    virtual bool  registerEvent(enNotifyerEvent event , pNotify_func pfunc) ;
    ///注销消息
    virtual void  UnregisterEvent(enNotifyerEvent event , pNotify_func pfunc);

public:///[virtual : CYApp]
    /**
     *  VCF初始化函数，
     *  完成 客户端启动的一些初始化操作。
     */
    virtual  bool         InitInstances();
    /**
     * VCF退出清理函数，一些资源的回收操作可以在这里执行
     */
    virtual  int          ExitInstances(int extid);

    /**
     * 定时器处理函数， 可以在这里驱动一些周期性的操作
     * 所有定义的定时器到了固定时间，都会在此处相应
     * 此函数和主线程通道函数在一个线程。
     */
    virtual  bool         timer_proc(int id);
    /**
     *  主线程消息处理函数
     */
    virtual  bool         msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id);
    ///消息执行通道的线程启动会调用
    virtual  bool         worker_start(tag_Dispatcher * pDisp , pthread_t pid) {
    	///属于日志处理通道的线程
    	if(pDisp->id == m_nlogChannelID) {
            if(m_localDB.db_isOpen()) {
                m_localDB.db_Attach();
            }
    	}
        return  CYApp::worker_start(pDisp , pid);
    }
    ///消息执行通道的线程结束会调用
    virtual  void  *  worker_finish(tag_Dispatcher * pDisp , pthread_t pid){
    	if(pDisp->id == m_nlogChannelID) {
            printf("本地数据库DETTCH\n");
            if(m_localDB.db_isOpen()) {
                m_localDB.db_Dettch(dbCOMMIT);
            }
        }
        return  CYApp::worker_finish(pDisp , pid);
    }
public:///[virtual : IMCSrvsinkinterface]
    /**
     *  IMCSrvsinkinterface  接口函数
     *  由客户端进程发来的消息都会在这函数里面获取到
     */
    virtual	 void        Sinkmsg_proc(unsigned short cmd,void * pbuffer,int len,int pid);
    /**
     *  登录消息响应
     *  id 为传入到客户端的ID
     */
    virtual   bool       onLogon(int id,bool btray = false ,const char * pUser = NULL);
    ///客户端登出
    virtual   void       onLogout(int id) ;
    /**
     * 获取ZMQ实例
     */
    virtual	 void    *    get_Ctx() {
        return  get_zmqCtx();
    }

    ///关闭网络
    void  				closeNet();
    ///恢复网络
    void  				openNet();
    ///检测自身
    void                checkSelf();
    ///增加一条特殊的规则
    void                addSpecRule();
    ///删除特殊规则
    void                delSpecRule();

    ///获取是否永久断网
    bool                get_AlawaysOffline(){
        return  m_bofflineAlaways ;
    }
    ///获取服务器类型
    void                get_Srvtype();
public:///[virtual : IVCFPolicyCtrlinterface]
    /**
     * 启动执行策略。\n
     * @pType     策略的类型\n
     * @interval  策略执行间隔\n
     * @once      是否执行一次， true执行一次， false循环执行\n
     * 返回值 :    true为启动成功，false为启动失败。
     */
    virtual    bool      start_pl4(int pType, int interval,bool once);
    ///获取策略状态
    virtual    int       get_pl4Status(int pType);
    ///关闭策略执行
    virtual    void      stop_pl4(int pType);

protected:
    /**
     *   对本地运行环境的检测
     *   用户权限 -》 工作路径 -》本地环境检查
     */
    bool        checkandset_Env();
    /**
     *   获取本地的系统配置
     */
    bool        get_Localconfig();
    /**
     *   启动各种消息执行通道
     */
    bool        startAllCmdChannel();
    /**
     *  关闭各种消息执行通道
     */
    void        stopAllcmdChannel();
    /**
     *	启动本地策略
     */
    bool        startLocalPolicy();

    /**
     *   从timerID得到策略类型
     *   id 为定时器ID
     */
    int         getTimerType(int id);

    /**
     *	本地数据库操作子函数
     */
    bool        ldb_Operator(void * pData , int len);
    bool        ldb_Op_assert(en_DBOp op,void * pData , int len);
    bool        ldb_Op_config(en_DBOp op,void * pData , int len);
    bool        ldb_Op_policy(en_DBOp op,void * pData , int len);
    bool        ldb_Op_tiplog(en_DBOp op,void * pData , int len);
    bool        ldb_op_softAsset(en_DBOp op,void * pData , int len);
    bool        ldb_get_Asset(void * pData , int len);

    /**
     *  进程间通道子函数
     */
    void        on_Regui(unsigned short cmd , void * buffer, int len);
    void        on_Tipui(unsigned short cmd , void * buffer, int len);
    bool        get_SpacialVal(std::string & reginfo);

    /**
     *  策略通道子函数
     */
    bool        on_Policy_Exec(void * buffer ,int len);
    bool        on_policy_Init(void * buffer ,int len);
    bool        on_Policy_Uninit(void * buffer ,int len);
    bool        on_Update_pGeneral();
    bool        on_Update_pGeneral(std::string & pktinfo,std::string & str_pGeneral);
    bool        On_Update_Policy(void * pGenArray,std::string  &  content);
    bool        on_Get_Asset();
    bool        on_Update_SAsset(void * buffer ,int len);
    bool        on_Update_HAsset(void * buffer ,int len);
    bool        on_Heart_Beat();
    bool        detect_vas_server(const std::string &server_ip);
    ///寻找注册网卡，系统启动的时候执行一次
    bool        findRegNic();

    ///
    void        showCloseNetTips();

    ///探测守护服务是否存在
    //void        checkWatchV();

    /**
     * 控制网络内核控制模块
     */
#if 0
    bool        ctrl_EdpNetKo(int cmd , void * buffer = NULL, int len = 0);
#endif

protected:
    std::string        get_server_time();
protected:
    ///进程间消息通道执行函数
    virtual	bool        IMC_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);
    ///审计日志消息
    virtual bool        Upload_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);
    ///策略执行消息通道
    virtual bool        Policy_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);
protected :
    /**
     * channle
     */
    ///和其他进程通讯的消息通道，可以进行阻塞调用
    int         m_nIMCChannelID;
    ///进行网络日志处理的通道
    int         m_nlogChannelID;
    ///策略执行通道
    int         m_nPolicyExeChannle;

    /**
     * timer
     */
    ///日志上传定时器
    int         m_nUploadTimer ;
    ///策略更新定时器
    int         m_nUpdatePolicyTimer ;
    ///策略执行定时器 key是策略的类型，value是定时器的ID
    int         m_policyTimer[en_policytype_count] ;
    ///策略定时器是否循环
    bool        m_bTimerLoop[en_policytype_count] ;
    ///断网定时器
    int         m_bTimerForCloseNet ;
    ///心跳定时器
    int         m_nHeartBeatTimer ;
    ///自身监测定时器
    int         m_nCheckSelf ;
    ///守护进程定时器
    int         m_nCheckWatchv ;
    ///系统启动时间
    time_t    m_startTime;

    /**
     * 进程间定义
     */
    ///注册GUI进程标识
    int         m_nRegGui ;
    ///提示进程标识
    int         m_nTipsGui;
    int         m_nTipsID ;
    ///历史提示进程标识
    int         m_nHistoryTipGui ;
    int         m_nHistoryTipID ;
    ///需要返回值的提示
    int         m_nNeedRetTips ;
    ///进程间通讯服务器
    CIMCSrv     m_imcSrv;


    /**
     * other
     */
    ///日志
    CYlog          m_runlog ;
    CYlog          m_log[enlog_count];
    ///是否注册
    bool           m_bisRegister ;
    ///本地数据库
    CYlocaldb      m_localDB ;
    ///网络管理
    CNetEngine     m_NetEngine ;
    ///策略管理
    CPolicyManager m_policyMgr ;
    ///是否注册
    bool           m_bRegister ;
    ///注册IP
    std::string    m_strRegiP;
    ///注册MAC
    std::string    m_strRegMac ;
    ///设备标识
    std::string    m_strDevid ;
    ///日志过滤类
    CAuditlogFilter  m_logFilter ;
    ///funcmap锁
    CLocker        m_funcmapLocker;
    ///funcmap
    std::map<int,pTips_retfunc>  m_funcMap ;
    std::map<int,std::string>    m_tipXmlMap ;
    ///服务器IP
    std::string    m_strSrvIp ;
    std::string    m_strPort  ;
    std::string    m_strReginfo; //注册界面的字符串
    ///是否一直断网
    bool           m_bofflineAlaways ;
    volatile bool          m_bcurOffline; ///当前是否断网
    ///注册网卡名
    std::string   m_strRegNic ;
    ///策略断网的标识
    bool          m_bCloseNet[en_policytype_count];
    int           m_bLoginDeskTop ;
    bool          m_bCloseNetFromSrv ; ///服务器要求关闭网络
    ///时间通知
    YCommonTool::CEventNotify m_eventNotifyer ;
    ///高级设置上次的状态
    bool          m_badvCfgEnable[en_policytype_count];
    ///监听端口
    std::string    m_strlistenPort;
    ///标志有没有备份过一次IPTABLES规则
    bool           m_bisSave ;
    CMyIptables    m_myIptables ;
    bool           m_bwinSrv ;
    //std::string    m_server_time;
    };

#endif /* CVCFAPP_H_ */
