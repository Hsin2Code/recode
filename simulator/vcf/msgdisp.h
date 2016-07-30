#ifndef  THIS_IS_MSGDISP_HEADER_EEEEEEEEEEEEEEEEER
#define  THIS_IS_MSGDISP_HEADER_EEEEEEEEEEEEEEEEER
/*
Model:
Description: 异步消息类，需要ZMQ的支持\n
Author: sharp.y\n
Changelog:
   （1） 2014年11月24日第一次建立， 添加类声明。\n
   （2） 2014年12月23日动态MAP修改为静态数组
*/
#include <map>
#include <vector>
#include <string>
#include <pthread.h>
#include <list>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <semaphore.h>

#ifndef PVOID
   #define PVOID  void *
#endif

#ifndef NULL
   #define  NULL  0
#endif

///最大通道数
const  int   max_disp_count = 100 ;

/**
 * 类声明
 */
class IMsgdispatcher ;


/**
 * Author: Sharp.y
 * Description:　消息的回调函数
 * Params: (1) cmd : 消息号，自定义　(2) pbuffer: 参数结构体指针　(3) len 结构体长度 (4) 附加参数 ,(5) 发送者的通道ID
 * Returns : 布尔值，　当前没有特殊意义。

*/
typedef bool (*msg_pworker)(unsigned short cmd , PVOID buffer , int len , void  * param,unsigned int id);

///消费分发通道类，提供异步的消息分发管理。
class IMsgdispatcher {
public :
    struct thread_info {
    	///线程ID
        pthread_t tid ;
    };
    /**
    *   消息通道数据
    */
    struct tag_Dispatcher {
    ///消息通道的ID
	int    id ;
	///通道参数
	void    *   param ;
	///通道处理回调函数
	msg_pworker  pfn ;
	///通道线程运行标志
	volatile bool bruning ;
	///通道运行标识
	volatile bool brun ;
	///通道消息数
	volatile int  msgcount ;
	///通道发送消息锁
	PVOID   plock ;
	///通道消息套接字指针
	PVOID   pEngine ;
	///同步消息信号量
#ifndef __APPLE__
	sem_t   Sem ;
#else
    sem_t   *pSem_Disp;
    char sem_name[65];
#endif
	///IMsgdispatcher类指针
	IMsgdispatcher * pDisp ;
	///通道名称
	std::string  name ;
	///通道处理线程数组
	std::vector<thread_info> trd_array ;
	tag_Dispatcher() {
		   brun = false ;
	       id = 0 ;
	       pfn = NULL ;
	       bruning = false ;
	       plock = NULL ;
	       pEngine = NULL ;
	       pDisp = NULL ;
	       msgcount = 0 ;
	       param = 0 ;
#ifndef __APPLE__
	       sem_init(&Sem,0,0);
#else
           memset(sem_name, 0, sizeof(sem_name));
           uuid_t uuid_org;
           uuid_generate(uuid_org);
           uuid_unparse(uuid_org, sem_name);
           //PSEMNAMLEN = 31
           sem_name[30] = '\0';
	       pSem_Disp = sem_open(sem_name, O_CREAT|O_EXCL, S_IRWXU, 0);
           if(pSem_Disp == SEM_FAILED) {
               printf("%s %s\n", "Sem_init Erroror", strerror(errno));
           }
#endif
	   }
	~tag_Dispatcher() {
#ifndef __APPLE__
		   sem_destroy(&Sem);
#else
           if(pSem_Disp != NULL) {
               sem_close(pSem_Disp);
               sem_unlink(sem_name);
               pSem_Disp = NULL;
           }
#endif
	   }
    };
    /**
    *  消息结构体
    */
    struct tag_msg {
       ///消息编号
       unsigned short  cmd ;
       ///发送者ID
       unsigned int    sender ;
       ///同步消息所用的信号量
       void  *         pSem ;
       ///数据的长度
       unsigned int    len ;
       ///数据的内容
       unsigned char   data[0];
    };

    typedef std::map<int , tag_Dispatcher *> CDispacherMap ;

    /**
     * 输出日志
     */
    void   log_outstd(const char * format,...);
  public:
     /**
      * ntrd 为处理消息调度的线程 数
      */
    IMsgdispatcher(int ntrd) ;
    virtual  ~IMsgdispatcher();
  protected:
     /**
      * 清理数据
      */
     void  clear();
     /**
      * 获取通道结构数据
      * 如果没由找到，返回空指针
      */
     tag_Dispatcher *  getDispinfo(int id);

     /**
      * 从名称获取id
      * 返回-1标识没有找到
      */
     int               getDispid(std::string name) {
    	 for(int i = 0 ; i < max_disp_count ; i++) {
    		 if(m_pDispatcherArray[i]) {
    			 if((m_pDispatcherArray[i])->name == name) {
					 return i ;
    			 }
    		 }
    	 }
    	 return -1 ;
     }
     /**
      *  获取ZMQ实例
      */
     void *    get_zmqCtx() {
    	 return m_zmqCtx ;
     }

     /**
      * 处理线程方法
      */
      static  void *    disp_worker(PVOID pParam);
  public:
    /**
    *  停止消息处理通道，参数为停止通道的ID号，0的话停止所有通道
    */
    void  stopDispatcher(int id = -1 );

    /**
    * description : 注册一个消息处理通道
    * params : (1) pName 通道名称
               (2) pfn  消息处理函数
               (3) trdcnt 处理消息的线程数、
               (4）param  附加参数
    * returns: 返回通道号，失败返回-1
    */
    int   registerDispatcher(const char * pName,
			     msg_pworker pfn,
			     unsigned short trdcnt = 1,
			     void *  param = 0);

    /**
    * description: 发送 消息到  处理
    * params : (1) 接受通道ID， （2） 消息编号 , (3) 消息数据 (4) 数据长度 (5) 发送者通道ID (6) 是否同步 (7) 是否枷锁
    * returns : true is succ , false is failed
    */
    bool  sendtoDispatcher(int id ,
    		unsigned short cmd ,
    		PVOID pdata = NULL ,
    		int len = 0,
    		int sendid = 0,
    		bool bsync = false,
    		bool lock = true);

  public :
    /**
     * 消息通道处理线程启动的时候会调用
     * params: (1) pDisp 通道数据结构
     *        （2） pid 线程自身ID
     * returns: 返回true程序继续执行,返回false程序退出
     */
    virtual  bool     worker_start(tag_Dispatcher * pDisp , pthread_t pid) { return true;}

    /**
     * 消息通道处理线程退出的时候会调用
     * params: 同worker_start
     * */
    virtual  void  *  worker_finish(tag_Dispatcher * pDisp , pthread_t pid){ return (void *)0 ;}
  private:
    ///通道的ID计数
    static     int      m_nindex  ;
    ///ZMQ实例指针
    PVOID               m_zmqCtx  ;
    ///通道指针
    tag_Dispatcher *    m_pDispatcherArray[max_disp_count];
};


#endif
