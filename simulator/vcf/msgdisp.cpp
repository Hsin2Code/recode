#include <stdlib.h>
#include "msgdisp.h"
#include "include/zmq/zmq.h"
#include "common/CLocker.h"
#include <unistd.h>
#include <stdarg.h>
#include <string.h>


int  IMsgdispatcher::m_nindex = 1 ;

/*
 *
 */

void  IMsgdispatcher::log_outstd(const char * format,...) {
#if  1
	va_list vl ;
	char buffer[1024];
	va_start(vl,format);
	vsprintf(buffer,format,vl);
	va_end(vl);
	printf(buffer);
#endif
	return ;
}


void * _memcpy(void *dest, const char *src, size_t count)
 {
         char *tmp = (char *)dest;
         const char *s = (const char *)src;
         while (count--)
              *tmp++ = *s++;
         return dest;
 }

IMsgdispatcher::IMsgdispatcher(int ntrd)
{
    m_zmqCtx = zmq_init(ntrd);
    memset(m_pDispatcherArray,0,sizeof(m_pDispatcherArray));
}

IMsgdispatcher::~IMsgdispatcher()
{
    stopDispatcher();
    clear();
    if(m_zmqCtx) {
        zmq_term(m_zmqCtx);
        m_zmqCtx = NULL ;
    }
}

void IMsgdispatcher::clear()
{
	for(int index = 0 ; index < max_disp_count ; index++) {
		if(m_pDispatcherArray[index]) {
			delete m_pDispatcherArray[index] ;
			m_pDispatcherArray[index] = NULL ;
		}
	}
}

void *   IMsgdispatcher::disp_worker(PVOID pParam)
{
	using namespace YCommonTool ;
	tag_Dispatcher * pDisp  =  (tag_Dispatcher *)pParam ;
	pthread_t pid = pthread_self();
    zmq_msg_t msg_t ;
	PVOID  pull  = zmq_socket(pDisp->pDisp->m_zmqCtx,ZMQ_PULL);
    int rc = zmq_connect(pull,pDisp->name.c_str());
    if(rc < 0)  return 0 ;
    int msgsize = 1000;
    zmq_setsockopt(pull,ZMQ_RCVHWM,&msgsize,sizeof(msgsize));


    if(!pDisp->pDisp->worker_start(pDisp,pid)) {
        goto finish_work ;
    }


    while(pDisp->bruning) {
    	zmq_msg_init(&msg_t);
    	int ret = zmq_msg_recv(&msg_t,pull,0);
    	if(ret < 0) {
    		lock_dec(&pDisp->msgcount);
    		continue ;
    	}

    	zmq_msg_size((zmq_msg_t *)&msg_t);
    	tag_msg * pMsg = (tag_msg *)zmq_msg_data((zmq_msg_t *)&msg_t);
    	if(pMsg->cmd == 0xFFFF) {
    		break ;
    	}
    	lock_dec(&pDisp->msgcount);
		/**
		 * 执行消息处理
		 */
    	bool bsucc = (*(pDisp->pfn))(pMsg->cmd,pMsg->data,pMsg->len,pDisp->param,pDisp->id);

    	if(pMsg->pSem) {
            /*same as linux and osx*/
    		sem_post((sem_t *)pMsg->pSem);
    	}
		if(!bsucc) { ///执行失败
			if(pMsg->sender) { ///return msg to sender , 先空起来

			}
		}
        zmq_msg_close(&msg_t);
		/**
		 * 暂时设定暂停10毫秒 = 10000微秒
		 */
		usleep(1000);
    }

finish_work:
    zmq_msg_close(&msg_t);
    zmq_close(pull);
	return pDisp->pDisp->worker_finish(pDisp,pid);
}

int  IMsgdispatcher::registerDispatcher(const char * pName,
	     msg_pworker pfn,
	     unsigned short trdcnt,
	     void *  param) {

	if(pName == NULL) {
		return -1 ;
	}
	/**
	 * 查找有没有相同名称的通道
	 */
	int index = 0 ;
	for(index = 0 ; index < max_disp_count ; index++) {
		if(m_pDispatcherArray[index]) {
			if((m_pDispatcherArray[index])->name == pName) {
				return index ;
			}
		}
	}

	tag_Dispatcher * pDisp = NULL;
	///寻找一个没有使用的通道，如果为通道指针为空,直接使用。
	for(index = 0 ; index < max_disp_count ; index++) {
		if(m_pDispatcherArray[index] == NULL) {
			m_pDispatcherArray[index] = new tag_Dispatcher;
			pDisp = m_pDispatcherArray[index] ;
			break ;
		} else {
			///没有使用
			if(!(m_pDispatcherArray[index])->brun) {
				pDisp = m_pDispatcherArray[index] ;
				break ;
			}
		}
	}
	if(pDisp==NULL) { ///通道全部沾满
		return -1;
	}

	unsigned int * pThis = (unsigned int *)this;
	pDisp->id = index ;
	char name[129] = "" ;
	pDisp->pEngine = zmq_socket(m_zmqCtx,ZMQ_PUSH);
	sprintf(name,"inproc://%p-%s",pThis,pName);///
	pDisp->name = name;
	pDisp->pfn = pfn ;
	pDisp->plock = new YCommonTool::CLocker ;
	pDisp->pDisp = this ;
	pDisp->param = param ;
	pDisp->bruning = true ;
	pDisp->brun = true ;

	int msgsize = 1000;
	zmq_setsockopt(pDisp->pEngine,ZMQ_SNDHWM,&msgsize,sizeof(msgsize));
    
	/**
	 * 绑定
	 */
	int rc = zmq_bind(pDisp->pEngine,name);
	if(rc < 0) return 0 ;

	for(index = 0;index < trdcnt ; index++) {
		thread_info info ;
		int rc = pthread_create(&info.tid,NULL,disp_worker,(PVOID)pDisp);
		if(rc != 0){
			return 0 ;
		}
		pDisp->trd_array.push_back(info);
	}

	return pDisp->id ;
}

bool  IMsgdispatcher::sendtoDispatcher(int id ,unsigned short cmd , PVOID pdata , int len , int sendid,bool bsync,bool block)
{
	if(id < 0 || id >= max_disp_count ) return false ;
	tag_Dispatcher * pDisp = m_pDispatcherArray[id];
	if(!pDisp->bruning) {
		return false ;
	}

	{   ///发送代码, 都是通过zmq_msg_init_size 由ZMQ管理内存，
		///调用频繁或者
		int rc = 0 ;
		zmq_msg_t message ;
		int nszie = sizeof(tag_msg) + len ;
		zmq_msg_init_size(&message,nszie);
		tag_msg * pmsg_t = (tag_msg *)zmq_msg_data(&message);
		pmsg_t->cmd = cmd ;
		pmsg_t->len = len ;
		pmsg_t->sender = sendid;
		pmsg_t->pSem = 0 ;
		if(len && pdata) {
			_memcpy(pmsg_t->data,(const char *)pdata,len);
        }

		if(block) {   //发送前枷锁
			YCommonTool::CLockHelper helper((YCommonTool::CLocker *)pDisp->plock);
			if(bsync) { ///设置同步
#ifndef __APPLE__
				pmsg_t->pSem = &(pDisp->Sem);
#else
				pmsg_t->pSem = pDisp->pSem_Disp;
#endif
			}
			///提前加上
			YCommonTool::lock_inc(&pDisp->msgcount);
			rc = zmq_msg_send(&message,pDisp->pEngine, 0);
			if(bsync) { ///通知等待线程执行完毕
#ifndef __APPLE__
                sem_wait(&(pDisp->Sem));
#else
                sem_wait(pDisp->pSem_Disp);
#endif

			}
		} else {
			if(bsync) { ///设置同步
#ifndef __APPLE__
				pmsg_t->pSem = &(pDisp->Sem);
#else
                pmsg_t->pSem = pDisp->pSem_Disp;
#endif
			}
			///提前加上
			YCommonTool::lock_inc(&pDisp->msgcount);
			rc = zmq_msg_send(&message,pDisp->pEngine, 0);
			if(bsync) { ///通知等待线程执行完毕
#ifndef __APPLE__
                sem_wait(&(pDisp->Sem));
#else

                sem_wait(pDisp->pSem_Disp);
#endif
			}
		}

		zmq_msg_close(&message);
		if(rc < 0) {
			YCommonTool::lock_dec(&pDisp->msgcount);
			return false ;
		}
	}

	return true ;
}

IMsgdispatcher::tag_Dispatcher * IMsgdispatcher::getDispinfo(int id) {
	if(id < 0 || id >= max_disp_count ) return NULL ;
	return m_pDispatcherArray[id];
}

void  IMsgdispatcher::stopDispatcher(int id) {
	if(id == -1) {
		int i = 0;
		for(; i < max_disp_count ; i++) {
			stopDispatcher(i);
		}
	} else {
		tag_Dispatcher * pDisp =  getDispinfo(id);
		if(pDisp == NULL)  return ;

		if(pDisp->bruning == false
				|| pDisp->brun == false) {
			return ;
		}
		zmq_msg_t message ;
		pDisp->bruning = false ;
		zmq_msg_init_size(&message,sizeof(tag_msg));
        tag_msg * pmsg_t = (tag_msg *)zmq_msg_data(&message);
        pmsg_t->cmd = 0xffff;
        pmsg_t->len = 0 ;
        pmsg_t->pSem = 0 ;

        std::vector<thread_info>::iterator iterTrd = pDisp->trd_array.begin();
        {
        	YCommonTool::CLockHelper helper((YCommonTool::CLocker *)pDisp->plock);
        	while(iterTrd != pDisp->trd_array.end()) {
        		zmq_msg_send(&message,pDisp->pEngine,0);
        		iterTrd++ ;
        	}
        }
        void *status;
        iterTrd  = pDisp->trd_array.begin();
        while(iterTrd != pDisp->trd_array.end()) {
        	pthread_join(iterTrd->tid,&status);
        	iterTrd++ ;
        }

        zmq_msg_close(&message);
        if(pDisp->plock) {
        	delete (YCommonTool::CLocker *)pDisp->plock  ;
        	pDisp->plock = NULL ;
        }

        if(pDisp->pEngine) {
        	zmq_close(pDisp->pEngine);
        	pDisp->pEngine = NULL ;
        }
        pDisp->brun = false ;
	}
}



