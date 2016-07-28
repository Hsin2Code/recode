#include <iostream>
#include "run_policy_sfd.h"
#include "common.h"
#include "Markup.h"
#include "old_functions.h"
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*本地宏定义*/
#ifndef EDPSERVER_PORT				
#define	EDPSERVER_PORT				88		//服务器监听端口
#endif//EDPSERVER_PORT				

#ifndef AGENT_DOWNLOADFILE			
#define	AGENT_DOWNLOADFILE			97		//请求下载文件
#endif//AGENT_DOWNLOADFILE			

#ifndef AGENT_DOWNLOADFINISH	
#define	AGENT_DOWNLOADFINISH		98		//文件下载结束
#endif//AGENT_DOWNLOADFINISH

#ifndef AGENT_GETDOWNLOADLIST		
#define	AGENT_GETDOWNLOADLIST		99
#endif//AGENT_GETDOWNLOADLIST

#define		DOWN_PATCH			0x01
#define		DOWN_SOFT			0x02
#define		DOWN_USERBIND		0x03

#ifndef VRV_TAG
#define	VRV_TAG		0x5652		//初始化pkt_head.mtag项
#endif//VRV_TAG

#ifndef VRV_FLAG	
#define	VRV_FLAG	0x56525620		//VRV1.0=0X56525620
#endif//VRV_FLAG	

#define		MAX_LEN		(1024 * 1024)		//限定每次下载文件长度为512

#define		FILE_TYPE_RPM			1		//rpm软件包
#define		FILE_TYPE_DEB			2		//deb软件包
#define		FILE_TYPE_CLT_UPDATE	3		//客户端升级包

#define FILE_POLICY_CRC	"/var/log/crc.txt"
#define CLIENT_UPDATE_FILE_PATH "/opt/edp_vrv/bin/updatefile/package"
#define CLIENT_UPDATE_PROGRAM_NAME "/opt/edp_vrv/bin/update"
#define FILE_DL_FILE_INFO "./softdown.txt"

typedef struct
{
    unsigned int m_flag;		//VRV版本
    unsigned short m_type;		//功能号，0表示成功，1表示失败
    unsigned short m_what;		//信息内容
    unsigned int m_pwd;		//加密秘钥或者加密版本
    unsigned int pkt_crc;		//CRC校验码
    unsigned int pkt_len;		//数据报总长度：包头+数据包
    unsigned short m_tag;		//默认置w为0x5652
    unsigned short m_size;		//包头长度，默认值为28
    unsigned int m_address;		//地址，预留选项，该版本无此功能
} pkt_head;

policy_st m_policy;
void softDownCtl_log_run_info (const char *val) {
    if(val != NULL) {
        SM_LOG() << val;
    } else {
        SM_ERROR() << "log msg empty";
    }

}

static int delete_target_path (const char *targetpath )
{
    char delete_path[1024]={'\0'};
    char buf_log[512] = {0};
    int ret = 0;

    strcpy(delete_path,"rm -rf ");
    strcat(delete_path,targetpath);
    ret = system(delete_path);

    snprintf(buf_log, sizeof(buf_log), "removing %s ret:%d", targetpath, ret);
    softDownCtl_log_run_info(buf_log);

    return EXIT_SUCCESS;
}	

static void replaceAll(char * src,char oldChar,char newChar)
{
    while(*src!='\0')
    {
        if(*src==oldChar) 
        {
            *src=newChar;
        }
        src++;
    }
}


/**
 *	函数名：send_pkt
 *	作者：张峰堃
 *	时间：2012/06/04
 *	描述：第一次调用send函数和服务器建立握手连接，第二次调用send函数发送sendbuf缓冲区中的数据
 *	参数：sockfd(文件描述符）,sendbuf(发送缓冲区),sendsize(发送长度),type(数据类型，宏定义AGENT_DOWNLOADFILE和AGENT_DOWNFINISH可选)
 *	返回值：发送成功返回0，发送失败返回-1
 */
static int send_pkt(int sockfd, char *sendbuf,unsigned int sendsize, int type, unsigned int pwd)
{
    int pktheadlength = sizeof(pkt_head);
    int len_send = 0;
    pkt_head pkthead;

    memset(&pkthead, 0, pktheadlength);

    pkthead.m_flag = VRV_FLAG;		//VRV1.0=0x56525620
    pkthead.m_type = type;		//类型，宏定义AGENT_DOWNLOADFILE和AGENT_DOWNFINISH可选
    pkthead.m_what = 0;		//包头，无数据内容
    //pkthead.m_pwd = 0;		//包头，无加密
    pkthead.m_pwd = pwd;      //包头，已加密 modified by donghx 2014.03.25
    pkthead.pkt_crc = 0;		//包头，无数据crc校验
    pkthead.m_tag = VRV_TAG;		//默认值，0x5652
    pkthead.m_size = pktheadlength;		//包头长度
    pkthead.m_address = 0;		//预留选项
    pkthead.pkt_len = pktheadlength + sendsize;		//包头+数据包长度

    /*-----------------------------------------------------------------------------
     *  功能：发送包头，建立握手连接
     *-----------------------------------------------------------------------------*/
    len_send = send(sockfd, &pkthead, pktheadlength, MSG_WAITALL);
    if(len_send != pktheadlength)
    {
        softDownCtl_log_run_info("send_pkt head err.");
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：发送sendbuf中的数据
     *-----------------------------------------------------------------------------*/
    len_send = send(sockfd, sendbuf, sendsize, MSG_WAITALL);
    if((unsigned int)len_send != sendsize)
    {
        softDownCtl_log_run_info("send_pkt dat err.");
        return -1;
    }

    return 0;
}

/**
 *  函数名：recv_pkt
 *  作者：张峰堃
 *  时间：2012/06/04
 *  描述：接收数据，如果接收数据小于1M，直接存放在文件描述符fd所指向的文件，
 *        大于1M时，采取边读边写的方式下载文件（每次读写1M)
 *  参数：sockfd(接收socket),filename(用于保存接收文件）,offset(偏移量，扩展包和
 *  	    普通包的差值)
 *  返回值：接收成功返回0,失败返回-1
 */
static int  recv_pkt(int sockfd,const char *filename, int offset, unsigned int pwd) {
    int pktheadlength = 0;;
    pkt_head pkthead;
    char buf_log[512] = {0};
    char recvdata[MAX_LEN] = {0};
    int recv_len = 0;

    if(NULL == filename) {
        softDownCtl_log_run_info("input ptr is null, recv_pkt err.");
        return -1;
    }

    pktheadlength = sizeof(pkt_head) - offset;		//普通数据包头长度：扩展包头长度-偏移量

    if ((recv_len = recv(sockfd, &pkthead, pktheadlength, MSG_WAITALL)) == pktheadlength) {
        snprintf(buf_log, sizeof(buf_log), 
                "recv_pkt,recv head ok:recv-len, headlen->%d, %d",recv_len, pktheadlength);
        softDownCtl_log_run_info(buf_log);
        softDownCtl_log_run_info("recv_pkt,recv pkthead ok.");
    } else {
        snprintf(buf_log, sizeof(buf_log), "recv_pkt,recv head err:recv-len, headlen->%d, %d",recv_len, pktheadlength);

        int err = 1;
        socklen_t len = sizeof err;
        if (-1 == getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&err, &len)) {
            SM_ERROR() <<  "error when get socket error";
        }
        if (err) {
            errno = err;              // set errno to the socket SO_ERROR
        }
        char buf_[128] = {0};
        sprintf(buf_, "%s-%s %d", "error in recv head----> ", strerror(errno), errno);
        softDownCtl_log_run_info(buf_);

        softDownCtl_log_run_info(buf_log);
        return -1;
    }

    int datalength = pkthead.pkt_len - pktheadlength;
    int fd = open(filename, O_RDWR| O_CREAT| O_APPEND, 0664);
    if(fd == -1) {
        snprintf(buf_log, sizeof(buf_log), "recv_pkt, open %s err,code:%d", filename, errno);
        softDownCtl_log_run_info(buf_log);
        return -1;
    }

    snprintf(buf_log, sizeof(buf_log), "recv_pkt,datalen:%d",datalength);
    softDownCtl_log_run_info(buf_log);

    int d_size = datalength >= MAX_LEN ? MAX_LEN : datalength;
    while (datalength > 0) {
        int _inner_ret = -1;
        if((_inner_ret = recv(sockfd, recvdata, d_size, MSG_WAITALL)) != -1) {
            if (offset == 0 && pwd != 0) {
                if (!Decrypt_V1(pwd, (LPVOID)recvdata, (LPVOID)recvdata, _inner_ret, 0)) {
                    softDownCtl_log_run_info("recv_pkt,len>Max_len, decrypt err.");
                    close(fd);
                    return -1;
                } 
            }
            if(_inner_ret != write(fd, recvdata, _inner_ret)) {
                softDownCtl_log_run_info("recv_pkt,len>Max_len,decrypt,write dat err.");
                close(fd);
                return -1;
            }
            datalength -= _inner_ret;
        } else {
            char buf_[128] = {0};
            sprintf(buf_, "%s->%d inner_ret : %d", "recv_msg len:", datalength, _inner_ret);
            softDownCtl_log_run_info(buf_);

            softDownCtl_log_run_info("recv_pkt,len>Max_len, err1.");
            close(fd);
            return -1;
        }
    }
	close(fd);
    return 0;
}

bool import_xml(const char *content) {
    char buf_policy[512] = {0};
    if(content == NULL) {
        return false;
    }
    CMarkup  xml ;
    if(!xml.SetDoc(content))
    {
        SM_ERROR() << "import_xml:SetDoc failed.";
        return false ;
    }

    memset(&m_policy, 0, sizeof(policy_st));

    if(xml.FindElem("vrvscript"))
    {
        xml.IntoElem();
        std::string tmp_str;

        while(xml.FindElem("item"))
        {
            tmp_str = xml.GetAttrib("RunHidden");
            if(0 != tmp_str.length())//获取RunHidden属性值
            {
                m_policy.runhidden = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "run_hidden:%d", m_policy.runhidden);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("IsSystem");
            if(0 != tmp_str.length())//获取IsSystem属性值
            {
                m_policy.issystem = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "issystem:%d", m_policy.issystem);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("Run");
            if(0 != tmp_str.length())//获取Run属性值
            {
                m_policy.run = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "run:%d", m_policy.run);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("Prompt");
            if(0 != tmp_str.length())//获取prompt 属性值
            {
                m_policy.prompt = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "prompt:%d", m_policy.prompt);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("DeleteSource");
            if(0 != tmp_str.length())//获取DeleteSource 属性值
            {
                m_policy.deletesource = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "DeleteSource:%d", m_policy.deletesource);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("RepeatDO");
            if(0 != tmp_str.length())//获取RepeatDO 属性值
            {
                m_policy.repeatdo = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "RepeatDO:%d", m_policy.repeatdo);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("AutoSync");
            if(0 != tmp_str.length())//获取AutoSync属性值
            {
                m_policy.autosync = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), ":AutoSync:%d", m_policy.autosync);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("FileCRC");
            if(0 != tmp_str.length())//获取FileCRC属性值
            {
                m_policy.filecrc = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "FileCRC:%d", m_policy.filecrc);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("InstallOkTime");
            if(0 != tmp_str.length())//获取InstallOkTime属性值
            {
                m_policy.installoktime = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkTime:%d", m_policy.installoktime);
                SM_LOG() << buf_policy;
            }
            else
            {
                m_policy.installoktime = 15;
                SM_LOG() << "installOkTime:using default val:15 ";
            }

            tmp_str = xml.GetAttrib("ReDownIntervalTime");
            if(0 != tmp_str.length())//获取ReDownIntervalTime属性值
            {
                m_policy.redownintervaltime = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "ReDownIntervalTime:%d", m_policy.redownintervaltime);
                SM_LOG() << buf_policy;
            }
            else
            {
                m_policy.redownintervaltime = 60;
            }

            tmp_str = xml.GetAttrib("FileName");
            if(0 != tmp_str.length())//获取FileName属性值
            {
                snprintf(m_policy.filename, LEN_FILE_NAME+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "FileName:%s", m_policy.filename);
            }

            tmp_str = xml.GetAttrib("TargetPath");
            if(0 != tmp_str.length())//获取TargetPath属性值
            {
                snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "%s", tmp_str.c_str());
                replaceAll(m_policy.targetpath,'\\','/');
                snprintf(buf_policy, sizeof(buf_policy), "TargetPath:%s", m_policy.targetpath);
                SM_LOG() << buf_policy;
                if(m_policy.targetpath[0] != '/')
                {
                    snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "/tmp/tmp");
                    SM_LOG() << "TargetPath:using default val:/tmp/tmp";
                }
            }
            else
            {
                snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "/tmp/tmp");
                SM_LOG() << "TargetPath:using default val:/tmp/tmp";
            }

            tmp_str = xml.GetAttrib("CmdArgv");
            if(0 != tmp_str.length())//获取CmdArgv属性值
            {
                snprintf(m_policy.cmdargv , LEN_PARAM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "CmdArgv:%s", m_policy.cmdargv);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("RunMsg");
            if(0 != tmp_str.length())//获取RunMsg属性值
            {
                snprintf(m_policy.runmsg, LEN_TIP_MSG+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "RunMsg:%s", m_policy.runmsg);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("InstallOkFileVersion");
            if(0 != tmp_str.length())//获取InstallOkFileVersion属性值
            {
                snprintf(m_policy.installokfileversion, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkFileVersion:%s", m_policy.installokfileversion);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("InstallOkFile");
            if(0 != tmp_str.length())//获取InstallOkFile属性值
            {
                snprintf(m_policy.installokfile, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkFile:%s", m_policy.installokfile);
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("InstallOkProcess");
            if(0 != tmp_str.length())//获取InstallOkProcess属性值
            {
                snprintf(m_policy.installokprocess, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkProcess:%s", m_policy.installokprocess );
                SM_LOG() << buf_policy;
            }

            tmp_str = xml.GetAttrib("LastUPFileAttr");
            if(0 != tmp_str.length())//获取LastUPFileAttr属性值
            {
                snprintf(m_policy.lastupfileattr, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "LastUPFileAttr:%s", m_policy.lastupfileattr);
                SM_LOG() << buf_policy;
            }
        }
        xml.OutOfElem();
    }


    return true;
}

static int get_dl_file_full_name(dl_file_info_st &dl_file_info, 
        const policy_st &m_policy)
{
    char *name = NULL;
    char *base_name  = NULL;
    char buf_log[512] = {0};
    char policy_filename[256] = {0};

    memset(&dl_file_info, 0, sizeof(dl_file_info_st));

    snprintf(policy_filename, sizeof(policy_filename), "%s", m_policy.filename);

    replaceAll(policy_filename,'\\','/');

    name = strrchr(policy_filename, '/');		
    if(NULL != name)
    {
	    base_name = strtok(name, "/");	
        if(NULL != base_name)
        {
            snprintf(buf_log, sizeof(buf_log), "get dl-file-info,name, base_name:%s,%s",name, base_name);
            SM_LOG() << buf_log;
            if(FILE_TYPE_CLT_UPDATE == m_policy.dl_file_type)
            {

                snprintf(dl_file_info.full_name, LEN_FILE_NAME + 1, "%s/%s_%s", CLIENT_UPDATE_FILE_PATH, base_name , g_dev_id.c_str());
                /*no upgrade*/
                return -1;
            }
            else
            {
                snprintf(dl_file_info.full_name, LEN_FILE_NAME + 1, "%s/%s_%s", m_policy.targetpath, base_name, g_dev_id.c_str());
            }
            dl_file_info.stat_ok = 1;

            snprintf(buf_log, sizeof(buf_log), "get dl-file-info ok:%s", dl_file_info.full_name);
            SM_LOG() << buf_log ;
            return 0;
        }
    }
    
    SM_ERROR() << "get dl-file-info fail";
    return -1;
}



static int download_file(policy_st &m_policy)
{
    string log_content;
    char mode[] = "0";
    char state[] = "0";
    char buf_log[512] = {0};
    
    dl_file_info_st dl_file_info;
    if(0 != get_dl_file_full_name(dl_file_info, m_policy))
    {
        SM_ERROR() <<  "get-dl-file-full-name err,downloadfile failed. ";
        return -1;
    }

    if(access(dl_file_info.full_name ,F_OK) == 0)
	{
        mode[0] = '0';
        state[0] = '0';
        SM_LOG() << "downloadfile already exists, downloadfile fail." ;
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：获取服务器ip信息，存放于ip_buf缓冲区中
     *-----------------------------------------------------------------------------*/
    string str_server_ip = g_server_ip;

    snprintf(buf_log, sizeof(buf_log), "downloadfile, svrip:%s", str_server_ip.c_str());
    SM_LOG() << buf_log ;

    /*-----------------------------------------------------------------------------
     *  功能：建立socket连接，连接服务器
     *-----------------------------------------------------------------------------*/
    int sockfd = 0;
    struct sockaddr_in serveraddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        softDownCtl_log_run_info("downloadfile, create socket err.");
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, create socket ok.");

    struct timeval tv;
    tv.tv_sec = 30; 
    tv.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#if 0
    struct linger s_linger;
    s_linger.l_onoff = 1;
    s_linger.l_linger = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &s_linger, sizeof(s_linger));
#endif

    bzero(&serveraddr, sizeof(serveraddr));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(EDPSERVER_PORT);
    serveraddr.sin_addr.s_addr = inet_addr(str_server_ip.c_str());

    if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
    {
        softDownCtl_log_run_info("downloadfile, connect err.");
        //close(sockfd);    
        closeSocket(sockfd);
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, connect ok.");

    char str_encrypt[1204] = {0};
    char filename[256+1]= {0};
    char filetype[256] = {0};

    string str_local_reg_ip = g_self_ipaddr;

    snprintf(buf_log, sizeof(buf_log), "downloadfile, local-ip:%s", str_local_reg_ip.c_str());
    softDownCtl_log_run_info(buf_log);

    strcpy(str_encrypt,"ActiveIPAddress=");
    strcat(str_encrypt, str_local_reg_ip.c_str());

    strcat(str_encrypt, STRITEM_TAG_END);
    sprintf(filetype, "Type=2%s", STRITEM_TAG_END);
    strncat(str_encrypt, filetype, sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    sprintf(filename, "FILENAME=%s%s", m_policy.filename, STRITEM_TAG_END);
    strncat(str_encrypt, filename, sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    strncat(str_encrypt, "Filepos=0", sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    strncat(str_encrypt, STRITEM_TAG_END, sizeof(str_encrypt) - strlen(str_encrypt) - 1);

    int b_enc_length = strlen(str_encrypt);
    snprintf(buf_log, sizeof(buf_log), "downloadfile, str-encrypt:%s", str_encrypt);
    softDownCtl_log_run_info(buf_log);

    unsigned int m_pwd = 0;
    if (1 == get_pwd(sockfd, m_pwd))
    {
        snprintf(buf_log, sizeof(buf_log), "downloadfile,pwd: %u", m_pwd);
        softDownCtl_log_run_info(buf_log);

        if(0 != m_pwd)
        {
            if(!Encrypt_V1(m_pwd, (LPVOID)str_encrypt, (LPVOID)str_encrypt, strlen(str_encrypt), 0))
            {
                softDownCtl_log_run_info("downloadfile,decrypt pwd err.");
                //close(sockfd);
                closeSocket(sockfd);
                return -1;
            }
        }
        else
        {
            softDownCtl_log_run_info("downloadfile,pwd is zero, no need to encrypt.");
        }
    }
    else
    {
        softDownCtl_log_run_info("downloadfile, get_pwd err.");
        //close(sockfd);
        closeSocket(sockfd);
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, get_pwd ok.");

    /*-----------------------------------------------------------------------------
     *  功能：发送包头，请求下载文件
     *-----------------------------------------------------------------------------*/

    if (send_pkt(sockfd, str_encrypt, b_enc_length, AGENT_DOWNLOADFILE, m_pwd) == 0)
    {
        softDownCtl_log_run_info("downloadfile,send download req ok.");
    }
    else
    {
        softDownCtl_log_run_info("downloadfile,send download req err.");
        //close(sockfd);
        closeSocket(sockfd);
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：接收文件下载信息，存放在softdowm.txt中
     *-----------------------------------------------------------------------------*/
    struct stat f_info;
    if(0 == lstat(FILE_DL_FILE_INFO, &f_info))
    {
        unlink(FILE_DL_FILE_INFO);
        softDownCtl_log_run_info("downloadfile,old dl-file-info removed.");
    }

    if (recv_pkt(sockfd, FILE_DL_FILE_INFO , 0, m_pwd) == 0)
    {
        softDownCtl_log_run_info("downloadfile,recv download file info ok.");
        //if(softDownCtl_dl_file_not_exist(FILE_DL_FILE_INFO))
        if(0)
        {
            char src_tip_buf[256] = {0};
            char dst_tip_buf[256] = {0};
            int dst_len = sizeof(dst_tip_buf);


            /*上报服务器*/
            mode[0] = '0';
            state[0] = '0';

            softDownCtl_log_run_info("downloadfile,src-file does not exist.");

    	    //close(sockfd);
            closeSocket(sockfd);
            return -1;
        }
    }
    else
    {
        softDownCtl_log_run_info("downloadfile,recv download file info err.");
    	//close(sockfd);
        closeSocket(sockfd);
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：首先根据xml中解析出的客户端接收文件路径，创建对应文件夹。然后接收软
     *  件包，存放在SOFTNAME中
     *-----------------------------------------------------------------------------*/

    static int flg_delete_dir = -1;
    if(access(m_policy.targetpath,F_OK)==0)
    {
	    flg_delete_dir = 0;
        softDownCtl_log_run_info("downloadfile,target dir already exists.");
    }
    else
    {
        char cmdbuf[256];
        memset(cmdbuf, 0, sizeof(cmdbuf));
        sprintf(cmdbuf, "mkdir -p %s", m_policy.targetpath);
        system(cmdbuf);
        struct stat st;
        if(stat(m_policy.targetpath, &st) == -1) 
        {
            softDownCtl_log_run_info("downloadfile,target dir does not exist,create err.");
            return -1;
        }
        if((st.st_mode & S_IFMT) == S_IFDIR)
        {
	        flg_delete_dir = 1;
            softDownCtl_log_run_info("downloadfile,target dir does not exist,create ok.");
        }
        else
        {
            //close(sockfd);
            closeSocket(sockfd);
            softDownCtl_log_run_info("downloadfile,target dir does not exist,failed to create.");
            return -1;
        }
    }

    if (recv_pkt(sockfd,dl_file_info.full_name, 8, m_pwd) == 0)
    {
        mode[0] = '0';
        state[0] = '1';

	}
	else
	{	
        mode[0] = '0';
        state[0] = '0';


        softDownCtl_log_run_info("downloadfile ,recv file err.");


        if (flg_delete_dir == 1)
        {
            delete_target_path(m_policy.targetpath); 
        }

        //close(sockfd);
        closeSocket(sockfd);
        return -1;
	}	

    softDownCtl_log_run_info("downloadfile ,recv file success.");
	//close(sockfd);
    closeSocket(sockfd);
    return 0;
}



void run_policy_sfd(const std::string &policy_content) {
    if(!import_xml(policy_content.c_str())) {
        SM_ERROR() << "import xml failed";
    }
    SM_LOG() << "start to run policy software down ..";
    SM_LOG() << policy_content;
    system("touch ./softdown.txt");
    {
        std::string down = "download_file:" + g_dev_id;
        TIMED_SCOPE(timer, down.c_str());
        download_file(m_policy);
    }
    SM_LOG() << "end run policy software down ..";
}

