/*
 * CMyIptables.cpp
 *
 *  Created on: 2015-4-3
 *      Author: sharp
 */

#include "CMyIptables.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char * MY_IPT_CHAIN_NAME =  "vrv_sharp";
char * MY_IPT_CHAIN_NAME4httpctrl = "YCPER_FILTER" ;

#ifndef __APPLE__
static int   get_mychainNum() {
    char buffer[256] = "";
    {
        sprintf(buffer,"iptables -L OUTPUT -n");
        FILE *fp= popen(buffer,"r");
        if(fp == NULL ) {
            return -1 ;
        }
        int nlen = strlen(MY_IPT_CHAIN_NAME);
        int cnt = -2 ;
        while(fgets(buffer,255,fp)) {
            cnt++ ;
            if(cnt>0) {
                if(strncmp(buffer,MY_IPT_CHAIN_NAME,nlen) == 0) {
                    pclose(fp);
                    return cnt ;
                }
            }
        }
        pclose(fp);
    }
    return 0 ;
}
#endif

CMyIptables::CMyIptables() {
    /**
     * 增加IPTABLES自定义规则链
     */
#ifndef __APPLE__
    clearAll();

    char  cmd[256] = "";
    ///新建规则链
    sprintf(cmd,"iptables -N %s",MY_IPT_CHAIN_NAME);
    system(cmd);
    ///将该规则链加到OUPUT链上
    sprintf(cmd,"iptables -I OUTPUT -j %s",MY_IPT_CHAIN_NAME);
    system(cmd);

    ///将上网访问控制的规则链加到MY_IPT_CHAIN_NAME上
    sprintf(cmd,"iptables -N %s",MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
    sprintf(cmd,"iptables -I %s -j %s",MY_IPT_CHAIN_NAME,MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);

#else  //APPLE_HERE

#endif

}

CMyIptables::~CMyIptables() {
#ifndef __APPLE__
    char  cmd[256] = "";
    sprintf(cmd,"iptables -D OUTPUT -j %s",MY_IPT_CHAIN_NAME);

    system(cmd);
    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME);
    system(cmd);
    sprintf(cmd,"iptables -X %s",MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
    sprintf(cmd,"iptables -X %s",MY_IPT_CHAIN_NAME);
    system(cmd);

#else  //APPLE_HERE

#endif

}



void  CMyIptables::check() {
#ifndef __APPLE__
    int index = get_mychainNum();
    char  cmd[256] = "";
    if(index == 0) { //不存在
        sprintf(cmd,"iptables -I OUTPUT -j %s",MY_IPT_CHAIN_NAME);
        system(cmd);
    } else if(index > 0){
        //删除掉原来的，重新加入
        sprintf(cmd,"iptables -D OUTPUT %d",index);
        system(cmd);
        sprintf(cmd,"iptables -I OUTPUT -j %s",MY_IPT_CHAIN_NAME);
        system(cmd);
    }

#else  //APPLE_HERE

#endif

}

void  CMyIptables::closeNet() {
#ifndef __APPLE__
    //check();
    char  cmd[256] = "";
    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME);
    system(cmd);
    sprintf(cmd,"iptables -I %s -p tcp  -j DROP"
            ";iptables -I %s -p tcp -d %s  -j ACCEPT"
            ";iptables -I %s -p tcp -d 127.0.0.1  -j ACCEPT",MY_IPT_CHAIN_NAME
            ,MY_IPT_CHAIN_NAME
            ,m_strSrvIp.c_str()
            ,MY_IPT_CHAIN_NAME);
    system(cmd);
    ///加入上网访问控制的链表
    sprintf(cmd,"iptables -A %s -j %s",MY_IPT_CHAIN_NAME,MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
#else  //APPLE_HERE

#endif


}

void  CMyIptables::openNet() {
#ifndef __APPLE__
    char  cmd[256] = "";
    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME);
    system(cmd);
#else  //APPLE_HERE

#endif

}

void CMyIptables::clearAll() {
#ifndef __APPLE__
    //在初始化之前清除之前添加的各种规则。
    char  cmd[256] = "";

    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
    sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME);
    system(cmd);

    sprintf(cmd,"iptables -D OUTPUT -j %s",MY_IPT_CHAIN_NAME);
    int ret = -1;
    do {
        ret = system(cmd);
    } while(ret == 0);

    sprintf(cmd,"iptables -X %s",MY_IPT_CHAIN_NAME4httpctrl);
    system(cmd);
    sprintf(cmd,"iptables -X %s",MY_IPT_CHAIN_NAME);
    system(cmd);

    //删除服务器规则
    sprintf(cmd,"iptables -D  INPUT -s %s -j ACCEPT",m_strSrvIp.c_str());
    do {
        ret = system(cmd);
    } while(ret == 0);

#else  //APPLE_HERE

#endif

}

