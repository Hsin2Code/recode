/**
 * Comminfucc.cpp
 *
 *  Created on: 2014-11-27
 *      Author: sharp
 */
#include "Commonfunc.h"
#include <sys/time.h>
#include <stdlib.h>
#include "../../include/cli_config.h"
using namespace YCommonTool ;

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <paths.h>
#include <utmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <algorithm>
#include <errno.h>

#ifndef __APPLE__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/sysinfo.h>
#include <functional>
#else
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <uuid/uuid.h>
#endif


using namespace std;

long int YCommonTool::get_Timemsec() {
	struct timeval  tv;
	gettimeofday(&tv, 0);
	return tv.tv_sec * 1000 + tv.tv_usec/1000;
}
time_t      YCommonTool::get_Timesec() {
	struct timeval  tv;
	gettimeofday(&tv, 0);
	return tv.tv_sec ;
}

time_t    YCommonTool::get_Startpmsec() {
    time_t start_msec = 0;
#ifndef __APPLE__
    struct sysinfo info;
    sysinfo(&info);
    struct timeval  tv;
    gettimeofday(&tv, 0);
    start_msec = info.uptime * 1000 + tv.tv_usec/1000;
#else //APPLE_HERE
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 ) {
        return -1.0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);
    time_t diff_time_val = difftime(csec, bsec);
    struct timeval  tv;
    gettimeofday(&tv, 0);
    start_msec = diff_time_val * 1000 + tv.tv_usec/1000;
#endif
    return start_msec;
}

time_t   YCommonTool::get_Startsec() {
    time_t start_sec = 0;
#ifndef __APPLE__
    struct sysinfo info;
    sysinfo(&info);
    start_sec = info.uptime ;
#else
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 ) {
        return -1.0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);
    start_sec = difftime(csec, bsec);
#endif
	return start_sec;
}


void  YCommonTool::get_randStr(char * buffer,int maxlen) {
	int len = maxlen - 1 ;
	for(int i = 0 ; i < len ; i++) {
		*(buffer + i) = rand()%26 + 'A' ;
	}
	*(buffer + len) = '\0';
}

///获取网卡信息
int       YCommonTool::get_Nicinfo(std::list<std::string> & niclst)  {
#ifndef __APPLE__
	 struct ifreq ifr;
	 struct ifconf ifc;
	 char buf[2048];
	 int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	 if (sock == -1) {
	     return -1;
	 }

	 ifc.ifc_len = sizeof(buf);
	 ifc.ifc_buf = buf;
	 if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		close(sock);
	    return -1;
	 }

	 struct ifreq* it = ifc.ifc_req;
	 const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	 for (; it != end; ++it) {
	     strcpy(ifr.ifr_name, it->ifr_name);
	     if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
	        if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
	            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
	            	std::string name = ifr.ifr_name;
	            	niclst.push_back(name);
	             }
	         }
	    }else{
	    	close(sock);
	        return -1;
	    }
	 }
	 close(sock);
#else
     struct ifaddrs *ifap, *ifaptr;
     if (getifaddrs(&ifap) != 0) {
         return -1;
     }
     for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
         if (((ifaptr)->ifa_addr)->sa_family == AF_LINK && !(ifaptr->ifa_flags & IFF_LOOPBACK)) {
             niclst.push_back(ifaptr->ifa_name);
         }
     }
     freeifaddrs(ifap);
#endif

	 return niclst.size();
}
///获取IP信息
std::string      YCommonTool::get_ip(std::string & nicname) {
    char ip_buufer[64] = "";
	int inet_sock;
	struct ifreq ifr;
	inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr,0,sizeof(struct ifreq));
	strcpy(ifr.ifr_name, nicname.c_str());
	if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0)
	{
		close(inet_sock);
	    return "";
	}
	struct sockaddr_in * pAddr = (struct sockaddr_in *)(&ifr.ifr_addr);
	char * p = inet_ntoa((struct in_addr)pAddr->sin_addr);
	strcpy(ip_buufer,p);
	close(inet_sock);

	return ip_buufer;
}
#ifdef __APPLE__
namespace YCommonTool {
    bool get_mac_addr_by_ifname(const char *ifname, char *mac_buffer) {
        struct ifaddrs *ifap, *ifaptr;
        unsigned char *ptr;
        if (getifaddrs(&ifap) == 0) {
            for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
                if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
                    ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
                    sprintf(mac_buffer, "%02x%02x%02x%02x%02x%02x",
                            *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
                    break;
                }
            }
            freeifaddrs(ifap);
            return ifaptr != NULL;
        } 
        return false;
    }

};

#endif


///获取MAC信息
std::string      YCommonTool::get_mac(std::string & nicname) {
    char mac_buffer[64] = "";
#ifndef __APPLE__
	 int sockfd;
	 struct ifreq tmp;

	 sockfd = socket(AF_INET, SOCK_STREAM, 0);
	 if( sockfd < 0) {
	     return "";
	 }

	 memset(&tmp,0,sizeof(struct ifreq));
	 strncpy(tmp.ifr_name,nicname.c_str(),nicname.length() > 15 ? 15 : nicname.length());
	 if( (ioctl(sockfd,SIOCGIFHWADDR,&tmp)) < 0 ) {
		 close(sockfd);
		 return "";
	 }

	 sprintf(mac_buffer, "%02x%02x%02x%02x%02x%02x",
	        (unsigned char)tmp.ifr_hwaddr.sa_data[0],
	        (unsigned char)tmp.ifr_hwaddr.sa_data[1],
	        (unsigned char)tmp.ifr_hwaddr.sa_data[2],
	        (unsigned char)tmp.ifr_hwaddr.sa_data[3],
	        (unsigned char)tmp.ifr_hwaddr.sa_data[4],
	        (unsigned char)tmp.ifr_hwaddr.sa_data[5]
	      );

	 close(sockfd);

#else //APPLE_HERE
     (void)YCommonTool::get_mac_addr_by_ifname(nicname.c_str(), mac_buffer);
#endif
	 return  mac_buffer ;
}


// 以下为获取当前活跃用户信息 接口函数
static const char * session_path = "/run/systemd/sessions/";

enum record_entry { _UID, _USER, _STATE, _SEAT, _REMOTE,
		    _CLASS, _DESKTOP, _DISPLAY, _RECORDS };

static const char *record_title[_RECORDS] = {"UID", "USER", "STATE", "SEAT", "REMOTE",
					     "CLASS", "DESKTOP", "DISPLAY"};

static void remove_space(char *str) {
    char *s1 = str;
    for(int i = 0; str[i] != '\0'; i++) {
	if(!isspace(str[i]))
	    *s1++ = str[i];
    }
    *s1 = '\0';
}

static int read_profile_value(const char * file_path, const char *key, char **value) {
    FILE * fp;
    char row[256];
    fp = fopen(file_path,"r");
    if(fp == NULL)
	return fprintf(stderr,"[fopen] %s -> %s\n",file_path,strerror(errno));
    if(*value != NULL) {
	free(*value);
	*value = NULL;
    }
    memset(row,0,256);
    while(fgets(row,256,fp)) {
	remove_space(row);
	if(row[0] == '#' || row[0] == '\0') continue;
	if(!strncmp(row, key, strlen(key))) {
	    *value = strdup(row + strlen(key) + 1);
	    fclose(fp);
	    return 0;
	}
    }
    fclose(fp);
    return -1;
}
// 获取当前活跃用户
int YCommonTool::get_active_user_info_systemd(std::vector<active_user_info_t> &active_user_list) {
    DIR *dir;
    struct dirent * ent;
    char file_path[512];
    char *record_value[_RECORDS] = {NULL};
    dir = opendir(session_path);
    if( dir == NULL) {
        printf("[opendir] %s -> %s",session_path, strerror(errno));
        return -1;
    }
    while((ent = readdir(dir)) != NULL) {
	if(ent->d_type & DT_REG) {
	    memset(file_path, 0 , 512);
	    snprintf(file_path, 512, "%s%s",session_path ,ent->d_name);
	    read_profile_value(file_path, record_title[_DISPLAY], &record_value[_DISPLAY]);
	    read_profile_value(file_path, record_title[_STATE], &record_value[_STATE]);
	    read_profile_value(file_path, record_title[_CLASS], &record_value[_CLASS]);
	    if( (record_value[_DISPLAY] != NULL) && (0 == strcmp(record_value[_CLASS],"user")) &&
		(0 == strcmp(record_value[_STATE], "active"))) {
		for(int i = 0; i < _RECORDS ; i++) {
		    read_profile_value(file_path, record_title[i], &record_value[i]);
		}
		active_user_info_t active_user;
		int uid = atoi(record_value[_UID]);
		struct passwd * pw = getpwuid(uid);
		active_user.user_name = record_value[_USER];
		active_user.display_no = record_value[_DISPLAY];
		active_user.home_dir = pw->pw_dir;
		active_user.is_local = atoi(record_value[_REMOTE]) == 0 ? 1 : 0;
		active_user.uid = uid;
		active_user_list.push_back(active_user);
	    }
	    for(int i = 0; i < _RECORDS ; i++) {
		if( record_value[i] ) {
		    free(record_value[i]);
		    record_value[i] = NULL;
		}
	    }
	}
    }
    closedir(dir);
    return active_user_list.size();
}



std::string      YCommonTool::get_subMask(std::string & nicname) {
	struct ifreq ifreq;

	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(0 > fd) {
	   return "" ;
	}

	memset(&ifreq,0,sizeof(struct ifreq));
	strncpy(ifreq.ifr_name,nicname.c_str(),nicname.length() > 15 ? 15 : nicname.length());

	if(0 > ioctl(fd,SIOCGIFNETMASK,&ifreq)) {
		close(fd);
		return "" ;
	}
	struct sockaddr_in addr ;
	memcpy(&addr,&ifreq.ifr_addr,sizeof(struct sockaddr_in));
	char * p = inet_ntoa(addr.sin_addr);
	close(fd);
	return p ;
}

#ifndef __APPLE__
static int readNlSock(
    int sockFd,
    char* bufPtr,
    int seqNum,
    int pId )
{
    struct nlmsghdr* nlHdr = NULL;
    int readLen = 0, msgLen = 0;

    while (true) {
        if ( (readLen = recv(sockFd, bufPtr, BUFSIZ - msgLen, 0)) < 0 ) {
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        if ( (NLMSG_OK(nlHdr, (unsigned int)readLen) == 0)
                || (nlHdr->nlmsg_type == NLMSG_ERROR) ) {
            return -1;
        }

        if ( nlHdr->nlmsg_type == NLMSG_DONE ) {
            break;
        } else {
            bufPtr += readLen;
            msgLen += readLen;
        }

        if ( (nlHdr->nlmsg_flags & NLM_F_MULTI) == 0 ) {
            break;
        }

        if ( (nlHdr->nlmsg_seq != (unsigned int)seqNum)
                || (nlHdr->nlmsg_pid != (unsigned int)pId) ) {
            break;
        }
    }
    return msgLen;
}

static int parseRoutes(const char * pNic ,struct nlmsghdr *nlHdr, char* default_gateway) {
    int rtLen = 0;
    struct in_addr dst;
    struct in_addr gate;
    struct rtmsg* rtMsg = NULL;
    struct rtattr* rtAttr = NULL;

    rtMsg = (struct rtmsg*)NLMSG_DATA(nlHdr);
    if ( (rtMsg->rtm_family != AF_INET)
            || (rtMsg->rtm_table != RT_TABLE_MAIN) ) {
        return -1;
    }

    u_int gateWay = 0;
    u_int srcAddr = 0;
    u_int dstAddr = 0;

    rtAttr = (struct rtattr*)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    char nic[16];
    strcpy(nic,pNic);
    for ( ; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen) )  {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int*)RTA_DATA(rtAttr),nic);
            break;
        case RTA_GATEWAY:
        	gateWay = *(u_int*)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
        	srcAddr = *(u_int*)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
        	dstAddr = *(u_int*)RTA_DATA(rtAttr);
            break;
        }
    }

    dst.s_addr = dstAddr;
    if (strstr((char*)inet_ntoa(dst), "0.0.0.0")) {
        gate.s_addr = gateWay;
        strcpy(default_gateway, (char*)inet_ntoa(gate));
    }
    return 0;
}

#endif

std::string    YCommonTool::get_gatWay(std::string & nicname) {
    char gateway[32]="";
#ifndef __APPLE__
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;
	char msgBuf[BUFSIZ]="";

	struct ifreq ifr;
	int socked, len, msgSeq = 0;
	if(0 > (socked = socket(PF_NETLINK,SOCK_DGRAM,NETLINK_ROUTE))) {
	     return "";
	}

	///绑定网卡
	if(nicname.length()) {
		memset(&ifr, 0x00, sizeof(ifr));
		len = (nicname.length() > IFNAMSIZ ? IFNAMSIZ : nicname.length());
		strncpy(ifr.ifr_name, nicname.c_str(), len);
		if(setsockopt(socked, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) != 0) {
			close(socked);
			return "" ;
		}
	}

	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

	nlMsg->nlmsg_len  = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlMsg->nlmsg_type = RTM_GETROUTE;

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq = msgSeq++;
	nlMsg->nlmsg_pid = getpid();

	if(send(socked, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
		close(socked);
		return "";
	}

	 /* Read the response */
	if((len = readNlSock(socked, msgBuf, msgSeq, getpid())) < 0) {
		close(socked);
		return "";
	}

	for(; NLMSG_OK(nlMsg,(unsigned int)len); nlMsg = NLMSG_NEXT(nlMsg,len)) {
		parseRoutes(nicname.c_str(),nlMsg,gateway);
	}

	close(socked);
    
#else //APPLE_HERE
    /*fake*/
    sprintf(gateway, "%s", "0.0.0.0");
#endif
	return gateway ;
}

///分割
int        YCommonTool::split_new(const std::string & strsrc,
		              std::vector<std::string> & vtdest,
					  std::string  break_str) {
	 if( strsrc.empty() || break_str.empty() )
	       return  0 ;

	 int  deli_len = break_str.size();
	 long index = -1, last_search_position = 0;
	 while( (index=strsrc.find(break_str,
	                        last_search_position))!=-1 ) {
	        if(index != last_search_position)
	        	vtdest.push_back( strsrc.substr(last_search_position, index-
	                                    last_search_position) );
	        last_search_position = index + deli_len;
	 }
	 std::string last_one = strsrc.substr(last_search_position);
	 if(last_one.length()) {
		 vtdest.push_back(last_one);
	 }

	 return vtdest.size();
}

int   YCommonTool::is_UserLogin(const char * name) {
#ifndef __APPLE__
    struct utmp pointer;
    int    utmpfd;
    int    utmp_size = sizeof(pointer);

    if((utmpfd = open(UTMP_FILE, O_RDONLY)) == -1) {
        printf("is_UserLogin 打开 %s文件失败\n",UTMP_FILE);
        return -1 ;
    }
    while(read(utmpfd, &pointer, utmp_size) == utmp_size) {
        if(pointer.ut_type != USER_PROCESS)
            continue;
        if(strcmp(pointer.ut_name,name) == 0) {
            close(utmpfd);
            return 1 ;
        }
    }
    close(utmpfd); /*关闭utmp文件*/

#else //APPLE_HERE
    
#endif
	return 0;
}

void YCommonTool::get_loginUser(std::string & user) {
#ifndef __APPLE__
	char tty[10]="";
	for(int i = 0 ; i < 10 ; i++) {
		sprintf(tty,"tty%d",i);
		if(get_ttyloginUser(tty,user)) {
			return  ;
		}
	}
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
    if(get_ttyloginUser(":0", user)) {
		return;
	}
#endif
	char * pStr =  getlogin();
	if(pStr) {
		user = pStr ;
		return ;
	}
#else //APPLE_HERE not implementation here
    const char dev_console[] = "/dev/console";
    struct stat console_stat;
    memset(&console_stat, 0, sizeof(console_stat));
    if(!stat(dev_console, &console_stat)) {
        struct passwd *pwp = getpwuid(console_stat.st_uid);
        if(pwp != NULL) {
            user = pwp->pw_name;
            return;
        }
    }
#endif
	user = "root" ;
	return ;
}


int  YCommonTool::get_ttyloginUser(const char * ttyname , std::string & name) {
#ifndef __APPLE__
	struct utmp pointer;
	int    utmpfd;
	int    utmp_size = sizeof(pointer);

	if((utmpfd = open(UTMP_FILE, O_RDONLY)) == -1) {
		printf("is_UserLogin 打开 %s文件失败\n",UTMP_FILE);
		return -1 ;
	}

	while(read(utmpfd, &pointer, utmp_size) == utmp_size){
		if(pointer.ut_type != USER_PROCESS)
			continue ;
		if(strcmp(pointer.ut_line,ttyname) == 0) {
			name = pointer.ut_name ;
			close(utmpfd);
			return 1 ;
		}
	}
	close(utmpfd); /*关闭utmp文件*/
#else //APPLE_HERE

#endif
	return 0 ;
}

void  YCommonTool::get_local_time(char strtime[])
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep);
    sprintf(strtime, "%d-%02d-%02d %02d:%02d:%02d", (1900 + p->tm_year),
            (1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min,p->tm_sec);
}

bool YCommonTool::get_CurloginUser(std::string & user) {

	FILE * fp = popen("who am i","r");
	if(fp == NULL) {
		return false ;
	}
	char szGet[256] = "";
	fgets(szGet,255,fp);

	int len = strlen(szGet);
	for(int i = 0 ; i < len ; i++) {
		if(szGet[i] == ' ') {
			szGet[i] = '\0';
			break ;
		 }
	}
	pclose(fp);
	user = szGet ;
	return true ;
}

int YCommonTool::get_rpm_all(std::string & file) {
    int ret;
    //确保开机启动时rpm查询到的信息是中文的
    string rpmcmd = "export LANG=zh_CN.UTF-8;rpm -qa|xargs rpm -qi>";
    rpmcmd = rpmcmd + file;
    ret = system(rpmcmd.c_str());
    if(-1 == ret) {
        return 0;
    }
    return 1;
}

int  YCommonTool::startup_nic(std::string & nic) {
	const char * ethNum = nic.c_str();
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	strcpy(ifr.ifr_name, ethNum);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(sockfd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 1;
}

YCommonTool::en_netaddrtype  YCommonTool::check_addr_type() {
	/**
	 * 先获取所有网卡
	 */
	std::list<std::string> nicVt ;
	YCommonTool::get_Nicinfo(nicVt);

	std::string  strIp ;
	unsigned int ip_addr = 0 ;
	unsigned int  cnt,cnt1 ; ///cnt 内网个数，cnt1外网个数
	cnt = cnt1 = 0 ;
	std::list<std::string>::iterator iter = nicVt.begin();
	while(iter != nicVt.end()) {
		strIp = get_ip(*iter);
		ip_addr = ntohl(inet_addr(strIp.c_str()));
	   if ((ip_addr >= 0x0A000000 && ip_addr <= 0x0AFFFFFF ) ||
			(ip_addr >= 0xAC100000 && ip_addr <= 0xAC1FFFFF ) ||
			(ip_addr >= 0xC0A80000 && ip_addr <= 0xC0A8FFFF ))
		{
		    cnt++;
		} else {
			cnt1++ ;
		}
		iter++ ;
	}

	if(cnt == nicVt.size()) {
		return addr_only_internal ;
	}

	if(cnt1 == nicVt.size()) {
		return addr_only_internet ;
	}

	return  addr_mix ;
}

int  YCommonTool::closeup_nic(std::string & nic) {
	const char * ethNum = nic.c_str();
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	strcpy(ifr.ifr_name, ethNum);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(sockfd);
		return -1;
	}

	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 1;
}

char *  YCommonTool::strupr(char * sz) {
	int size = strlen(sz);
	for(int i = 0 ; i < size ; i++) {
		if(sz[i] >= 'a' && sz[i] <= 'z') {
			sz[i] = sz[i] - 32 ;
		}
	}
	return sz ;
}

// trim from start
std::string & YCommonTool::ltrim(std::string &s) {
#ifndef __APPLE__
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
#else //not readly apple just lamba c11
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int c) {return !std::isspace(c);}));
#endif
    return s;
}

// trim from end
std::string & YCommonTool::rtrim(std::string &s) {
#ifndef __APPLE__
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
#else
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int c){return !std::isspace(c);}).base(), s.end());
#endif

    return s;
}

// trim from both ends
std::string & YCommonTool::trim(std::string &s) {
    return ltrim(rtrim(s));
}

bool YCommonTool::startwith(std::string &s, std::string str) {
    return (s.find(str) == 0);
}

bool YCommonTool::endwith(std::string &s, std::string str) {
    return (s.rfind(str) == (s.length() - str.length()));
}


/*set time with offset*/
int YCommonTool::set_time(const std::string &time_str, int offset, time_t &outval) {
    int ret = 0;
    if(time_str.empty()) {
        return --ret;
    }
    /*server time format*/
    char format[] = "%Y-%m-%d %H:%M:%S";
    struct tm tm_val;
    time_t time_p;
    time(&time_p);
    struct tm *ptm = localtime(&time_p);
    if(ptm == NULL) {
        return --ret;
    }
    memset(&tm_val, 0, sizeof(tm_val));
    strptime(time_str.c_str(), format, &tm_val);

    time_t t_epoch = mktime(&tm_val);
    if(t_epoch == -1) {
        return --ret;
    }
    outval = t_epoch;
    time_t t_local_epoch = mktime(ptm);
    if(labs(t_local_epoch - t_epoch) <= labs(offset)) {
        return ret;
    }
#ifndef __APPLE__
    if(stime(&t_epoch) == -1) {
        return --ret;
    }
#else
    struct timeval time_sec;
    struct timezone c_time_zone;
    gettimeofday(&time_sec, &c_time_zone);
    time_sec.tv_sec = t_epoch;
    if(settimeofday(&time_sec, &c_time_zone) == -1) {
        return --ret;
    }
#endif

    /*ret > 0 and settime */
    return ++ret;
}


std::string YCommonTool::exec_cmd(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return "";
    }
    char buffer[1024];
    std::string ret = "";
    while(!feof(fp)) {
        if(fgets(buffer, 1024, fp) != NULL)
            ret += buffer;
    }
    pclose(fp);
    return ret;
}



#define red   "\033[1;31m"        /*  0 -> normal ;  31 -> red */
#define cyan  "\033[0;36m"        /*  1 -> bold ;  36 -> cyan */
#define green "\033[0;32m"        /*  4 -> underline ;  32 -> green */
#define blue  "\033[1;34m"        /*  9 -> strike ;  34 -> blue */

#define black  "\033[0;30m"
#define brown  "\033[0;33m"
#define magenta  "\033[1;35m"
#define gray  "\033[0;37m"

#define none   "\033[0m"        /*  to flush the previous property */ 

void YCommonTool::logWarn(int line, const char *func, const char *fmt, ...) {
    if(fmt == NULL)
        return;
    char str[4096] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(str, sizeof(str) - 1, fmt, args);
    va_end(args);
    printf("%s%s: %s (LINE:%d) %s%s\n", blue, "[WARN]", func, line, none, str);
}

void YCommonTool::logErr(int line, const char *func, const char *fmt, ...) {
    if(fmt == NULL)
        return;
    char str[4096] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(str, sizeof(str) - 1, fmt, args);
    va_end(args);
    printf("%s%s: %s (LINE:%d) %s%s\n", red, "[ERR]", func, line, none, str);
}

void YCommonTool::logInfo(int line, const char *func, const char *fmt, ...) {
    if(fmt == NULL)
        return;
    char str[4096] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(str, sizeof(str) - 1, fmt, args);
    va_end(args);
    printf("%s%s: %s (LINE:%d) %s%s\n", green, "[INFO]", func, line,  none, str);
}

void YCommonTool::logDebug(int line, const char *func, const char *fmt, ...) {
    if(fmt == NULL)
        return;
    char str[4096] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(str, sizeof(str) - 1, fmt, args);
    va_end(args);
    printf("%s%s: %s (LINE:%d) %s%s\n", cyan, "[DEBUG]", func, line,  none, str);
}
void YCommonTool::logDebugImp(int line, const char *func, const char *fmt, ...) {
    if(fmt == NULL)
        return;
    char str[4096] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(str, sizeof(str) - 1, fmt, args);
    va_end(args);
    printf("%s%s: %s (LINE:%d) %s%s\n", magenta, "[DEBUG]", func, line,  none, str);
}

