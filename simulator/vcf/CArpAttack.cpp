/*
 * CArpAttack.cpp
 *
 *  Created on: 2015-3-12
 *      Author: sharp
 */

#include "CArpAttack.h"
#include "common/Commonfunc.h"
#include "VCFCmdDefine.h"
#include <string>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

extern ILocalCfginterface * g_GetlcfgInterface() ;

#pragma pack(push)
#pragma pack(1)


struct ARPPacket
{
    unsigned char dmac[6]; ///接收方MAC
	unsigned char smac[6]; ///发送方MAC
	short eth_type;        ///帧类型 0x0806 arp
	short hdr_type;        ///硬件类型 默认值0x1
	short pro_type;        ///上层协议类型0X0800 IP
	char  hdr_len;          ///MAC地址长度 6
    char  pro_len;          ///IP地址长度  4
	short op;              ///操作码 0x1表示ARP请求包,0x2表示应答包
	unsigned char s_mac[6];  ///发送方MAC
	unsigned int  s_ip;       ///发送方IP
	unsigned char d_mac[6];  ///接收方MAC
	unsigned int  d_ip;       ///接受方IP
};
#pragma pack(pop)

int inet_mton(const char *cp, u_char *ap)
{
    int colons = 0;
    quad_t acc = 0, addr = 0;

    do {
        register char cc = *cp;

        switch (cc) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            acc = acc * 16 + (cc - '0');
            break;

    case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            acc = acc * 16 + (cc - 'a' + 10);
            break;

    case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            acc = acc * 16 + (cc - 'A' + 10);
            break;

        case ':':
            if (++colons > 5) {
                return 0;
            }

        case '\0':
            if (acc > 0xFF) {
                return 0;
            }
            addr = addr << 8 | acc;
            acc = 0;
            break;

        default:
            return 0;
        }
    } while (*cp++) ;

    if (colons < 5) {
        addr <<= 8 * (5 - colons) ;
    }

    if (ap) {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0, j = 0;
    for(i=0,j=5; (i<6)&&(j>=0); i++,j--)
    {
        ap[i] = ((u_char *) &addr)[j];
    }
    #elif __BYTE_ORDER == __BIG_ENDIAN
    ap = (u_char *) &addr;
    #endif
    }

    return 1;
}

/**
 * 填充欺骗ARP， 将网关的MAC改为其他MAC
 */
void   fill_arppacket(unsigned char * pData,std::string & gateWay,///欺骗的目的IP
		std::string & dip,std::string & dmac,std::string & mymac) {
	ARPPacket * pArp = (ARPPacket *)pData;
	pArp->eth_type = htons(0x0806);
	pArp->hdr_type = htons(0x0001);
	pArp->pro_type = htons(0x0800);
	pArp->hdr_len = 0x06;
	pArp->pro_len = 0x04;
	pArp->op = htons(0x0002);

	inet_mton(dmac.c_str(),pArp->dmac);
	inet_mton(mymac.c_str(),pArp->smac);

	memset(pArp->s_mac,0xAA,sizeof(pArp->s_mac));
	pArp->s_ip = inet_addr(gateWay.c_str());
	memcpy(pArp->d_mac,pArp->dmac,sizeof(pArp->dmac));
	pArp->d_ip = inet_addr(dip.c_str());
}

//判断是否时有效的IP地址
static bool is_valid_ip(std::string ip) {
	int i=0;
	char delim='.';
	int dot_cnt = 0 ;
	int size = ip.length();

	char psub[4][5] = {"1","2","3","4"};
	int  index = 0 ;
	for( i=0;i<size;i++) {
		if(ip[i] != delim) {
			if(!isdigit(ip[i])) {
				return false ;
			}
			psub[dot_cnt][index++] = ip[i];
			if(index > 3) {
				return false ;
			}
		} else {
			char * psub1 =   (char *)psub[dot_cnt];
			if(atoi(psub1) > 255) {
				return false ;
			}
			dot_cnt++ ;
			index = 0 ;
		}
	}

	if(dot_cnt != 3) {
		return false ;
	}
	return true;
}

static int    splitIp(const char * pIp,std::vector<std::string> & _vt) {
	std::string src = pIp ;
	return YCommonTool::split_new(src,_vt,";");
}

///根据IP获取MAC
bool   arping_get_mac(std::string & eth, std::string & ip , std::string & mac) {
	char buffer[1024] = "";
	char buf[256] = "";
	char mac_sub[6][32] = {"","","","","",""};
	sprintf(buffer,"arping %s -I %s -c 1 | grep Unicast",ip.c_str(),eth.c_str());
	FILE * fp = popen(buffer,"r");
	if(fp == NULL) {
		return false ;
	}

	if(fgets(buf,255,fp)) {
		memset(mac_sub,0,sizeof(mac_sub));
		///Unicast reply from 192.168.131.1 [5C:DD:70:D7:7F:C8]  2.962ms
		sscanf(buf,"%s %s %s %s %s %s",mac_sub[0],mac_sub[1],mac_sub[2],mac_sub[3],mac_sub[4],mac_sub[5]);
		char * pMac = (char *)mac_sub[5];
		int len = strlen(pMac);
		if(len > 0) {
			*(pMac+len-1) = '\0';
			mac = pMac + 1 ;
		}
	} else {
		pclose(fp);
		return false ;
	}
	pclose(fp);
	return true ;
}

CArpAttack::CArpAttack() {
	m_fp = NULL ;
	m_trd = 0 ;
	m_brunning = false ;
	m_bUpdate = false ;
}

CArpAttack::~CArpAttack() {

}

void  CArpAttack::cancle_Attack(std::vector<std::string> & ipvt) {

}

void  CArpAttack::stop() {
	m_brunning = false ;
	if(m_trd) {
		void * status = NULL ;
		pthread_join(m_trd,&status);
		m_trd = 0 ;
	}

	if(m_fp) {
		pcap_close((pcap_t *)m_fp);
		m_fp = NULL ;
	}

}

bool  CArpAttack::init() {
	pcap_if_t *device = NULL;
	char errbuf[PCAP_ERRBUF_SIZE]= "";

	std::string  nic ;
	g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);
	///查找网卡
	if(-1 == pcap_findalldevs(&device,errbuf)) {
		return false ;
	}
	///没找到， 就没有执行的必要。
	if(device == NULL) {
		return false ;
	}
	///存放地址
	bpf_u_int32 netaddr = 0;
	///存放掩码
	bpf_u_int32	mask = 0;
	while(device) {
		if(pcap_lookupnet(device->name, &netaddr, &mask, errbuf) == -1) {
			device = device->next ;
			continue ;
		}

		///找到注册网卡
		if(device->name == nic) {
			m_fp = pcap_open_live(device->name,2048,4,0,errbuf);
			if(m_fp == NULL) {
				return false ;
			}
			break ;
		}
		device = device->next ;
	}
	pcap_freealldevs(device);

	return true ;
}

int  CArpAttack::attack_unreg_dev(const char * pIPs) {
	///获取网关
	std::string  nic , strvip;
	g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip,strvip);
	std::string  gatway = YCommonTool::get_gatWay(nic);

	std::vector<std::string> tmpvt;
	tmpvt.clear();
	splitIp(pIPs,tmpvt);

	///去掉网关
	std::vector<std::string>::iterator iter = tmpvt.begin();
	while(iter != tmpvt.end()) {
		if(*iter == gatway || *iter == strvip) {
			iter = tmpvt.erase(iter);
		} else
			iter++ ;
	}

	std::vector<std::string> add,del;
	if(m_ipvt.size() == 0) {
		YCommonTool::CLockHelper helper(&m_locker);
		m_ipvt = tmpvt ;
	} else {
		YCommonTool::CLockHelper helper(&m_locker);
		m_ipadd.clear();
		m_ipdel.clear();
		/**
		 * 找出取消的
		 */
		iter = m_ipvt.begin();
		while(iter != m_ipvt.end()) {
			bool exsit = false ;
			std::vector<std::string>::iterator iter1 = tmpvt.begin();
			while(iter1 != tmpvt.end()) {
				if(*iter1 == *iter) {
					exsit = true ;
					break ;
				}
				iter1++ ;
			}
			if(!exsit) {
				m_ipdel.push_back(*iter);
				m_ipvt.erase(iter);
			} else
				iter++ ;
		}

		/**
		 * 增加的
		 */
		iter = tmpvt.begin();
		while(iter != tmpvt.begin()) {
			bool exsit = false ;
			std::vector<std::string>::iterator iter1 = m_ipvt.begin();
			while(iter1 != m_ipvt.end()) {
				if(*iter1 == *iter) {
					exsit = true ;
					break ;
				}
				iter1++ ;
			}
			if(!exsit) {
				m_ipadd.push_back(*iter);
				m_ipvt.push_back(*iter);
			}
			iter++ ;
		}
	}
	m_bUpdate = true ;
	if(m_trd == 0) {
		m_brunning = true ;
		int ret = pthread_create(&m_trd,NULL,ArpAttack_work,this);
		if(ret) {
			return -1;
		}
	}
	return 0 ;
}

void     CArpAttack::getUpdateInfo(std::vector<std::string> & addd ,
		std::vector<std::string> & del) {
	YCommonTool::CLockHelper helper(&m_locker);
	addd = m_ipadd ;
	del  = m_ipdel ;
}


void     CArpAttack::attack(std::map<std::string,std::string> & _map) {
	unsigned char arpData[256] = {0};
	std::string nic ;
	g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);
	std::string  gatway = YCommonTool::get_gatWay(nic);
	std::string  mymac =  YCommonTool::get_mac(nic);
	std::string  ip;
	std::map<std::string,std::string>::iterator iter = _map.begin();
	while(iter != _map.end()) {
		if(!m_brunning) {
			break ;
		}
		ip = iter->first ;
		std::string & mac = iter->second;
		fill_arppacket(arpData,gatway,ip,mac,mymac);
		if(m_fp) {
			pcap_sendpacket((pcap_t *)m_fp,arpData,42);
		}
		usleep(10000);
		iter++ ;
	}
}

void     CArpAttack::update(std::map<std::string,std::string> & _map) {
	std::vector<std::string>  addVt,delVt;
	getUpdateInfo(addVt,delVt);
	std::string  nic ;
	g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);

	///删除取消的
	std::vector<std::string>::iterator iter = delVt.begin();
	while(iter != delVt.end())  {
		std::map<std::string,std::string>::iterator itermap = _map.find(*iter);
		if(itermap != _map.end()) {
			_map.erase(itermap);
		}
		iter++ ;
	}

	///增加新加入的
	std::string mac ;
	iter = addVt.begin();
	while(iter != addVt.end()) {
		if(arping_get_mac(nic,*iter,mac)) {
			_map[*iter] = mac ;
		}
		iter++ ;
	}
}

void   *  ArpAttack_work(void * parg) {
	CArpAttack * pAttack = (CArpAttack *)parg;
#define ATTACK_INTERVAL  30  ///10S攻击一次

    int lastTime =	0;
    std::map<std::string,std::string> m_macMap ;

	while(pAttack->m_brunning) {
		int curTime = YCommonTool::get_Timesec();
		if((curTime - lastTime) < ATTACK_INTERVAL) {
			usleep(100000);
			continue ;
		}
		lastTime = curTime ;
		if(pAttack->m_bUpdate) {
			pAttack->m_bUpdate = false ;
			pAttack->update(m_macMap);
		}
		pAttack->attack(m_macMap);
	}
	return NULL ;
}
