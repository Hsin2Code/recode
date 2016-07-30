#include "net_bd_chk.h"
#include <iconv.h>
#define ICMP_HEADER_LEN 8
#define TIMEOUT 1000  /* Time of waiting for packets with last set TTL in miliseconds (= 1 second) */
#define TTL_LIMIT 30
#define REQUESTS_PER_TTL 3
#define BUFFER_SIZE 256

#define ERROR(str) { fprintf(stderr, "%s: %s\n", str, strerror(errno)); return -1; }


static CNetBdChk * g_ctrl = NULL;
static int old_crc_value;
static bool close_net = false;
static map< int, set<string> > ip_list;
static map< string, string > detection_list; //ip,key
static map< string, string > intranet_list;  //ip,ip
static map< string, string > router_list;    //ip,ip
static map< string, string > proxy_list;     //ip,port

int execshell(const char *cmd,vector<string> &resvec) {
    resvec.clear();
    FILE * fp = popen(cmd, "r");
    if(!fp) {
	ERROR("[execshell] ");
    }
    char tmp[1024];
    while(fgets(tmp, sizeof(tmp), fp) != NULL) {
	while(tmp[strlen(tmp) - 1] == '\n' || tmp[strlen(tmp) - 1] == ' ') {
	    tmp[strlen(tmp) - 1] = '\0';
	}
	resvec.push_back(tmp);
    }
    pclose(fp);
    return 0;
}
vector<string> split(string str,string pattern) {
    string::size_type pos;
    vector<string> result;
    str += pattern;//扩展字符串以方便操作
    int size = str.size();

    for(int i = 0; i < size; i++) {
	pos = str.find(pattern,i);
	if(pos < size) {
	    string s = str.substr(i,pos-i);
	    if(s.size() == 0) continue;
	    result.push_back(s);
	    i = pos+pattern.size()-1;
	}
    }
    return result;
}

int audit_report(const char *context,const char *router,int kind,int type) {
    vector<string> resvec;
    if(execshell("who | grep :0 | awk -F ' ' '{print $1}' ", resvec) < 0) {
	ERROR("[get_proxy_ip]");
    }
    string username = resvec.begin()->c_str();

    char szTime[21] = {0};
    YCommonTool::get_local_time(szTime);
    char buffer[2048]={0};
    tag_Policylog *plog = (tag_Policylog *)buffer;
    plog->type = AGENT_RPTAUDITLOG;
    plog->what = AUDITLOG_REQUEST;
    char *tmp = plog->log;
    string list = "";
    string last = "";
    char traceroute[BUFFER_SIZE];
    if(type == 1) {
	map<int ,set<string> >::iterator it;
	for(it = ip_list.begin() ;it != ip_list.end(); it++) {
	    set<string>::iterator _it;
	    for(_it = it->second.begin(); _it != it->second.end(); _it++) {
		if(last == *_it || _it->empty()) continue;
		sprintf(traceroute,"%s;" ,_it->c_str());
		list.append(traceroute);
	    }
	    last = *(it->second.begin());
	}
    }else {
	list = router;
    }
    sprintf(tmp,"Body0=time=%s<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=%s IP=%s<>RouteAddress=%s<>way=%d%s%s%s"
	    ,szTime
	    ,kind
	    ,g_ctrl->get_id()
	    ,g_ctrl->get_name().c_str()
	    ,username.c_str()
	    ,context
	    ,list.c_str()
	    ,router
	    ,type
	    ,STRITEM_TAG_END
	    ,"BodyCount=1"
	    ,STRITEM_TAG_END);

    /* --------上报日志---------- */
    report_policy_log(plog);

    /* --------记录到本地-------- */
    if(-1 == access(NET_BD_CHK_INFO_PATH, F_OK)) {
	creat(NET_BD_CHK_INFO_PATH, O_RDWR);
    }	
    FILE *fp = NULL;
    if(NULL != (fp =fopen(NET_BD_CHK_INFO_PATH,"a+"))) {
	fwrite(tmp,strlen(tmp),1,fp);
	fclose(fp);
    }
    return 0;
}
int illegal_disposal(const char *contest,const char *router,int kind,int type) {
    if(g_ctrl->Prompt == 0) {
	char buffer[512] = "";
	struct tag_GuiTips * pTips = (struct tag_GuiTips *)buffer;
	pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
	pTips->defaultret = en_TipsGUI_None ;
	pTips->pfunc = NULL;
	sprintf(pTips->szTitle,"提示");
	char outbuffer[BUFFER_SIZE]="";
	int outlen = BUFFER_SIZE;
	code_convert("gb2312","utf-8",const_cast<char *>(g_ctrl->PromptInfo.c_str()),g_ctrl->PromptInfo.length(), outbuffer, outlen);
	sprintf(pTips->szTips,"%s",outbuffer);
	printf("打印提示信息->%s\n",outbuffer);
	g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
    }else if(g_ctrl->Prompt == 1) {
	char buffer[512] = "";
	tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
	pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut ;
	pTips->defaultret = en_TipsGUI_None ;
	pTips->pfunc = NULL;
	sprintf(pTips->szTitle,"提示");
	char outbuffer[BUFFER_SIZE]="";
	int outlen = BUFFER_SIZE;
	code_convert("gb2312","utf-8",const_cast<char *>(g_ctrl->PromptInfo1.c_str()),g_ctrl->PromptInfo1.length(), outbuffer, outlen);
	sprintf(pTips->szTips,"%s",outbuffer);
	printf("打印提示信息->%s\n",outbuffer);
	g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
	tag_closeNet  tmp ;
	tmp.policy = NET_BD_CHK;
	tmp.bAlaways = false ;
	printf("断开网络\n");
	g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET,&tmp,sizeof(tmp));
	close_net = true;
    }else {
	printf("nothing.........\n");
    }
    //审计上报
    if(g_ctrl->AuditProxyServer) {
	printf("审计上报->contest:%s->router:%s->kind:%d->type:%d\n",contest,router,kind,type);
	audit_report(contest, router,kind, type);
    }
    return 0;
}

/* Returns the difference between two times in miliseconds. struct timeval member tv_sec holds the number of
   seconds (1 s = 1000 ms) and member tv_usec holds the number of microseconds (1 us = 1/1000 ms) */
double timeDifference(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec)*1000.0 + (end.tv_usec - start.tv_usec)/1000.0;
}

uint16_t in_cksum(uint16_t *addr, int len, int csum) {
    int sum = csum;
    while(len > 1)  {
        sum += *addr++;
        len -= 2;
    }
    if(len == 1) sum += htons(*(uint8_t *)addr << 8);
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    return ~sum; /* truncate to 16 bits */
}

int get_ip_list(const char* ip) {

    struct sockaddr_in remoteAddr;
    bzero(&remoteAddr, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    if(inet_pton(AF_INET, ip, &remoteAddr.sin_addr) <= 0)
	ERROR("[inet_pton] ");    

    int pid = getpid();    
    int sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockId < 0) ERROR("[socket] ");
    
    struct timeval begin, current;
    begin.tv_sec = 0;
    begin.tv_usec = 1000;  // (= 1 ms)
    if(setsockopt(sockId, SOL_SOCKET, SO_RCVTIMEO, &begin, sizeof(begin)) < 0) {
	close(sockId);
	ERROR("[setspckopt] ");
    }
    
    char icmpRequestBuffer[BUFFER_SIZE], replyBuffer[BUFFER_SIZE];  // place in memory for our ICMP requests and received IP packets

    struct icmp *icmpRequest = (struct icmp *) icmpRequestBuffer;
    icmpRequest->icmp_type = ICMP_ECHO;
    icmpRequest->icmp_code = htons(0);  // htons(x) returns the value of x in TCP/IP network byte order
    icmpRequest->icmp_id = htons(pid);    
    
    int ttl, sequence = 0, repliedPacketsCnt, i;
    bool stop = 0;  // set to true, when echo reply has been received
    double elapsedTime;  // variable used to compute the average time of responses
    struct timeval sendTime[REQUESTS_PER_TTL];  // send time of a specific packet
    
    for(ttl=1; ttl<=TTL_LIMIT; ttl++) {
	repliedPacketsCnt = 0;
	elapsedTime = 0.0;

	for(i=1; i<=REQUESTS_PER_TTL; i++) {
	    if(setsockopt(sockId, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		close(sockId);
		ERROR("[setsockopt] ");
	    }
	    icmpRequest->icmp_seq = htons(++sequence);
	    icmpRequest->icmp_cksum = 0;
	    icmpRequest->icmp_cksum = in_cksum((uint16_t*) icmpRequest, ICMP_HEADER_LEN, 0);

	    gettimeofday(&sendTime[(sequence-1) % REQUESTS_PER_TTL], NULL);
	    if( ICMP_HEADER_LEN != sendto(sockId, icmpRequestBuffer, ICMP_HEADER_LEN,
					  0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr))) {
		close(sockId);
		ERROR("[send] ");
	    }
	}
	gettimeofday(&begin, NULL);  // get time after sending the packets
	while(repliedPacketsCnt < REQUESTS_PER_TTL) {
	    
	    int RecvRetVal = recvfrom(sockId, replyBuffer, BUFFER_SIZE, 0, 0, 0);
	    if(RecvRetVal < 0 && errno != EAGAIN) {
		close(sockId);
		ERROR ("[recvfrom] ");
	    }
	    gettimeofday(&current, NULL);
	    
	    if(RecvRetVal < 0) {
		if(timeDifference(begin, current) > TIMEOUT) break;
		continue;
	    }
	    
	    struct ip *reply = (struct ip *) replyBuffer;
		
	    if(reply->ip_p != IPPROTO_ICMP) continue;  // Check packet's protocol (if it's ICMP)
		
	    struct icmp *icmpHeader = (struct icmp *) (replyBuffer + reply->ip_hl*4);  // we "extract" the ICMP header from the IP packet
			
	    if(icmpHeader->icmp_type != ICMP_ECHOREPLY && 
	       !(icmpHeader->icmp_type == ICMP_TIME_EXCEEDED && icmpHeader->icmp_code == ICMP_EXC_TTL)) continue;
		
	    if(icmpHeader->icmp_type == ICMP_TIME_EXCEEDED)
		icmpHeader = (struct icmp *) (icmpHeader->icmp_data + ((struct ip *) (icmpHeader->icmp_data))->ip_hl*4);
		
	    if(ntohs(icmpHeader->icmp_id) != pid || sequence - ntohs(icmpHeader->icmp_seq) >= REQUESTS_PER_TTL) continue;
		
	    elapsedTime += timeDifference(sendTime[(ntohs(icmpHeader->icmp_seq)-1) % REQUESTS_PER_TTL], current);

	    ip_list[ttl].insert(inet_ntoa(reply->ip_src));
	    repliedPacketsCnt++;
	    inet_ntoa(reply->ip_src);
	    if(icmpHeader->icmp_type == ICMP_ECHOREPLY) stop = 1;
	}
	if(repliedPacketsCnt == REQUESTS_PER_TTL) {
	    //printf("TTL=%2d -- delay=%.2f ms\n",ttl,elapsedTime/repliedPacketsCnt);
	}
	else{
	    //printf("\t???\n");
	}
	if(stop == 1) break;
    }
    close(sockId);
    return 0;
}
bool check_str_in_list(string ip,map<string,string> list) {
    uint64_t ip_num = htonl(inet_addr(ip.c_str()));
    map<string,string>::iterator it;
    for(it = list.begin(); it != list.end(); it++) {
	uint64_t ip_begin = htonl(inet_addr(it->first.c_str()));
	uint64_t ip_end = htonl(inet_addr(it->second.c_str()));
	if(ip_begin <= ip_num && ip_num <= ip_end) {
	    return true;
	} 
    }
    return false;
}
int check_ip_list(void) {
    map<int ,set<string> >::iterator it;
    string last = "127.0.0.1";
    for(it = ip_list.begin() ;it != ip_list.end(); it++) {
	set<string>::iterator _it;
	for(_it = it->second.begin(); _it != it->second.end(); _it++) {
	    //监测是否在内网中
	    if( false == check_str_in_list(_it->c_str(), intranet_list)) {
		//检查是否在路由列表中
		if( false == check_str_in_list(last.c_str(), router_list)) {
		    illegal_disposal("发现违规路由IP列表",last.c_str(), 3201, 1);
		    return 1;
		}else {
		    printf("使用合法路由 IP=%s\n",last.c_str());
		    return 0;
		}
	    }
	}
	last = *(it->second.begin());
    }
    return 0;
}
string host_to_ip(const char *name){
    sockaddr_in addr;
    struct hostent *host;
    string ip;
    if(inet_aton(name, &addr.sin_addr) !=0 ) {
	ip = name;
    }else {
	host = gethostbyname(name);
	if(host != NULL) {
	    ip = inet_ntoa(*((struct in_addr *)host->h_addr));
	}else {
	    return "";
	}
    }
    return ip;
}
int get_proxy_value(FILE *fp,char *key,char *value) {
    char tmp[1024];
    fseek(fp, SEEK_SET, 0);
    while(fgets(tmp, sizeof(tmp), fp) != NULL) {
	if(NULL != strstr(tmp,key)) {
	    char *pos = strstr(tmp, ", ");
	    pos += 2; char *tmp = pos;
	    while(*tmp++ != ')');
	    *--tmp = '\0';
	    if(*pos == '"') {
		pos++;
		*--tmp = '\0';
	    }
	    strcpy(value, pos);
	    return 0;
	}
    }
    return -1;
}
int check_ip_connect(const char *ip,const uint16_t port) {
    struct sockaddr_in remoteAddr;
    bzero(&remoteAddr, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    if(inet_pton(AF_INET, ip, &remoteAddr.sin_addr) <= 0)
	ERROR("[inet_pton] ");
    remoteAddr.sin_port = htons(port);
    
    int socket_id = socket(AF_INET, SOCK_STREAM, 0);    
    struct timeval current;
    current.tv_sec = 3;
    current.tv_usec = 0;  // (= 1 ms)
    if( setsockopt(socket_id, SOL_SOCKET, SO_SNDTIMEO, &current, sizeof(current)) < 0) {
	close(socket_id);
	ERROR("[setspckopt] ");
    }
    if( connect(socket_id,(struct sockaddr*)&remoteAddr, sizeof(struct sockaddr_in)) != 0) {
	fprintf(stderr, "%s: %s\n", "无法连接原因", strerror(errno));
	printf("ip:%s,port:%u 无法连通\n",ip,port);
	close(socket_id);
	return false;
    }else {
	shutdown(socket_id, SHUT_RDWR);
	printf("ip:%s,port:%u 可以连通\n",ip,port);
	close(socket_id);
	return true;
    }
}
int check_proxy_flie(FILE *fp,const char *type) {
    char host[BUFFER_SIZE] = {0};
    char port[BUFFER_SIZE] = {0};
    char host_key[BUFFER_SIZE] = {0};
    char port_key[BUFFER_SIZE] = {0};
    char context[BUFFER_SIZE] = {0};
    char proxy_addr[BUFFER_SIZE] = {0};
    sprintf(host_key, "network.proxy.%s", type);
    sprintf(port_key, "network.proxy.%s_port", type);
    if( get_proxy_value(fp, host_key, host) == 0 ) {
	if( get_proxy_value(fp, port_key, port) == 0 ) {
	    map<string,string>::iterator it = proxy_list.find(host);
	    if(it != proxy_list.end())
		if(it->second == port)
		    return 0;
	    string ip = host_to_ip(host);
	    printf("type:%s->ip:%s->port:%s\n",type,ip.c_str(),port);
	    if(check_ip_connect(ip.c_str(), atoi(port))) {
		sprintf(context, "违规使用%s代理", type);
		sprintf(proxy_addr, "%s:%s",host,port);
		illegal_disposal(context, proxy_addr, 3201, 2);
		printf("违规使用%s代理->ip:%s->port:%s\n",type,ip.c_str(),port);
		printf("%s--->Address = %s\n",context,proxy_addr);
		return 1;
	    }
	}
    }
    printf("合法使用%s代理->ip:%s->port->%s\n",type,host,port);
    return 0;
}
int check_proxy() {
    vector<string> resvec;
    if(execshell("who | grep :0 | awk -F ' ' '{print $1}' ", resvec) < 0) {
	ERROR("[get_proxy_ip]");
    }
    char str[BUFFER_SIZE] = {0};
    string username = resvec.begin()->c_str();
    sprintf(str,"cat /home/%s/.mozilla/firefox/profiles.ini | grep Path | awk -F '=' '{print $2}'",username.c_str());
    if(execshell(str, resvec) < 0) {
	ERROR("[get_proxy_ip]");
    }
    sprintf(str,"/home/%s/.mozilla/firefox/%s/prefs.js",username.c_str(),resvec.begin()->c_str());
    FILE *fp = fopen(str, "r");
    if(fp == NULL)
	return fprintf(stderr,"[fopen] %s",strerror(errno));
    if(get_proxy_value(fp, "network.proxy.type", str) < 0) {
	fclose(fp);
	ERROR("[get_value] [network.proxy.type] ");
    }
    if(atoi(str) != 1) {
	fclose(fp);
	return 0;
    }
    if( check_proxy_flie(fp, "ftp") == 0 ) {
	printf("使用合法ftp代理\n");
    }
    if( check_proxy_flie(fp, "http") == 0 ) {
	printf("使用合法http代理\n");
    }
    if( check_proxy_flie(fp, "ssl") == 0 ) {
	printf("使用合法ssl代理\n");
    }
    if( check_proxy_flie(fp, "socks") == 0 ) {
	printf("使用合法socks代理\n");
    }
    fclose(fp);
    return 0;
}
bool net_bd_chk_init() {
    close_net = false;
    ip_list.clear();
    old_crc_value = 0;
    return true;
}
bool net_bd_chk_worker(CPolicy * policy,void *param) {
    static int times;
    if(policy->get_type() != NET_BD_CHK) {
	return false;
    }
    vector<string> vec;
    vector<string>::iterator it;
    map<string,string>::iterator map_it;
    string  server_ip ;
    g_ctrl = (CNetBdChk*)policy;
    if( g_ctrl->RoutingProbe != 1 || close_net ) {
	return true;
    }

    if(old_crc_value != g_ctrl->get_crc()) {
	old_crc_value = g_ctrl->get_crc();

	times = 0;

	//探测列表
	detection_list.clear();
	
	string first, second;
	vec = split(g_ctrl->DetectionList, ";");
	for(it = vec.begin(); it != vec.end(); it++) {
	    first = host_to_ip(it->substr(0, it->find(':')).c_str());
	    second = it->substr(it->find(':')+1, it->size());
	    if(!first.empty()) {
		detection_list[first] = second;
	    }
	}

	//内网地址列表
	intranet_list.clear();
	
	vec = split(g_ctrl->SetAddress ,";");
	for(it = vec.begin(); it != vec.end(); it++) {
	    first = it->substr(0, it->find('-'));
	    second = it->substr(it->find('-')+1, it->size());
	    intranet_list[first] = second;
	}
	    
	//边界路由列表
	router_list.clear();
	
	vec = split(g_ctrl->OnlyAllowsList, ";");
	for(it = vec.begin(); it != vec.end(); it++) {
	    first = it->substr(0, it->find('-'));
	    second = it->substr(it->find('-')+1, it->size());
	    router_list[first] = second;
	}

	//代理白名单
	if(g_ctrl->proxycheck == 1) {
	    proxy_list.clear();
	    vec = split(g_ctrl->proxyOnlyAllowsList, ";");
	    for(it = vec.begin(); it != vec.end(); it++) {
		first = it->substr(0, it->find(':'));
		second = it->substr(it->find(':')+1, it->size());
		proxy_list[first] = second;
	    }
	}
	
	ip_list.clear();
    }

    g_GetlcfgInterface()->get_lconfig(lcfg_srvip,server_ip);
    if(!check_ip_connect(server_ip.c_str(),88)) {
	fprintf(stderr,"不在内网中，不进行探测\n");
	return true;
    }

    //周期探测
    int cycle = 20;
    if(g_ctrl->Detection_Cycle)
	cycle = g_ctrl->Detection_Cycle;

    if(times % cycle == 0) {
	
	if(detection_list.empty()) {
	    fprintf(stderr,"探测列表为空,无法探测路由\n");
	}else {
	    for( map_it = detection_list.begin();map_it != detection_list.end(); map_it++) {
		get_ip_list(map_it->first.c_str());
	    }
	    //边界检查
	    if(ip_list.empty()) {
		fprintf(stderr,"目标地址错误,无法对路由进行边界检查\n");
	    }else {
		check_ip_list();
	    }
	}

	//代理检查
	if(g_ctrl->proxycheck == 1) {
	    check_proxy();
	}
    }
    times ++;
    return true;
}
void net_bd_chk_uninit() {
    if(close_net) {
	///开启网络
	tag_openNet open ;
	open.policy = NET_BD_CHK;
	g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&open,sizeof(open));
	close_net = false ;
    }
    ip_list.clear();
    detection_list.clear();
    router_list.clear();
    intranet_list.clear();
    proxy_list.clear();
    old_crc_value = 0;
    return;
}
