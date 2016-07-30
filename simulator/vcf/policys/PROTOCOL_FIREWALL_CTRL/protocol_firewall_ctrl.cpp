
#include "protocol_firewall_ctrl.h"

static int old_crc_value;

static int check_ip_connect(const char *ip,const uint16_t port) {
    struct sockaddr_in remoteAddr;
    bzero(&remoteAddr, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    if(inet_pton(AF_INET, ip, &remoteAddr.sin_addr) <= 0) {
	fprintf(stderr,"[inet_pton] : %s\n", strerror(errno));
	return false;
    }
    remoteAddr.sin_port = htons(port);
    
    int socket_id = socket(AF_INET, SOCK_STREAM, 0);    
    struct timeval current;
    current.tv_sec = 3;
    current.tv_usec = 0;  // (= 1 ms)
    if( setsockopt(socket_id, SOL_SOCKET, SO_SNDTIMEO, &current, sizeof(current)) < 0) {
	close(socket_id);
	fprintf(stderr,"[setsockopt] : %s\n", strerror(errno));
	return false;
    }
    if( connect(socket_id,(struct sockaddr*)&remoteAddr, sizeof(struct sockaddr_in)) != 0) {
	fprintf(stderr, "ip:%s,port:%u 无法连通 : %s\n", ip, port, strerror(errno));
	close(socket_id);
	return false;
    }else {
	shutdown(socket_id, SHUT_RDWR);
	fprintf(stdout, "ip:%s,port:%u 可以连通\n", ip, port);
	close(socket_id);
	return true;
    }
}
/* 端口管控扩展
 * type = 1 tcp端口，type = 2 udp端口。
 * io_flag = 1 本地端口，io_flag = 2 远程端口。
 * target = 1 DROP, target = 2 ACCEPT。
 * rev_flag = 0 正常逻辑, rev_flag = 1 去反,
 */
static int iptables_port(const char * protocol, const char *port, const char * target, unsigned int io_flag, unsigned int rev_flag) {
    char cmd[BUFFER_SIZE] = {0};
    char reverse[MARK_SIZE] = {0};
    if(rev_flag) {
	strcpy(reverse, "!");
    }
    int ret = 0;
    /* 本地端口管控 */
    if(io_flag == 1) {
	sprintf(cmd, "iptables -A %s -p %s %s --dport %s -j %s", CHAIN_CUSTOM_INPUT, protocol, reverse, port, target);
	ret = system(cmd);
	sprintf(cmd, "iptables -A %s -p %s %s --sport %s -j %s", CHAIN_CUSTOM_OUTPUT, protocol, reverse, port, target);
	ret = system(cmd);
    }
    /* 远程端口控制 */
    if(io_flag == 2) {
	sprintf(cmd, "iptables -A %s -p %s %s --sport %s -j %s", CHAIN_CUSTOM_INPUT, protocol, reverse, port, target);
	ret = system(cmd);
	sprintf(cmd, "iptables -A %s -p %s %s --dport %s -j %s", CHAIN_CUSTOM_OUTPUT, protocol, reverse, port, target);
	ret = system(cmd);
    }
    return 0;
}
/* 端口管控扩展
 * type = 0 全部，type = 1 tcp端口，type = 2 udp端口。
 * mark = 1 禁用填充项中指定端口，开放其它端口
 * mark = 2 禁用填充项中指定端口
 * mark = 3 开放填充项中指定端口，禁用其它端口
 * mark = 4 开放填充项中指定端口
 * io_flag = 3 双向，io_flag = 1 本地端口，io_flag = 2 远程端口。
 */
static int iptables_port_ex(const char *port,unsigned int type, unsigned int mark, unsigned int io_flag)
{
    /* 递归分解参数 */
    if(type == 0) {
	iptables_port_ex(port, 1, mark, io_flag);
	iptables_port_ex(port, 2, mark, io_flag);
	return 0;
    }
    /* 递归分解参数 */
    if(io_flag == 3) {
	iptables_port_ex(port, type, mark, 1);
	iptables_port_ex(port, type, mark, 2);
	return 0;
    }
    char protocol[MARK_SIZE] = {0};
    if(type == 1) {
	strcpy(protocol, "tcp");
    }else if(type == 2) {
	strcpy(protocol, "udp");
    }else { return 0;}
    
    switch(mark) {
    case 1:/* 禁用填充项中指定端口，开放其它端口 */
	iptables_port(protocol, port, "ACCEPT", io_flag, 1);
    case 2:/* 禁用填充项中指定端口 */
	iptables_port(protocol, port, "DROP", io_flag, 0);
	break;
    case 3:/* 开放填充项中指定端口，禁用其它端口 */
	iptables_port(protocol, port, "DROP", io_flag, 1);
    case 4:/* 开放填充项中指定端口 */
	iptables_port(protocol, port, "ACCEPT", io_flag, 0);
	break;
    default:
	break;
    }
    return 0;
}
/* 限制其他设备对本机的访问
 * mark = 0 , 只允许填充项中IP地址访问自己，禁止其余IP地址访问。
 * mark = 1 , 只禁止填充项中IP地址访问自己，允许其余IP地址访问。
 * mark = 2 , 禁止其他设备ping自己。
 */
static int iptables_input(const char * iprange, unsigned int mark )
{
    char cmd[BUFFER_SIZE] = {0};
    switch(mark) {
    case 0:
	sprintf(cmd, "iptables -A %s -m iprange ! --src-range %s -j DROP", CHAIN_CUSTOM_INPUT ,iprange);
	break;
    case 1:
	sprintf(cmd, "iptables -A %s -m iprange --src-range %s -j DROP", CHAIN_CUSTOM_INPUT ,iprange);
	break;
    case 2:
	sprintf(cmd, "iptables -A %s -p icmp --icmp-type Echo-Request -j DROP", CHAIN_CUSTOM_INPUT);
	break;
    default:
	return -1;
    }
    printf("%s\n",cmd);
    int ret = system(cmd);
    return 0;
}
/* 限制本机对其他设备的访问
 * mark = 0 , 只允许自己访问填充项中IP地址，禁止访问其余IP地址。
 * mark = 1 , 只禁止自己访问填充项中IP地址，允许访问其余IP地址。
 * mark = 2 ，进制自己ping其他设备。
 */
static int iptables_output(const char * iprange, unsigned int mark )
{
    char cmd[BUFFER_SIZE] = {0};
    switch(mark) {
    case 0:
	sprintf(cmd, "iptables -A %s -m iprange ! --dst-range  %s -j DROP", CHAIN_CUSTOM_OUTPUT, iprange);
	break;
    case 1:
	sprintf(cmd, "iptables -A %s -m iprange --dst-range %s -j DROP", CHAIN_CUSTOM_OUTPUT, iprange);
	break;
    case 2:
	sprintf(cmd, "iptables -A %s -p icmp --icmp-type Echo-Request -j DROP", CHAIN_CUSTOM_OUTPUT);
	break;
    default:
	return -1;
    }
    printf("%s\n",cmd);
    int ret = system(cmd);
    return 0;
}
static int iptables_init(unsigned int mark)
{
    char cmd[BUFFER_SIZE] = {0};
    int ret = 0;
    /* 添加用户自定义链 */
    if(mark & 1) {
	sprintf(cmd, "iptables -N %s", CHAIN_CUSTOM_INPUT);
	ret = system(cmd);
	sprintf(cmd, "iptables -N %s", CHAIN_CUSTOM_OUTPUT);
	ret = system(cmd);
    }
    /* 将其绑定到，INPUT OUTPUT链上，使其生效 */
    if(mark & 2) {
	sprintf(cmd, "iptables -A INPUT -j %s", CHAIN_CUSTOM_INPUT);
	ret = system(cmd);
	sprintf(cmd, "iptables -A OUTPUT -j %s", CHAIN_CUSTOM_OUTPUT);
	ret = system(cmd);
    }
    if(mark & 4) {
	string server_ip;
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip,server_ip);
	sprintf(cmd, "iptables -A %s -s %s -j ACCEPT", CHAIN_CUSTOM_INPUT ,server_ip.c_str());
	ret = system(cmd);
	sprintf(cmd, "iptables -A %s -d %s -j ACCEPT", CHAIN_CUSTOM_OUTPUT ,server_ip.c_str());
	ret = system(cmd);
    }
    return 0;
}
static int iptables_uninit(unsigned int mark)
{
    char cmd[BUFFER_SIZE] = {0};
    int ret = 0;
    /* 将用户自定义链解除绑定 */
    if(mark & 2) {
	sprintf(cmd, "iptables -D INPUT -j %s", CHAIN_CUSTOM_INPUT);
	ret = system(cmd);
	sprintf(cmd, "iptables -D OUTPUT -j %s", CHAIN_CUSTOM_OUTPUT);
	ret = system(cmd);
    }
    /* 清空用户自定义链 */
    if(mark & 4) {
	sprintf(cmd, "iptables -F %s", CHAIN_CUSTOM_INPUT);
	ret = system(cmd);
	sprintf(cmd, "iptables -F %s", CHAIN_CUSTOM_OUTPUT);
	ret = system(cmd);
    }
    /* 删除用户自定义链 */
    if(mark & 1) {
	sprintf(cmd, "iptables -X %s", CHAIN_CUSTOM_INPUT);
	ret = system(cmd);
	sprintf(cmd, "iptables -X %s", CHAIN_CUSTOM_OUTPUT);
	ret = system(cmd);
    }
    return 0;
}

void _log(const char *fmt, va_list ap)
{
    FILE * pf = fopen("/var/log/iptables_debug.log", "a+");
    if(NULL == pf) {
	printf("open log file failed...:%s.\n",strerror(errno));
	    
    }
    char buf[1024] = {0};
    vsnprintf(buf, sizeof(buf), fmt, ap);
    /* 获取系统时间 */
    time_t timep;
    time(&timep);
    /* 写入日志文件 */
    fprintf(pf, "Time\t: %s%s\n", ctime(&timep),buf);
    fclose(pf);
}

static void debug_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _log(fmt, ap);
    va_end(ap);
}

bool protocol_firewall_ctrl_init()
{
    /* 创建挂载表 */
    iptables_init( 1 | 2 );
    return true;
}

bool protocol_firewall_ctrl_worker(CPolicy *policy, void *param)
{
    static unsigned int old_mark;
    if(policy->get_type() != PROTOCOL_FIREWALL_CTRL) {
	return false;
    }
    CProtocolFirewallCtrl * ctrl = (CProtocolFirewallCtrl*)policy;
    /* 判断是否在内网中 */
    unsigned int net_mark = 0;
    unsigned int net_mode = 0;
    string server_ip;
    g_GetlcfgInterface()->get_lconfig(lcfg_srvip,server_ip);	
    net_mark |= 16;
    if(check_ip_connect(server_ip.c_str(), 88)) {
	net_mark |= 1; /* 内网中 */
    }else {
	net_mark |= 4; /* 离线 */
    }
    /* 策略CRC变更 */
    if(old_crc_value != ctrl->get_crc() || old_mark != net_mark) {
	/* 更新CRC值 */
	old_crc_value = ctrl->get_crc();
	debug_msg("old_mark = %u\t\t net_mark = %u\n", old_mark, net_mark);

	old_mark = net_mark;
	/* 清空表 */
	iptables_uninit(4);
	iptables_init(4);
	/* 不符合网络运行条件 */
	net_mode = ctrl->get_invalNetMod();
    if(net_mode == 0) net_mode = 21;
	debug_msg("old_mark = %u\t\t net_mark = %u net_mode = %u\n", old_mark, net_mark, net_mode);

    if((net_mode & net_mark) == 0) {
	    return 0;
	}
	debug_msg("old_mark = %u\t\t net_mark = %u net_mode = %u\n", old_mark, net_mark, net_mode);

	vector<struct control_data>::iterator it;
	net_mode = ctrl->get_invalNetMod();
	for(it = ctrl->ctrl_data.begin(); it != ctrl->ctrl_data.end(); it++ ) {
	    /* IP 管控*/
	    if( it->kind.compare("IP") == 0) {
		switch(it->mode) {
		case 1:
		    iptables_input(it->text.c_str(), 0); break;
		case 2:
		    iptables_output(it->text.c_str(), 0); break;
		case 3:
		    iptables_input(it->text.c_str(), 1); break;
		case 4:
		    iptables_output(it->text.c_str(), 1); break;
		default: break;
		}
	    }
	    /* ICMP 管控*/
	    if(it->kind.compare("ICMP") == 0) {
		switch(it->mode) {
		case 1:
		    iptables_input("", 2); break;
		case 2:
		    iptables_output("", 2); break;
		case 3:
		    iptables_input("", 2);
		    iptables_output("", 2);
		    break;
		default: break;
		}
	    }
	    /* 端口管控 */
	    if(it->kind.compare("TCP") == 0) {
		iptables_port_ex(it->text.c_str(), 1, it->mode, it->drct);
	    }
	    if(it->kind.compare("UDP") == 0) {
		iptables_port_ex(it->text.c_str(), 2, it->mode, it->drct);
	    }
	    if(it->kind.compare("ALL") == 0) {
		iptables_port_ex(it->text.c_str(), 0, it->mode, it->drct);
	    }
	    /* 超级IP */
	    //....
	    /* 超级端口 */
	    //....
	}
    }
    return true;
}
void protocol_firewall_ctrl_uninit()
{
    /* 卸载清空表 */
    iptables_uninit( 1 | 2 | 4);
    old_crc_value = 0;
    return;
}
