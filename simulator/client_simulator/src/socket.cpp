#include "socket.h"
#include "VrvProtocol.h"

CommonSocket::CommonSocket(int socket_type)
{
    this->_socket_type = socket_type;
    this->_opened = false;
    this->_binded = false;
    this->open();
}
int CommonSocket::socket_id(void) {
    if(this->_opened)
	return this->_socket_id;
    else {
	cerr << "[socket_id] Cannot open socket" << endl;
	return -1;
    }
}
int CommonSocket::open(void)
{
    if (!this->_opened) {
	if ((this->_socket_id = socket(AF_INET, this->_socket_type, 0)) == -1) {
	    cerr << "[open] Cannot create socket" << endl;
	    return errno;
	}
	this->_opened = true;
	this->_binded = false;
    }
    return 0;
}
int CommonSocket::close(void)
{
    if (this->_opened) {
	shutdown(this->_socket_id, SHUT_RDWR);
	this->_opened = false;
	this->_binded = false;
	return 0;
    }
    else {
	cerr << "[close] Cannot opened socket" << endl;
	return -1;
    }
}
TCP::TCP(void): CommonSocket(SOCK_STREAM) {
    this->_sockaddr_in.sin_family = AF_INET;
    inet_aton("192.168.133.144", &this->_sockaddr_in.sin_addr);
    this->_sockaddr_in.sin_port = htons(88);
}
TCP::TCP(string ip,uint16_t port): CommonSocket(SOCK_STREAM) {
    this->_sockaddr_in.sin_family = AF_INET;
    if (inet_aton(ip.c_str(), &this->_sockaddr_in.sin_addr) == 0) {
	inet_aton("0.0.0.0", &this->_sockaddr_in.sin_addr);
    }
    this->_sockaddr_in.sin_port = htons(port);
}
string TCP::ip(void) {
    return inet_ntoa(this->_sockaddr_in.sin_addr);
}
uint16_t TCP::port(void) {
    return ntohs(this->_sockaddr_in.sin_port);
}
uint32_t TCP::passwd() {
    if(!this->_binded) {
	cerr << "[passwd] No connection is established" << endl;
	this->_passwd = 0;
    }
    return this->_passwd;
}
struct sockaddr_in TCP::sockaddr_in(void) {
    return this->_sockaddr_in;
}
int TCP::connect(void) {
    if (this->_binded) {
	cerr << "[connect] Socket already binded to a port, use another socket" << endl;
	return -1;
    }
    if (!this->_opened) this->open();

    struct timeval time_out;
    time_out.tv_sec = 20;
    time_out.tv_usec = 0;
    setsockopt(this->_socket_id, SOL_SOCKET, SO_SNDTIMEO, &time_out, sizeof(time_out));
    setsockopt(this->_socket_id, SOL_SOCKET, SO_SNDTIMEO, &time_out, sizeof(time_out));

    if (::connect(this->_socket_id, (struct sockaddr*)&this->_sockaddr_in, sizeof(struct sockaddr_in)) < 0) {
	cerr << "[connect] with [address=" << this->ip() << ":" << this->port()
	     << "] Cannot connect to the specified address" << endl;
	return errno;
    }
    this->_binded = true;
    get_pwd(this->_socket_id, this->_passwd);
    return 0;
}
