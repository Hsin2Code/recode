#ifndef _SOCKET_H_
#define _SOCKET_H_

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

using namespace std;

class CommonSocket {
  protected:
    int _socket_id;
    int _socket_type;
    bool _opened;
    bool _binded;
    
  public:
    CommonSocket(int);    
    int socket_id(void);
    int open(void);
    int close(void);
};

class TCP : public CommonSocket
{
  private:
    struct sockaddr_in _sockaddr_in;
    uint32_t _passwd;
  public:
    TCP(void);
    TCP(string, uint16_t);

    string ip(void);
    uint16_t port(void);
    uint32_t passwd(void);

    struct sockaddr_in sockaddr_in(void);

    int connect(void);
};

#endif
