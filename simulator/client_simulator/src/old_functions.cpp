#include <sys/socket.h>
#include <netdb.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include "old_functions.h"
#include "common.h"

bool conn_serv(int skt) {
    ///连接
    ///获取服务器地址，也可以只获取一次，保存下来。
    bool ret = false;
    std::string  str_addr = g_server_ip;

    struct hostent * he = NULL;
    he = gethostbyname(str_addr.c_str());

    struct sockaddr_in their_addr;
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(g_server_port);
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(their_addr.sin_zero), '\0', 8);


    int flags = 0;
    int connect_timeout = 2;
    int error = -1;
    int len = sizeof(socklen_t);
    fcntl(skt, F_GETFL, &flags);
    flags |= O_NONBLOCK;
    fcntl(skt, F_SETFL, flags);

    timeval tm;
    memset(&tm, 0, sizeof(tm));
    fd_set conn_set;
    if (connect(skt, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
        tm.tv_sec = connect_timeout;
        tm.tv_usec = 0;
        FD_ZERO(&conn_set);
        FD_SET(skt, &conn_set);
        if(select(skt + 1, NULL, &conn_set, NULL, &tm) > 0) {
            getsockopt(skt, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if(error == 0){
                ret = true;
            } else {
                ret = false;
            }
        } else {
            ret = false;
        }
    } else {
        ret = true;
    }
    fcntl(skt, F_GETFL, &flags);
    flags &= (~O_NONBLOCK);
    fcntl(skt, F_SETFL, flags);

    return ret;
}


void closeSocket(int fd) {
    if (fd >= 0) {
        // first clear any errors, which can cause close to fail
        getSO_ERROR(fd);
        // secondly, terminate the 'reliable' delivery
        if (shutdown(fd, SHUT_RDWR) < 0) {
            // SGI causes EINVAL
            if (errno != ENOTCONN && errno != EINVAL) {
                SM_ERROR() << "close socket error when shutdown ";
            }
        }
        if (::close(fd) < 0) {
            SM_ERROR() << "inner close socket error";
        }
    }
}

void close_socket(int skt, int line) {
    if(line != -1) {
        char buf[128] = {0};
        sprintf(buf, "%s: %d\n", "close socket at line: ", line);
        SM_LOG() << buf;
    }
    closeSocket(skt);
}


int getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        SM_ERROR() << "get so option error";
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}
