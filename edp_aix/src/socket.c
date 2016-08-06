#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <strings.h>
#include <fcntl.h>
#include "socket.h"
#include "journal.h"


/* 创建服务端 套接字 */
uint32_t
create_server_socket(int *fd, const uint16_t port)
{
    int sock;
    struct sockaddr_in server_addr;
    int opt;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERR("Failed to create socket!\n");
        return FAIL;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(sock, (struct sockaddr *)(&server_addr), sizeof(server_addr))) {
        LOG_ERR("Failed to bind socket!\n");
        close_socket(sock);
        return FAIL;
    }

    if (listen(sock, 5)) {
        LOG_ERR("Failed to listen socket!\n");
        close_socket(sock);
        return FAIL;
    }

//    epoll_add_socket(sock);
    *fd = sock;

    return OK;
}

/* 创建客户端 套接字 */
uint32_t
create_client_socket(int* fd, const char* ip, const uint16_t port)
{
    int sock, flags, res;
    struct sockaddr_in their_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == sock) {
        LOG_ERR("Failed to create socket. ERROR:%s\n", strerror(errno));
        return FAIL;
    }
    struct timeval timeout = {3,0};
    //设置发送超时
    setsockopt(sock, SOL_SOCKET,SO_SNDTIMEO, (char *)&timeout,sizeof(struct timeval));
    //设置接收超时
    setsockopt(sock, SOL_SOCKET,SO_RCVTIMEO, (char *)&timeout,sizeof(struct timeval));

    their_addr.sin_family = AF_INET;
    their_addr.sin_addr.s_addr = inet_addr(ip);
    their_addr.sin_port = htons(port);
    bzero(&their_addr.sin_zero, 8);

    if((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        LOG_ERR("Connet fcntl.... ERROR:%s\n", strerror(errno));
        close(sock);
        return FAIL;
    }

    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("Connet fcntl.... ERROR:%s\n", strerror(errno));
        close(sock);
        return FAIL;
    }
    LOG_MSG("IP is ->%s<- port is ->%u<- \n", ip, port);
    if(0 != connect(sock, (struct sockaddr*)&their_addr, sizeof(struct sockaddr))) {
        if(errno != 0 && errno != EINPROGRESS) { // EINPROGRESS
            LOG_ERR("Connect server.... ERROR:%s\n", strerror(errno));
            close(sock);
            return FAIL;
        }
    }else {
        fcntl(sock, F_GETFL, &flags);
        fcntl(sock, F_SETFL, flags & (~O_NONBLOCK));

        *fd = sock;
        return OK;
    }
    fd_set fdr, fdw;
    FD_ZERO(&fdr); FD_ZERO(&fdw);
    FD_SET(sock, &fdr); FD_SET(sock, &fdw);
    res = select(sock + 1, &fdr, &fdw, NULL, &timeout);
    if(res == 1) {
        if(FD_ISSET(sock, &fdw)) {
            LOG_MSG("Connected...\n");
            fcntl(sock, F_GETFL, &flags);
            fcntl(sock, F_SETFL, flags & (~O_NONBLOCK));
            *fd = sock;
            return OK;
        }
    }
    if(res < 0) {
        LOG_ERR("Connect server.... ERROR:%s\n", strerror(errno));
        close(sock);
        return FAIL;
    }
    LOG_MSG("Connect server timeout\n");
    close(sock);
    return FAIL;
}
/* 接入客户端请求 */
uint32_t
accept_socket(const int sock, int *new_sock, uint32_t * ip, uint16_t * port)
{

    int fd;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    if (!new_sock || !ip || !port) {

        LOG_ERR("Parameter is NULL in accept_socket function!\n");
        return FAIL;
    }

    client_len = sizeof(client_addr);
    fd = accept(sock, (struct sockaddr *)(&client_addr), &client_len);
    if (fd < 0) {

        LOG_ERR("Failed to accepet socket!\n");
        return FAIL;
    }

//    epoll_add_socket(fd);

    *new_sock = fd;
    *ip = client_addr.sin_addr.s_addr;
    *port = client_addr.sin_port;

    return OK;
}

/* 关闭套接字 */
void
close_socket(const int sock)
{
    if(sock >= 0) {
        /* shutdown 也关闭了其它进程使用此sock */
        if(shutdown(sock, SHUT_RDWR) < 0) {
            // SGI causes EINVAL
            if (errno != ENOTCONN && errno != EINVAL) {
                LOG_ERR("close socket error when shutdown\n");
            }
        }
        if(close(sock) < 0) {
            LOG_ERR("inner close socket error\n");
        }
    }
}
