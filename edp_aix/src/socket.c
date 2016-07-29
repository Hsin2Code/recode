#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "socket.h"
#include "journal.h"
#include "base.h"

/* 创建服务端 套接字 */
uint32_t
create_server_socket(int *fd, uint16_t port)
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
        return FAIL;
    }

    if (listen(sock, 5)) {
        LOG_ERR("Failed to listen socket!\n");
        return FAIL;
    }

//    epoll_add_socket(sock);
    *fd = sock;

    return OK;
}
/* 创建客户端 套接字 */
uint32_t
create_client_socket(int* fd, char* ip, uint16_t port)
{
    int sock;
    struct sockaddr_in their_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == sock) {
        LOG_ERR("Failed to create socket. \n");
        return FAIL;
    }

    their_addr.sin_family = AF_INET;
    their_addr.sin_addr.s_addr = inet_addr(ip);
    their_addr.sin_port = htons(port);
    bzero(&their_addr.sin_zero, 8);

    if(-1 == connect(sock, (struct sockaddr*)&their_addr, sizeof(struct sockaddr))){
        LOG_ERR("Cannot connect. \n");
        return FAIL;
    }

//    epoll_add_client(sock);
    *fd = sock;

    return OK;
}
/* 接入客户端请求 */
uint32_t
accept_socket(int sock, int *new_sock, uint32_t * ip, uint16_t * port)
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
