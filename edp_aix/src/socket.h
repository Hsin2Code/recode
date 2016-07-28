#ifndef _SOCKET_H___
#define _SOCKET_H___

#include "type.h"


/* 创建服务端 套接字 */
uint32_t
create_server_socket(int *fd, const uint16_t port);

/* 创建客户端 套接字 */
uint32_t
create_client_socket(int* fd, const char* ip, const uint16_t port);

/* 接入客户端请求 */
uint32_t
accept_socket(const int sock, int *new_sock, uint32_t * ip, uint16_t * port);

/* 关闭套接字 */
void
close_socket(const int sock);

#endif
