#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "socket.h"
#include "journal.h"
#include "comint.h"
#include "protocol.h"
#include "base.h"
#include "register.h"
/* 心跳函数 */
static uint32_t
do_heart_beat(char* ip, uint16_t port)
{
    int sock;
    /* 创建客户端套接字 */
    if(create_client_socket(&sock, ip, port)) {
        LOG_ERR("Create client socket error!\n");
        return errno;
    }
    /* 获取加密密钥 */
    uint32_t key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close(sock);
        return FAIL;
    }
    LOG_MSG("Get encrypt KEY is %u", key);
    return OK;
}

int main(int argc,char **argv) {
    /* 注册 */
    do_register("192.168.133.143", 88);
    /* 心跳 */
    //do_heart_beat("192.168.133.143", 88);
    printf("pkt ex size %zu\n", sizeof(struct packet_ex_t));
    printf("head ex size %zu\n", sizeof(struct head_ex_t));
    return OK;
}
