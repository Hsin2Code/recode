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

static uint32_t
do_heart_beat(char* ip, uint16_t port)
{
    int sock;
    if(create_client_socket(&sock, ip, port)) {
        LOG_ERR("Create client socket error!\n");
        return FALSE;
    }
    /* 获取加密密钥 */
    uint32_t key;
    if(get_encrypt_key(sock, &key)) {
        LOG_ERR("Get encrypt KEY error!\n");
        close(sock);
        return FALSE;
    }
    return TRUE;
}

int main(int argc,char **argv) {
    return 0;
}
