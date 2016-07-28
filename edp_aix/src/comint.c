#include <string.h>
#include "protocol.h"
#include "socket.h"
#include "comint.h"
#include "type.h"
/* 策略名称 */
const char * policy_target[POLICY_TYPE_COUNT] = {"ONLINE-DEAL-CONTROL"};

/* 策略标签转枚举 */
static enum policy_type
type_from_target(const char * target) {
    enum policy_type type;
    for(type = 0; type < POLICY_TYPE_COUNT; type++) {
        if(strcmp(target, policy_target[type]) == 0)
            return type;
    }
    return POLICY_TYPE_COUNT;
}

static uint32_t
anonymous(const char *ip, const uint32_t port)
{
    /* 连接服务器 */
    int sock;
    if(create_client_socket(&sock, ip, port)) {
        close_socket(sock);
        return FAIL;
    }
    /* 获取加密密钥 */
    DWORD key;
    if(get_encrypt_key(sock, &key)) {
        close_socket(sock);
        return FAIL;
    }
    DWORD pkt_len = 0;
    struct packet_t pkt;
    pkt.head.type = ENDIANS(DOWNLOAD_POLICY);
    pkt.head.what = ENDIANS(DETECT_POLICY);
    pkt.head.key = ENDIANL(key);
    pkt.head.pkt_len = ENDIANL(pkt_len);


    return OK;
}
