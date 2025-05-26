#ifndef TCP_H
#define TCP_H

#include "net.h"

#pragma pack(1)
typedef struct tcp_hdr {
    uint16_t src_port16;  // 源端口
    uint16_t dst_port16;  // 目标端口
    uint32_t seq;         // sequence number(当前字节序列号)
    uint32_t ack;         // ack number（期待的下一字节的序列号）
    uint8_t doff;         // 低4bit表示保留位，高4bit表示首部长度（指向TCP报文数据起始位）
    uint8_t flags;
    uint16_t win;         // window size
    uint16_t checksum16;  // 校验和
    uint16_t uptr;        // urgent pointer
} tcp_hdr_t;
#pragma pack()

typedef struct tcp_key {
    uint8_t remote_ip[NET_IP_LEN];
    uint16_t remote_port;
    uint16_t host_port;
} tcp_key_t;

typedef enum tcp_state {
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT1,
    TCP_STATE_FIN_WAIT2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK
} tcp_state_t;

typedef struct tcp_connection {
    /* TCP connection states */
    tcp_state_t state;
    uint8_t not_send_empty_ack;   // 不需要发送空的ACK报文

    /* TCP communication states */
    int port;
    uint32_t seq;  // 要发送的序列号
    uint32_t ack;  // 要发送的 ACK
} tcp_conn_t;

#define TCP_FLG_URG (1 << 5)
#define TCP_FLG_ACK (1 << 4)
#define TCP_FLG_PSH (1 << 3)
#define TCP_FLG_RST (1 << 2)
#define TCP_FLG_SYN (1 << 1)
#define TCP_FLG_FIN (1 << 0)

#define TCP_FLG_ISSET(x, y) (((x & 0x3f) & (y)) ? 1 : 0)

#define TCP_HEADER_LEN 20
#define TCP_RETRANSMISSON_TIMEOUT 3
#define TCP_MAX_WINDOW_SIZE UINT16_MAX
#define TCP_MAX_CONN_NUM (MAP_MAX_LEN / (sizeof(tcp_key_t) + sizeof(tcp_conn_t) + sizeof(time_t)))

typedef void (*tcp_handler_t)(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port);

void tcp_init();
int tcp_open(uint16_t port, tcp_handler_t handler);
void tcp_close(uint16_t port);

void tcp_in(buf_t *buf, uint8_t *src_ip);
void tcp_out(tcp_conn_t *tcp_conn, buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port, uint8_t flags);
void tcp_send(tcp_conn_t *tcp_conn, uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port);
#endif