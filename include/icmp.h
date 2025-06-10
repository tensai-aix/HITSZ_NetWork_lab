#ifndef ICMP_H
#define ICMP_H

#include "net.h"

#define PING_DATA_SIZE 32  // 填充的ping请求的数据大小

#pragma pack(1)
typedef struct icmp_hdr {
    uint8_t type;         // 类型
    uint8_t code;         // 代码
    uint16_t checksum16;  // ICMP报文的校验和
    uint16_t id16;        // 标识符
    uint16_t seq16;       // 序号
} icmp_hdr_t;

#pragma pack()
typedef enum icmp_type {
    ICMP_TYPE_ECHO_REQUEST = 8,  // 回显请求
    ICMP_TYPE_ECHO_REPLY = 0,    // 回显响应
    ICMP_TYPE_UNREACH = 3,       // 目的不可达
} icmp_type_t;

typedef enum icmp_code {
    ICMP_CODE_PROTOCOL_UNREACH = 2,  // 协议不可达
    ICMP_CODE_PORT_UNREACH = 3       // 端口不可达
} icmp_code_t;

typedef struct ping_req{             // 一次icmp请求报文的数据结构
    dtime_t send_time;               // 发送时间
    dtime_t receive_time;            // 接收时间
    uint8_t dst_ip[NET_IP_LEN];      // 目的ip
    int length;                      // 数据长度
    uint8_t TTL;                     // TTL
} ping_req_t;

typedef struct ping{                 // ping请求的数据结构
    int ping_time;                   // ping_req的次数

    time_t last_send;                // 上一次发送ping_req的时间

    int success_time;                // 成功的ping_req次数
    int shortest_time;               // 最短的ping_req时间
    int longest_time;                // 最长的ping_req时间
    int sum_time;                    // ping_req总时间

    int is_finished;                 // 是否完成了ping请求
} ping_t;

void icmp_in(buf_t *buf, uint8_t *src_ip);
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code);
void icmp_init();
void icmp_req_out(uint8_t* dst_ip,uint16_t id);
int ping_req(uint8_t* dst_ip);
char *ip_to_string(uint8_t *ip);
void ping_req_check(ping_t* ping);
void set_ping_req_TTL(uint8_t TTL,buf_t* buf);
#endif
