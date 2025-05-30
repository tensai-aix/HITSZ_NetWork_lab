#ifndef IP_H
#define IP_H

#include "net.h"

#pragma pack(1)
typedef struct ip_hdr {
    uint8_t hdr_len : 4;         // 首部长, 4字节为单位
    uint8_t version : 4;         // 版本号
    uint8_t tos;                 // 服务类型
    uint16_t total_len16;        // 总长度
    uint16_t id16;               // 标识符
    uint16_t flags_fragment16;   // 标志与分段
    uint8_t ttl;                 // 存活时间
    uint8_t protocol;            // 上层协议
    uint16_t hdr_checksum16;     // 首部校验和
    uint8_t src_ip[NET_IP_LEN];  // 源IP
    uint8_t dst_ip[NET_IP_LEN];  // 目标IP
} ip_hdr_t;
#pragma pack()

#define IP_HDR_LEN_PER_BYTE 4       // ip包头长度单位
#define IP_HDR_OFFSET_PER_BYTE 8    // ip分片偏移长度单位
#define IP_VERSION_4 4              // ipv4
#define IP_MORE_FRAGMENT (1 << 13)  // ip分片mf位
#define IP_FRAGMENT_TIMEOUT 10000   // 超过10s未更新就丢弃
void ip_in(buf_t *buf, uint8_t *src_mac);
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol);
void ip_init();
void ip_fragment_in(uint8_t protocol,uint16_t flags_fragment16,buf_t* buf,uint8_t* src_ip,uint16_t id);
void ip_fragment_send_in(uint8_t protocol,uint8_t* src_ip,buf_t* buf,uint16_t id);
void fragment_check_entry(void *id, void *ipfragment_mess, time_t *timestamp);
void fragment_check();

typedef struct ipFragment_mess{
    dtime_t last_update;            // 上一个分片到达时间
    uint8_t payload[BUF_MAX_LEN];   // 数据负载
    int total_bytes;                // 数据总量
    int receive_bytes;              // 已经收到的数据量
    uint8_t map_offset[BUF_MAX_LEN / IP_HDR_OFFSET_PER_BYTE];  // 记录已经收到的offset，避免重复收包
} ipFragment_mess_t;

#endif