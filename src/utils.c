#include "utils.h"

#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
    // TO-DO
    uint32_t sum = 0;
    while(len > 1){
        sum += (*data);
        data++;
        len -= 2;
    }
    if(len == 1){
        sum += *((uint8_t*)data);
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    // TO-DO
    #pragma pack(push, 1)  
    typedef struct {
        uint8_t src_ip[NET_IP_LEN];  
        uint8_t dst_ip[NET_IP_LEN]; 
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len16;
    } udpUR_hdr_t;
    #pragma pack(pop)     
    buf_add_header(buf,sizeof(udpUR_hdr_t));
    uint8_t temp_ip_store[sizeof(udpUR_hdr_t)];
    memcpy(temp_ip_store,buf->data,sizeof(udpUR_hdr_t));
    udpUR_hdr_t* udpUR_head = (udpUR_hdr_t*) buf->data;
    memcpy(udpUR_head->src_ip,src_ip,NET_IP_LEN);
    memcpy(udpUR_head->dst_ip,dst_ip,NET_IP_LEN);
    udpUR_head->zero = 0;
    udpUR_head->protocol = protocol;
    udpUR_head->udp_len16 = swap16(buf->len - sizeof(udpUR_hdr_t));
    int add_zero = buf->len % 2 == 1;
    buf_add_padding(buf,add_zero);
    uint16_t checksum = checksum16((uint16_t*)buf->data,buf->len);
    buf_remove_padding(buf,add_zero);
    memcpy(buf->data,temp_ip_store,sizeof(udpUR_hdr_t));
    buf_remove_header(buf,sizeof(udpUR_hdr_t));
    return checksum;
}