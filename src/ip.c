#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

static uint16_t ip_id = -1;  // 使用全局变量ip_id

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 发往上层（传输层），删去ip头部
    if(buf->len < sizeof(ip_hdr_t)){
        return;
    }
    ip_hdr_t* in_ip = (ip_hdr_t*)buf->data;
    if(in_ip->version != IP_VERSION_4 || swap16(in_ip->total_len16) > buf->len){
        return;
    }
    uint16_t ori_checksum = in_ip->hdr_checksum16;
    in_ip->hdr_checksum16 = 0;
    if(ori_checksum != checksum16((uint16_t*)in_ip,sizeof(ip_hdr_t))){
        return;
    }
    in_ip->hdr_checksum16 = ori_checksum;
    if(memcmp(in_ip->dst_ip,net_if_ip,NET_IP_LEN) != 0){
        return;
    }
    if(buf->len > swap16(in_ip->total_len16)){
        buf_remove_padding(buf,buf->len - swap16(in_ip->total_len16));
    }
    buf_remove_header(buf,sizeof(ip_hdr_t));
    if(in_ip->protocol == NET_PROTOCOL_ICMP){
        #ifdef PING    // 仅在PING测试模式下修改TTL，避免其他模块（如ip_test）因缺少icmp相关函数而报错
        set_ping_req_TTL(in_ip->ttl,buf);
        #endif
    }
    #ifndef IP_SER
    if(net_in(buf,in_ip->protocol,in_ip->src_ip) != 0){  // 这里net_in的src要填源ip地址！因为会传到icmp_in里，作为目的ip地址（请问这个src_mac究竟有什么用？）
        buf_add_header(buf,sizeof(ip_hdr_t));
        memcpy(buf->data,in_ip,sizeof(ip_hdr_t));
        icmp_unreachable(buf,in_ip->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
    #endif
}

// void ip_fragment_in(){

// }

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t to_add_ip;
    to_add_ip.hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    to_add_ip.version = IP_VERSION_4;
    to_add_ip.tos = 0;
    to_add_ip.total_len16 = swap16(buf->len);  // 记得要大小端转换
    to_add_ip.id16 = swap16(id);
    offset /= IP_HDR_OFFSET_PER_BYTE;
    to_add_ip.flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    to_add_ip.ttl = IP_DEFALUT_TTL; 
    to_add_ip.protocol = protocol;
    to_add_ip.hdr_checksum16 = 0;
    memcpy(to_add_ip.src_ip,net_if_ip,NET_IP_LEN);
    memcpy(to_add_ip.dst_ip,ip,NET_IP_LEN);
    to_add_ip.hdr_checksum16 = checksum16((uint16_t*)(&to_add_ip),sizeof(ip_hdr_t)); // 要进行类型转换
    memcpy(buf->data,&to_add_ip,sizeof(ip_hdr_t));
    arp_out(buf,ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // 发往下层（数据链路层），加上ip头
    int max_dataSize = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    int offset = 0;
    int buf_len = buf->len;
    ip_id++;
    if(buf_len <= max_dataSize){
        ip_fragment_out(buf,ip,protocol,ip_id,offset,0);  
        return;
    }
    buf_t* ip_buf;
    while(buf_len > max_dataSize){
        ip_buf = (buf_t*) malloc (sizeof(buf_t));
        buf_init(ip_buf,max_dataSize);  // 重要！因为在ip_fragment_out中添加了头部，所以这个ip_buf的长度和data指针是被修改了的！要重新初始化
        memcpy(ip_buf->data,buf->data + offset,max_dataSize);
        ip_fragment_out(ip_buf,ip,protocol,ip_id,offset,1);
        offset += max_dataSize;
        buf_len -= max_dataSize;
    }
    ip_buf = (buf_t*) malloc (sizeof(buf_t));
    buf_init(ip_buf,buf_len);  
    memcpy(ip_buf->data,buf->data + offset,buf_len);
    ip_fragment_out(ip_buf,ip,protocol,ip_id,offset,0);
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}