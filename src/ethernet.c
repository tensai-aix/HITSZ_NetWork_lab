#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // TO-DO
    // 先进行长度检查，然后把eth包头中的src mac地址与协议类型提取出来，并去除掉eth包头，最后通过net_in传给上层
    if(buf->len < sizeof(ether_hdr_t)) {
        return;
    }
    ether_hdr_t* hdr = (ether_hdr_t*) buf->data;
    uint16_t protocol = swap16(hdr->protocol16);  // 这里进行字节序转换
    uint8_t src_mac[NET_MAC_LEN]; 
    memcpy(src_mac,hdr->src,NET_MAC_LEN);  
    buf_remove_header(buf,sizeof(ether_hdr_t));
    net_in(buf,protocol,src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // TO-DO
    // 先进行长度检查，然后构造出eth包头并填充数据，最后发送给下层
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT){
        buf_add_padding(buf,ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    buf_add_header(buf,sizeof(ether_hdr_t));
    ether_hdr_t* hdr = (ether_hdr_t*) buf->data;
    memcpy(hdr->dst,mac,NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);
    memcpy(hdr->src,net_if_mac,NET_MAC_LEN);
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
