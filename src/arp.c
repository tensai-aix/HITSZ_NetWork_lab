#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),   // 映射IP地址，所以这个上层协议类型一定是IP协议
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;
map_t extend_arp_buf;   // 不能直接修改arp_buf，因为test逻辑检测里要用到！

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    // 基于arp_init_pkt构造报文，并使用txbuf构造数据包并将报文放入数据包内，最后将报文发送出去
    buf_init(&txbuf,sizeof(arp_pkt_t)); // 直接使用txbuf作为发送包，初始化arp报文长度
    arp_pkt_t new_arp = arp_init_pkt;
    new_arp.opcode16 = swap16(ARP_REQUEST);  // 记得要swap16
    memcpy(new_arp.target_ip,target_ip,NET_IP_LEN);  // 将target_ip放到报文相应字段

    memcpy(txbuf.data,&new_arp,sizeof(new_arp));
    ethernet_out(&txbuf,ether_broadcast_mac,NET_PROTOCOL_ARP);  // 此处发送的是ARP报文，故协议类型ARP
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    buf_init(&txbuf,sizeof(arp_pkt_t));
    arp_pkt_t new_arp = arp_init_pkt;
    new_arp.opcode16 = swap16(ARP_REPLY);
    memcpy(new_arp.target_ip,target_ip,NET_IP_LEN);
    memcpy(new_arp.target_mac,target_mac,NET_MAC_LEN);  // 将target_mac放到相应字段（虽然在本实验中这一步不必要，但还是加上好）

    memcpy(txbuf.data,&new_arp,sizeof(new_arp));
    ethernet_out(&txbuf,target_mac,NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 先进行格式检查，然后根据报文操作类型执行不同操作：1.REPLY：更新arp表并将缓存数据包发出（若有）2.REQUEST：若target_ip是自己，则发送arp响应
    if(buf->len < sizeof(arp_pkt_t)){
        return;
    }
    arp_pkt_t* arp = (arp_pkt_t*) buf->data;
    if((arp->hw_type16 != arp_init_pkt.hw_type16) || (arp->pro_type16 != arp_init_pkt.pro_type16) || (arp->hw_len != arp_init_pkt.hw_len)|| (arp->pro_len != arp_init_pkt.pro_len)){
        return;
    }

    map_set(&arp_table,arp->sender_ip,arp->sender_mac); // 根据sender更新arp表,无论是request还是reply都要更新！

    if(arp->opcode16 == swap16(ARP_REPLY)){
        #ifdef IP_SER
            buf_list_t* store_buf_list = (buf_list_t*)map_get(&extend_arp_buf,arp->sender_ip);
            if(store_buf_list){
                for(int i = 0;i < store_buf_list->buf_count;i++){
                    ethernet_out(store_buf_list->buf[i],src_mac,NET_PROTOCOL_IP); // 注意发送的上层协议类型是ip协议
                }
                map_delete(&extend_arp_buf,arp->sender_ip);
            }
        #else
            buf_t* send_buf = map_get(&arp_buf,arp->sender_ip);
            if(send_buf){
                ethernet_out(send_buf,src_mac,NET_PROTOCOL_IP); // 注意发送的协议类型是ip协议，因为是正常把数据包往上发
                map_delete(&arp_buf,arp->sender_ip);
            }
        #endif
    }
    
    else if(arp->opcode16 == swap16(ARP_REQUEST) && memcmp(arp->target_ip,net_if_ip,NET_IP_LEN) == 0){
        arp_resp(arp->sender_ip,arp->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // 发送数据包，若ip对应mac在map里，直接发。否则查看buf缓存是否被占用。若被占用则丢弃，若不占用则将buf装入缓存中，然后发送req。
    uint8_t* target_mac = (uint8_t*)map_get(&arp_table,ip);
    if(target_mac){
        ethernet_out(buf,target_mac,NET_PROTOCOL_IP);
        return;
    }
    
    #ifdef IP_SER
        buf_list_t* store_buf_list = (buf_list_t*)map_get(&extend_arp_buf,ip);
        if(!store_buf_list){
            buf_list_t* new_buf_list = (buf_list_t*) malloc (sizeof(buf_list_t));
            new_buf_list->buf_count = 0;
            new_buf_list->buf[new_buf_list->buf_count++] = buf;
            map_set(&extend_arp_buf,ip,new_buf_list);
            arp_req(ip);
        }
        else{
            store_buf_list->buf[store_buf_list->buf_count++] = buf;
        }
    #else
        buf_t* store_buf;
        store_buf = (buf_t*)map_get(&arp_buf,ip);
        if(store_buf){
            return;
        }
        map_set(&arp_buf,ip,buf);
        arp_req(ip);
    #endif
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    #ifdef IP_SER
        map_init(&extend_arp_buf, NET_IP_LEN, sizeof(buf_list_t), 0, ARP_MIN_INTERVAL, NULL, NULL);
    #else
        map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    #endif
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}