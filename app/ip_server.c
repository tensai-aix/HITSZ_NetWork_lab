#include "driver.h"
#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "icmp.h"

#define BUF_AMOUNT 4   // 要发送的数据包数量
#define MAX_REC_BUF MAX_STORE_BUF  // 最大接收数据包数量
#define NET_PROTOCOL_TEST 253   // 实验用的虚拟protocol
#define CEIL_DIV(a, b) (((a) + (b) - 1) / (b)) // 向上取整除法

typedef struct buf_record{
    buf_t buf;
    dtime_t recv_time;
    int i, j;
    int valid;
} buf_record_t;

// 发送包相关数据
int send_buf_length[BUF_AMOUNT] = {2000, 2500, 3000, 3000};
buf_t send_buf[BUF_AMOUNT];
int send_amount = 0;
int send_buf_content[BUF_AMOUNT] = {0xa1,0xb3,0xe5,0x37};
// 接收缓存列表
buf_record_t rec_buf_store[MAX_REC_BUF];
int receive_amount = 0;
// 分片延迟时间，-1代表永不发送
int delay_time[ ][3] = {
    {0, 4000, -1},
    {2000, 0, -1},
    {0, 15000, -1},
    {20000, 20000, 20000}
};
// 轮询时间
dtime_t last;

// 新的buf_copy，只拷贝有效数据部分
void new_buf_copy(buf_t* dst,buf_t* src){
    buf_init(dst,src->len);
    memcpy(dst->data,src->data,src->len);
}

// 向里传送数据包
void send_in() {
    dtime_t now;
    mingw_gettimeofday(&now,NULL);

    for (int i = 0; i < receive_amount; i++) {
        if (!rec_buf_store[i].valid){
            continue;
        }
            
        int i_idx = rec_buf_store[i].i;
        int j_idx = rec_buf_store[i].j;
        int delay = delay_time[i_idx][j_idx];

        if (delay >= 0 && calcul_diff_time(rec_buf_store[i].recv_time,now) >= delay) {
            printf("Forwarding: packet %d, fragment %d\n", i_idx, j_idx);
            if(i_idx == 1 && j_idx == 1){   // 对包1分片1实行repeat测试
                buf_t test_repeat_buf;
                new_buf_copy(&test_repeat_buf,&rec_buf_store[i].buf);
                ethernet_in(&(rec_buf_store[i].buf));
                printf("repeat test\n");
                ethernet_in(&test_repeat_buf);
            }
            else{
                ethernet_in(&(rec_buf_store[i].buf));
            }
            rec_buf_store[i].valid = 0;
        }
    }
}

// 接收包并缓存
void receive_buf(){
    if (driver_recv(&rxbuf) > 0) {
        ip_hdr_t* ip_hdr = (ip_hdr_t*)(rxbuf.data + sizeof(ether_hdr_t));
        if((memcmp(net_if_ip,ip_hdr->src_ip,NET_IP_LEN) != 0) && (ip_hdr->protocol != NET_PROTOCOL_TEST)){   // 非本实验的数据包直接eth_in(抓包发现有很多未知包)
            ethernet_in(&rxbuf);
        }
        else{
            buf_record_t* rec = &rec_buf_store[receive_amount];
            new_buf_copy(&rec->buf,&rxbuf);   // 不能调用buf_copy!因为rec->buf和rxbuf的payload一样而data指针不一样
            mingw_gettimeofday(&rec->recv_time, NULL);

            uint8_t* data = (uint8_t*)(rxbuf.data + sizeof(ether_hdr_t) + sizeof(ip_hdr_t));

            for(int tmp = 0;tmp < BUF_AMOUNT;tmp++){    // 遍历找对应发送包
                if(data[0] == send_buf_content[tmp]){
                    rec->i = tmp;
                    break;
                }
            }
            // 因为分片长度减少，但没减少很多，所以向上取整除法计算是第几个分片
            rec->j = CEIL_DIV((swap16(ip_hdr->flags_fragment16) & 0x1FFF),((ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) / IP_HDR_OFFSET_PER_BYTE));
            
            rec->valid = 1;
            receive_amount++;
            printf("receive: packet %d fragment %d, id:%d, offset:%-4d, data_len:%-4d, rec_num:%d\n",rec->i,rec->j,swap16(ip_hdr->id16),
                (swap16(ip_hdr->flags_fragment16) & 0x1FFF) * IP_HDR_OFFSET_PER_BYTE,(int)(rec->buf.len - sizeof(ether_hdr_t) - sizeof(ip_hdr_t)),receive_amount);
        }
    }
}

// 发送数据包
void send_out(){   
    if (send_amount < BUF_AMOUNT) {
        ip_out(&send_buf[send_amount],net_if_ip,NET_PROTOCOL_TEST);
        send_amount++;
    }
}

// 初始化发送数据包
void init_buf(){
    for (int i = 0;i < BUF_AMOUNT;i++) {
        buf_init(&send_buf[i],send_buf_length[i]);
        memset(send_buf[i].data,send_buf_content[i],send_buf_length[i]);
    }
}

// 等待1s，建立自身的ip-mac连接
void warmup(){
    dtime_t before,now;
    mingw_gettimeofday(&before, NULL);
    while(1){
        net_poll(); 
        mingw_gettimeofday(&now, NULL);
        if(calcul_diff_time(before,now) >= 1000){
            break;
        }
    }
}

// 隔100ms轮询一次,淘汰过期的ip缓存包
void _fragment_check(){
    dtime_t now;
    mingw_gettimeofday(&now,NULL);
    if(calcul_diff_time(last,now) >= 100){
        fragment_check();
        last = now;
    }
}

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {
        return -1;
    }

    init_buf();

    warmup();
    mingw_gettimeofday(&last,NULL);

    while (1) {
        send_out();         // 发送数据包
        receive_buf();      // 接收数据包
        send_in();          // 延迟向里发送
        _fragment_check();  // 检查过期包
    }

    return 0;
}
