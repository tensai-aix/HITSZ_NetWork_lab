#include "driver.h"
#include "net.h"
#include "icmp.h"

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {  
        printf("net init failed.");
        return -1;
    }

    int test_time = 4;
    uint8_t to_ping_ip[4][NET_IP_LEN] = {{10, 250, 185, 147},{10, 250, 185, 148},{183, 2, 172, 17},{127, 0, 0, 1}};
    char* descibe[] = {"本机ip", "实验ip", "百度ip", "回环地址"};

    for(int i = 0;i < test_time;i++){
        printf("---------------------------------------------------------------\n");
        printf("下面测试ping%s:\n",descibe[i]);
        while (1) {
            if(ping_req(to_ping_ip[i])){
                break;
            }
            net_poll();  
        }
    }

    while (1) {
        net_poll(); 
    }
    
    return 0;
}
