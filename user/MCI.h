
#ifndef _M_C_I
#define _M_C_I

#include <string.h>
#include <stdlib.h>
#include <vector>
#include "serverInfo.h"
#include "partovdef.h"

using namespace std;
class MCI {
    uint32_t gateway_IP;
    byte gatewayMac[6];
    vector<serverInfo*> servers;
public:
    void setInfo(char* info);
    uint8_t toInt(char first);
    byte* getGatewayMac();
    vector<serverInfo*>* get_servers();
    uint32_t get_gatewayIP();
    int get_server_ind (uint32_t IP);
};

struct Routing{
    uint32_t next_hop_RTT;
    uint32_t next_hop_Loss;
    uint32_t RTT;
    double Loss;
    int RTT_interface;
    int Loss_interface;
    bool inf_RTT;
}__attribute__((packed));

struct NAT_info{
    uint32_t realIP;
    uint16_t real_port;
    bool for_others;
    bool is_dsa;
    uint64_t start;
    bool expire;
}__attribute__((packed));

#endif /* MCI.h */
