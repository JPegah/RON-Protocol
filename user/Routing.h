

#ifndef _R_T
#define _R_T

#include <stdlib.h>
#include <string.h>
#include "partovdef.h"

using namespace std;

class Routing {
private:
    uint32_t next_hop_RTT;
    uint32_t next_hop_Loss;
    uint32_t RTT;
    double Loss;

public:
    int RTT_interface;
    int Loss_interface;

    void set_RTT_IP(uint32_t IP, uint32_t RTT);
    void set_Loss_IP(uint32_t IP, double loss);

    uint32_t next_RTT_IP();
    uint32_t next_Loss_IP();
    uint32_t next_RTT();
    double next_Loss();
};
#endif
