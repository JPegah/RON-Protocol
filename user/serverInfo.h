


#ifndef _S_I
#define _S_I

#include <stdlib.h>
#include <string.h>
#include "partovdef.h"

using namespace std;

class serverInfo {
private:
    uint32_t IP;
    bool is_connected;
    int seqeunce_num;
    uint64_t time_last_packet;
    int RTT;
    int num_send_packets;
    int num_recieved_packets;

    bool infRTT;

    int last_sequnec_num_recieved;

public:
    void setIP(uint32_t IP);
    uint32_t getIP();
    int get_next_sequence(long);
    bool is_connect();
    void connect();
    void disconnect();
    void add_recieved(int sequnce_number);
    void add_sent();
    int get_sent();
    int get_recieved();
    bool check_sequnce_num(int num);
    void set_last_time(long time);
    void compute_RTT(long time, bool reset);

    double loss_rate();
    bool is_inf_RTT();
    int getRTT();


};

#endif /* serverInfo.h */
