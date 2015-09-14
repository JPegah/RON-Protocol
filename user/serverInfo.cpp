#include "serverInfo.h"
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include "partovdef.h"
#include <chrono>


using namespace std;
int serverInfo::getRTT(){
    return this->RTT;
}

double serverInfo::loss_rate(){
    if (!is_connected)
        return 1;
    else
        return 1 - 1.0 *num_recieved_packets/num_send_packets;
}

void serverInfo::set_last_time(long time){
    this->time_last_packet = time;
    return;
}
void serverInfo::compute_RTT(long time, bool reset){
    if (reset){
        RTT = time - time_last_packet;
        return;
    }

    RTT = (RTT+(time - time_last_packet)) / 2.0;
}
void serverInfo:: setIP(uint32_t IP){
    this->IP = IP;
    this->seqeunce_num = -1;
    this->last_sequnec_num_recieved = -1;
    this->is_connected = false;
    this->infRTT = true;
}
bool serverInfo:: check_sequnce_num(int num){

    if (num == this->seqeunce_num)
        return true;

    return false;
}

void serverInfo::add_recieved(int sequnce_number){
    this->last_sequnec_num_recieved = sequnce_number;
    num_recieved_packets++;
    connect();
    return;
}
void serverInfo::add_sent(){
    num_send_packets++;
    return;
}
int serverInfo::get_sent(){
    return num_send_packets;
}
int serverInfo::get_recieved(){
    return num_recieved_packets;
}
bool serverInfo::is_connect(){
    return this->is_connected;
}
uint32_t serverInfo:: getIP(){
    return this->IP;
}

int serverInfo ::get_next_sequence(long now){
    this->seqeunce_num++;


    if(last_sequnec_num_recieved + 3 < this->seqeunce_num)
        disconnect();

    if (is_connected) /// shak daram
        this->num_send_packets++;


    //long now = chrono::system_clock::now();
    time_last_packet = now;
    /// set the sending time here
    return this->seqeunce_num;
}

void serverInfo:: connect(){
    this ->infRTT = false;
    this->is_connected = true;
}

void serverInfo:: disconnect(){
    this->infRTT = true;
    this->is_connected = false;
}
bool serverInfo:: is_inf_RTT(){
    return this->infRTT;

}

