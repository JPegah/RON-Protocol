#include "Routing.h"
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include "partovdef.h"



using namespace std;
void Routing::set_RTT_IP(uint32_t IP, uint32_t RTT){
    this->next_hop_RTT = IP;
    this->RTT = RTT;
}
void Routing::set_Loss_IP(uint32_t IP, double loss){
    this->next_hop_Loss = IP;
    this->Loss = loss;
}

uint32_t Routing::next_RTT_IP(){
    return next_hop_RTT;
}
uint32_t Routing::next_Loss_IP(){
    return next_hop_Loss;
}
uint32_t Routing::next_RTT(){
    return RTT;
}
double Routing::next_Loss(){
    return Loss;
}


