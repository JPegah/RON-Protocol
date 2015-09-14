#include "MCI.h"
#include <iostream>
#include <string.h>

using namespace std;
uint32_t MCI:: get_gatewayIP(){
    return this->gateway_IP;
}
//initialize the custom information
void MCI:: setInfo(char* IP_MAC){
    int counter = 0;
    int i = 0;

    // set the IP address here
    int IP = 0;
    for (;counter < 4;){
        IP *= 256;
        uint8_t temp = 0;;

        //i++;
        while (IP_MAC[i] <= '9' && IP_MAC[i] >= '0'){
            temp *= 10;
            temp += (int) (IP_MAC[i] - '0');
            i++;
        }
        IP += temp;
        i++;
        counter++;
    }

    this->gateway_IP = IP;

    counter = 0;

    // set the gatewat Mac address here
    for( ; counter < 6;){
        this-> gatewayMac[counter] = toInt(IP_MAC[i])*16 + toInt(IP_MAC[i + 1]);
        i += 3;
        counter++;
    }


    int numservers = 0;
    while (IP_MAC[i] <= '9' && IP_MAC[i] >= '0'){
        numservers *= 10;
        numservers += (int) (IP_MAC[i] - '0');
        i++;
    }

    //cerr << "pegah " << IP_MAC[i] << endl;
    i++;
    for (int j = 0; j < numservers; j++){
        serverInfo* server = new serverInfo();

        int IP = 0;
        counter = 0;
        for (;counter < 4;){
            IP *= 256;
            uint8_t temp = 0;//(int) (IP_MAC[i] - '0');
        //    i++;
            while (IP_MAC[i] <= '9' && IP_MAC[i] >= '0'){
                temp *= 10;
                temp += (int) (IP_MAC[i] - '0');
                i++;
            }
            IP += temp;
            i++;
            counter++;
        }
      //  cerr << "IP for server steps: " << temp<< endl;
        server->setIP(IP);
        server->disconnect();
        this->servers.push_back(server);
    }
  //  for (int j = 0; j < 6; j++){
   //     cerr << (int) this->gatewayMac[j] << ":" ;
    //}
    //cerr << endl;




    //cerr << "successfully finished";

}

byte* MCI::getGatewayMac(){
    return this->gatewayMac;
}
uint8_t MCI:: toInt(char first){
    if (first <= '9' && first >= '0'){
        uint8_t res = first - '0';
        return res;
    }else if(first <= 'Z' && first >= 'A'){
        return first -'A' + 10;
    }else{
        return first - 'a' + 10;
    }
}

vector<serverInfo*>* MCI:: get_servers(){
    return &(this->servers);
}

// get the index of the given server IP in servers vector
int MCI::get_server_ind (uint32_t IP){
    for (int i = 0; i < this->servers.size(); i++){
        if (servers.at(i)->getIP() == IP)
            return i;
    }
    return -1;
}

