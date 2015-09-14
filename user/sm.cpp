//                   In the name of GOD
/**
 * Partov is a simulation engine, supporting emulation as well,
 * making it possible to create virtual networks.
 *
 * Copyright © 2009-2014 Behnam Momeni.
 *
 * This file is part of the Partov.
 *
 * Partov is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Partov is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Partov.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

 /// use the loss_rate function instead of computing here

#include "sm.h"
#include "interface.h"
#include "frame.h"
#include <stdio.h>
#include <utility>
#include "MCI.h"
#include <sstream>
#include <cstring>
#include "sr_protocol.h"
#include <netinet/in.h>
#include <chrono>
#include <time.h>
#include <iomanip>
using namespace std;
#include <sys/timeb.h>
/// check kardane in ke time daghighan koja bashe va che farghi dare

SimulatedMachine::SimulatedMachine (const ClientFramework *cf, int count) :
	Machine (cf, count) {
	// The machine instantiated.
	// Interfaces are not valid at this point.
}

SimulatedMachine::~SimulatedMachine () {
	// destructor...
}

void SimulatedMachine::initialize () {
    string info = getCustomInformation();
	this->additionalInfo.setInfo(&info[0]);

    last_port = 8000;
	vector<serverInfo*>* servers = this->additionalInfo.get_servers();
	for (uint i = 0; i < servers->size(); i++){
	    mutex* lock = (mutex*) malloc(sizeof(mutex));
	    server_locks.push_back(lock);
	    struct Routing* r = (Routing*) malloc(sizeof (struct Routing));
        r->Loss_interface = 1; // it means that uses straight path
        r->RTT_interface = 1;
        r->next_hop_Loss = additionalInfo.get_gatewayIP();
        r->next_hop_RTT = additionalInfo.get_gatewayIP();
        r->Loss_interface = 1;
        r->RTT_interface = 1;
        r->inf_RTT = true;
        r->Loss = 1;
        learn_table.insert(std::pair<uint32_t,Routing*>(servers->at(i)->getIP(), r));
        struct Routing* r1 = (Routing*) malloc(sizeof (struct Routing));
        r1->Loss_interface = 1; // it means that uses straight path
        r1->RTT_interface = 1;
        r1->next_hop_Loss = additionalInfo.get_gatewayIP();
        r1->next_hop_RTT = additionalInfo.get_gatewayIP();
        r1->Loss_interface = 1;
        r1->RTT_interface = 1;
        forward_table.insert(std::pair<uint32_t,Routing*>(servers->at(i)->getIP(), r1));
	}
}

/**
 *       uint32 length;
 *       byte *data;
 *       Frame (uint32 _length, byte *_data);
 */
void SimulatedMachine::processFrame (Frame frame, int ifaceIndex) {
	// TODO: process the raw frame; frame.data points to the frame's byte stream
	cerr << "Frame received at iface " << ifaceIndex << " with length " << frame.length << endl;
    int timer = getMilliCount();

    byte *tmp  = new byte[frame.length];
    int frame_length = frame.length;
    copyFrame(frame.data, tmp, frame.length);

    if (!valid_frame(tmp, frame_length, ifaceIndex)){
        cerr << "invalid frame" << endl;
        return;}


    struct ip *ip_hdr = (struct ip*)(tmp + sizeof(sr_ethernet_hdr));
    int ip_size = sizeof(struct ip);
    if (ip_hdr->ip_hl > 5)
        ip_size += (ip_hdr->ip_hl - 5) * sizeof(uint32_t);


    // check what king of packet is recieved
    if (ip_hdr->ip_p == IPPROTO_ICMP){ // recieved ICMP packet
        if (ifaceIndex != 1)
            return;

        struct icmp_hdr *icmp = (struct icmp_hdr*) (tmp + sizeof(sr_ethernet_hdr) + ip_size);  /// ip_size moshkeli ke ijad nakarde??
        int last_sum = ntohs(icmp->checksum);
        icmp->checksum = 0;
        if (ip_sum_calc((3) * 4, (uint8_t*) (icmp))!= last_sum)
            return;


        if (icmp->type == 0 && icmp->code == 0) { // recieved echo reply message
            int server_ind = this->additionalInfo.get_server_ind(ntohl(ip_hdr->ip_src.s_addr));
            if (server_ind == -1){ // server is not found in the list of available servers
                return;
            }
            serverInfo* server = additionalInfo.get_servers()->at(server_ind);
            server_locks.at(server_ind)->lock();
            bool v = server->check_sequnce_num(ntohs(icmp->seq_num));
            server_locks.at(server_ind)->unlock();
            if (v == false)
                return;

            server_locks.at(server_ind)->lock();
            if (server->is_connect()){ // this server was connected
                server->add_recieved(ntohs(icmp->seq_num));
                server->compute_RTT((long) timer, false);
            }else { // this sever has been disconnected and now is connected again
                server->compute_RTT((long) timer, true);
                server->connect();
                server->add_sent();
                server->add_recieved(ntohs(icmp->seq_num));
            }

            // update the learn table
            update_ltable(server->getRTT(), server->loss_rate(), server->getIP(), additionalInfo.get_gatewayIP(), 1, server_ind);
            server_locks.at(server_ind)->unlock();
        }
    }else if (ip_hdr->ip_p == IPPROTO_UDP){ // recieved UDP packet
        ///valid udp ham ezafe shavad
        if (ntohl(ip_hdr->ip_dst.s_addr) == 0xffff){ // recieved advertise
            if (ifaceIndex != 0)
                return;

            struct sr_udp *udp = (struct sr_udp*) (tmp + sizeof(sr_ethernet_hdr) + ip_size);
            if (ntohs(udp->port_dst) != 5000)
                return;

            // save the mac address of peer
            std::map<uint32_t, byte*>::iterator ipMac;
            ipMac = IP_MAC.find(ntohl(ip_hdr->ip_src.s_addr));
            if (ipMac == IP_MAC.end()){
                //add this mac address to list
                byte* mac_t = new byte[6];
                struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*) tmp;
                for (int i = 0; i < 6; i++){
                    mac_t[i] = eth->ether_shost[i];
                }
                IP_MAC.insert(std::pair<uint32_t, byte*>(ntohl(ip_hdr->ip_src.s_addr), mac_t));
            }else{/* this mac address was previosly added*/}


            // edit update of table according to advertise rows
            int num_rows = (frame_length - (sizeof(struct sr_ethernet_hdr) + ip_size + sizeof(uint32_t) + sizeof(struct sr_udp))) /(sizeof(struct sr_server));
            int base = sizeof(struct sr_ethernet_hdr) + ip_size + sizeof(struct sr_udp);
            for (int j = 0; j < num_rows; j++){
                if (base + j*sizeof(struct sr_server) > sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_len)
                    return;
                struct sr_server *advert_row = (struct sr_server*) (tmp + base + j*sizeof(struct sr_server));
                /// lock here
                /// waht if iface is not 0?
                /// what if sent is 0
                int server_ind = this->additionalInfo.get_server_ind(ntohl(advert_row->IP));
                if (server_ind == -1)
                    continue;
                double loss = 1;
                if (ntohs(advert_row->sent) == 0){
                    if (ntohs(advert_row->recieved) == 0)
                        loss = 1;
                    else
                        continue;
                }else{
                    loss -= 1.0*ntohs(advert_row->recieved)/ntohs(advert_row->sent);
                }
                if (loss < 0 || loss > 1)
                    continue;
                server_locks.at(server_ind)->lock();
                update_ltable(ntohl(advert_row->RTT), loss, ntohl(advert_row->IP), ntohl(ip_hdr->ip_src.s_addr), 0, server_ind);
                server_locks.at(server_ind)->unlock();
            }

        }else{ // recieved unicast packet
            // basteyi az baghye gerefte ke brashon befreste agar dst port 1000 ya 2000 bashad yani ke ke basteye request bude ast
            // ya basteye javabe => basteye javab baraye khodesh ya in ke baraye baghyie befreste
            struct sr_udp *udp = (struct sr_udp*) (tmp + sizeof(sr_ethernet_hdr) + ip_size);
            if (ntohs(udp->port_dst) == 5000)
                return;

                /// check kardane port ha hanuz kamel nist
            if (ntohs(udp->port_dst) == 1000 || ntohs(udp->port_dst) == 2000){ // dest ip ham bashad this was application request
                /// ttl ra bayad kam konim?
                struct NAT_info* nat = (struct NAT_info*) malloc(sizeof(struct NAT_info));
                nat->for_others = true;
                nat->realIP = ntohl(ip_hdr->ip_src.s_addr);
                nat->real_port = ntohs(udp->port_src);
                nat->is_dsa = false;
                nat->expire = false;
                /// what if server is not in custom info??
                string ipstr = printIPstr(ntohl(ip_hdr->ip_dst.s_addr));
                if (ntohs(udp->port_dst) == 1000){
                    nat->is_dsa = true;
                    cout << "DSA packet forwarded to " << ipstr << " \n";
                }else{
                    cout << "LSA packet forwarded to " << ipstr << " \n";
                }

              // mac, ip, udp port bayad avaz shavad
                /// what about TTL?
                struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*) tmp;

                byte* dest_mac = additionalInfo.getGatewayMac();
                for(int i = 0; i < 6; i++){
                    eth->ether_shost[i] = iface[1].mac[i];
                    eth->ether_dhost[i] = dest_mac[i]; // gateway
                }
              //  ntohl(ip_hdr->ip_src.s_addr
                ip_hdr->ip_src.s_addr = htonl(iface[1].getIp());
                port_lock.lock();
                int port = get_lastport();
                port_lock.unlock();
                NAT_table.insert(std:: pair<uint32_t, NAT_info*> (port, nat));
                udp->port_src = htons(port);
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = htons(ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)));
                Frame new_frame(frame_length, tmp);
                sendFrame(new_frame, 1);

            }
            else if (ntohs(udp->port_dst) >= 8000){ // recieved dsa or lsa reply from server
                cerr << "Recieved application reply" << endl;
            //    printFrame(tmp, frame_length);
                std::map<uint16_t, NAT_info*>::iterator it;
                it = NAT_table.find(ntohs(udp->port_dst));

                if (it == NAT_table.end()){
                    // packet is not for me this port is not used
                    return;
                }else { // another peer reply should forward it
                    /// waht about ttl?
                    /// agar roye yek porti basteye dsa ferestade basham vali javab lsa amade bashad?
                    // search in NAT table
                // forward reply to proper destination

                    NAT_info* nat = it->second;
                    if (nat->expire) /// agar ke 2 bar javabe baste umad dige bayad monghazi beshe?
                        return;
                    nat->expire = true;
                    if (nat->for_others){ //got reply for others
                        cerr << "got reply for others" << endl;
                        // mac, ip, udp port bayad avaz shavad , check sum
                        struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*) tmp;
                        std::map<uint32_t, byte*> ::iterator it_m;
                        it_m = IP_MAC.find(nat->realIP);

                        if (it_m == IP_MAC.end()){//does not have the mac of this ip address
                            return;
                        }

                        byte* dest_mac = it_m ->second;
                        for(int i = 0; i < 6; i++){
                            eth->ether_shost[i] = iface[0].mac[i];
                            eth->ether_dhost[i] = dest_mac[i]; // gateway
                        }
                //   ip_hdr->ip_src.s_addr = htonl(iface[1].getIp());
                    /// ino bayad taghyir bedahim?? balayi?
                        ip_hdr->ip_dst.s_addr = htonl(nat->realIP);
                        udp->port_dst = htons(nat->real_port);
                        ip_hdr->ip_sum = 0;
                        ip_hdr->ip_sum = htons(ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)));

                        string ipstr = printIPstr(ntohl(ip_hdr->ip_src.s_addr));
                        if (ntohs(udp->port_src) == 1000){
                            cout << "DSA forwarded packet reply received from " << ipstr << " \n";
                        }else if (ntohs(udp->port_src) == 2000){
                            cout << "LSA forwarded packet reply received from " << ipstr << " \n";
                        }
                        Frame new_frame(frame_length, tmp);
                        sendFrame(new_frame, 0);
                    }else{ //got it's own reply packet
                        if (nat->start > timer)
                            return; // this has not been sent :))
                        if (ntohs(udp->port_src) == 1000) /// should change it to port
                            cout << "DSA packet "<< ntohs(udp->port_dst) <<" reply received in " << timer - nat->start << "ms\n";
                        else if (ntohs(udp->port_src) == 2000)
                            cout << "LSA packet "<< ntohs(udp->port_dst) <<" reply received in " << timer - nat->start << "ms\n";
                    }

                }
            }
        }

    }else{
        return;
    }
}

/**
 * This method will be run from an independent thread. Use it if needed or simply return.
 * Returning from this method will not finish the execution of the program.
 */
void SimulatedMachine::run (){
	// TODO: write your business logic here...
	while(true){
	    string a;
	    cin >> a;
	    std::cout.precision(2);
	    if (a == "stats"){
	        vector<serverInfo*>* servers = this->additionalInfo.get_servers();
	          for (uint i = 0; i < servers->size(); i++){
                serverInfo* s = servers->at(i);
                uint32_t ip = s->getIP();
                string ip_str = printIPstr(ip);
                server_locks.at(i)->lock();
                if (s->is_connect()){
                    std::cout.precision(2);
                    char tmp[5];
                    sprintf(tmp, "%.2f", s->loss_rate());
                    tmp[4] = '\0';
                    cout << ip_str << " " <<s->getRTT() << " " << tmp << " (" << s->get_sent() << " " << s->get_recieved() <<")"<< endl;
                }else{
                    cout << ip_str<<" INF 1.00" << endl;
                }
                server_locks.at(i)->unlock();
            }

	    }else if (a == "ltable"){
            vector<serverInfo*>* servers = this->additionalInfo.get_servers();
            for (uint i = 0; i < servers->size(); i++){
                serverInfo* s = servers->at(i);
                std::map<uint32_t, Routing*>::iterator it_f;
                std::map<uint32_t, Routing*>::iterator it_l;
                uint32_t ip = s->getIP();
                it_f = forward_table.find(ip);
                it_l = learn_table.find(ip);
                if (it_f == forward_table.end() || it_l == learn_table.end()){
                    continue;
                }
                else{
                    struct Routing* r = it_f->second;
                    struct Routing* r1 = it_l->second;
                    server_locks.at(i)->lock();
                    char tmp[5];
                    sprintf(tmp, "%.2f", r1->Loss);
                    tmp[4] = '\0';
                  //  n=sprintf (buffer, "%d.%d.%d.%d", c1, c2, c3, c4);
                  //  cout.unsetf(ios_base::floatfield);
                    cout << printIPstr(s->getIP()) << " " << printIPstr(r->next_hop_Loss) << " " << printIPstr(r1->next_hop_Loss) << " " << tmp << "\n";
                    server_locks.at(i)->unlock();
                }
            }

	    }else if (a == "dtable"){
            vector<serverInfo*>* servers = this->additionalInfo.get_servers();
            for (uint i = 0; i < servers->size(); i++){
                serverInfo* s = servers->at(i);
                uint32_t ip = s->getIP();

                std::map<uint32_t, Routing*>::iterator it_f;
                std::map<uint32_t, Routing*>::iterator it_l;
                it_f = forward_table.find(ip);
                it_l = learn_table.find(ip);
                if (it_f == forward_table.end() || it_l == learn_table.end()){
                    continue;
                }
                else{
                    struct Routing* r = it_f->second;
                    struct Routing *r1 = it_l->second;
                    server_locks.at(i)->lock();
                    if (r1->inf_RTT)
                        cout << printIPstr(s->getIP()) <<" "<< printIPstr(r->next_hop_RTT) << " " << printIPstr(r1->next_hop_RTT)<<" INF\n";
                    else
                        cout << printIPstr(s->getIP()) <<" "<< printIPstr(r->next_hop_RTT) << " " << printIPstr(r1->next_hop_RTT)<<" "<<r1->RTT <<" \n";
                    server_locks.at(i)->unlock();
                }
            }
	    }else if (a == "advertise" ){
	        advertise(0); // lock
	        ltable_ftable(); // lock
	    }else if (a == "ping"){
	        /// bayad in ja update ezafe shavad
	        /// va khob havas be in bashad ke agar ghat shod toye update table inf baraye rtt ro ye harekati anjam daham
	        vector<serverInfo*>* servers = this->additionalInfo.get_servers();

           for (uint i = 0; i < servers->size(); i++){
                serverInfo* s = servers->at(i);
                int timer = getMilliCount();
                server_locks.at(i)->lock();
                int num = s->get_next_sequence((long) timer);
                server_locks.at(i)->unlock();
                send_ICMP_packet(1, s->getIP(), num);

                server_locks.at(i)->lock();
                update_ltable(s->getRTT(), s->loss_rate(), s->getIP(), additionalInfo.get_gatewayIP(), 1, i);
                server_locks.at(i)->unlock();
            }
	    }else{
	        ///felan in shekli bashe
	        if (a == "dsa"){
                cin >> a;
                forward_packet(true, convertIP(&a[0]));
            }
            else if (a == "lsa"){
                cin >> a;
                forward_packet(false, convertIP(&a[0]));
              //  cerr << a << endl;
            }else{
            cerr << "ajibe";
            }

	    }
	}
}


/**
 * You could ignore this method if you are not interested on custom arguments.
 */
void SimulatedMachine::parseArguments (int argc, char *argv[]) {

}

uint32_t SimulatedMachine::convertIP(char* IP_str){
    int counter = 0;
    int i = 0;
    //cerr << IP_str[0] << endl;
    // set the IP address here
    while (IP_str[i] > '9' || IP_str[i] < '0'){
        i++;
    }
   // cerr << IP_str << endl;
    uint32_t IP = 0;
    for (;counter < 4;){
        IP *= 256;
        uint8_t temp = 0;

        //i++;
        while (IP_str[i] <= '9' && IP_str[i] >= '0'){
            temp *= 10;
            temp += (int) (IP_str[i] - '0');
            i++;
        }
        IP += temp;
        i++;
        counter++;
    }
    //cerr << "not this part" << endl;
    //cerr << IP;
    return IP;
}
void SimulatedMachine::update_ltable(uint32_t RTT, double Loss, uint32_t destIP, uint32_t next_hopIP, int interface, int server_ind){
    /// lock baraye taghyire in jadval niz bayad gozashte shavad
    /// need the server information to tasmim begirad
    //std::map<uint32_t, Routing*>::iterator it_f;
    std::map<uint32_t, Routing*>::iterator it_l;
    it_l = learn_table.find(destIP);


    if (it_l == learn_table.end()){
        return; // this server was not in table
    }
    struct Routing* r = it_l->second;

    // update RTT in table
    if (interface == 1){ // update of the gateway
        if (r->RTT_interface == 1){
            // change all the information according to this server info
            r->next_hop_RTT = next_hopIP;
            r->RTT = RTT;
            r->inf_RTT = ((additionalInfo.get_servers())->at(server_ind))->is_inf_RTT();
        }else{
            if (((additionalInfo.get_servers())->at(server_ind))->is_connect()){ // if this server is connected
                if (RTT < r->RTT){
                    r->RTT_interface = 0;
                    r->RTT = RTT;
                    r->inf_RTT = false;
                    r->next_hop_RTT = next_hopIP;
                }
            }
        }

    }else{
        if (r->RTT_interface == 1){ // direct to server
            if (r->inf_RTT){
                r->next_hop_RTT = next_hopIP;
                r->inf_RTT = false;
                r->RTT = RTT;
                r->RTT_interface = 0;
            }else if(RTT < r->RTT){
                r->next_hop_RTT = next_hopIP;
                r->inf_RTT = false;
                r->RTT = RTT;
                r->RTT_interface = 0;
            }
        }else{
            if (r->next_hop_RTT == next_hopIP){
                if (RTT < r->RTT)
                    r->RTT = RTT;
                else{
                    if (((additionalInfo.get_servers())->at(server_ind))->is_connect()){
                        if (((additionalInfo.get_servers())->at(server_ind))->getRTT() < RTT){
                            r->RTT = additionalInfo.get_servers()->at(server_ind)->getRTT();
                            r->RTT_interface = 1;
                            r->inf_RTT = false;
                            r->next_hop_RTT = additionalInfo.get_gatewayIP();
                        }else{
                            r->RTT = RTT;
                        }
                    }else{
                        r->RTT = RTT;
                    }
                }
            }else{
                if (RTT < r->RTT){
                    r->RTT = RTT;
                    r->inf_RTT = false;
                    r->RTT_interface = 0;
                    r->next_hop_RTT = next_hopIP;
                }
            }
        }
    }


    // update Loss rate
    if (interface == 1){ // update of the gateway
        if (r->Loss_interface == 1){// change all the information according to this server info
            r->next_hop_Loss = next_hopIP;
            r->Loss = Loss;
        }else{
            if (((additionalInfo.get_servers())->at(server_ind))->is_connect()){ // if this server is connected
                if (Loss < r->Loss){
                    r->Loss_interface = 0;
                    r->Loss = Loss;
                    r->next_hop_Loss = next_hopIP;
                }
            }
        }

    }else{
        if (r->Loss_interface == 1){ // direct to server
            if(Loss < r->Loss){
                r->next_hop_Loss = next_hopIP;
                r->Loss = Loss;
                r->Loss_interface = 0;
            }
        }else{
            if (r->next_hop_Loss == next_hopIP){
                if (Loss < r->Loss)
                    r->Loss = Loss;
                else{
                    if (((additionalInfo.get_servers())->at(server_ind))->is_connect()){
                        if (((additionalInfo.get_servers())->at(server_ind))->loss_rate() < Loss){
                            r->Loss = additionalInfo.get_servers()->at(server_ind)->loss_rate();
                            r->Loss_interface = 1;
                            r->next_hop_Loss = additionalInfo.get_gatewayIP();
                        }else{
                            r->Loss = Loss;
                        }
                    }else{
                        r->Loss = Loss;
                    }
                }
            }else{
                if (Loss < r->Loss){
                    r->Loss = Loss;
                    r->Loss_interface = 0;
                    r->next_hop_Loss = next_hopIP;
                }
            }
        }
    }

    return;
}
bool SimulatedMachine::advertise(int interface){
    vector<serverInfo*>* servers = this->additionalInfo.get_servers();
    int num_servers = servers->size();

    int packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp) + sizeof(uint32_t) + sizeof(uint32_t) * 3 * num_servers;
    byte* data = new byte[packet_size];

    // make ethernet header
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) data;
    struct ip *ip_hdr = (struct ip*) (data + sizeof(struct sr_ethernet_hdr));
    struct sr_udp *udp = (struct sr_udp*) (data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    int num_actives = 0;
    for (uint i = 0; i < servers->size(); i++){
        struct sr_server *s = (struct sr_server*) (data+sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp) + i * sizeof(sr_server));
        serverInfo* s_tmp = servers->at(i);
        server_locks.at(i)->lock();
        if (!s_tmp->is_connect()){
            server_locks.at(i)->unlock();
            continue;
        }
        s->IP = htonl(s_tmp->getIP());
        s->sent = htons(s_tmp->get_sent());
        s->recieved = htons(s_tmp->get_recieved());
        s->RTT = htonl(s_tmp->getRTT());
        server_locks.at(i)->unlock();
        num_actives++;
    }

    for(int i = 0; i < 6; i++){
        eth->ether_shost[i] = iface[0].mac[i];
        eth->ether_dhost[i] = 0xff;
    }
    eth->ether_type = htons(ETHERTYPE_IP);

    // make ip header
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;

    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = htonl(iface[0].getIp());
    ip_hdr->ip_dst.s_addr = htonl(0xffff); // in ja ro dobare chek konam

 // make udp header
    udp->port_src = htons(5000); // in hamon jayie ke az 8000 shoro mishe
    udp->port_dst = htons(5000);

    udp->udp_sum = 0;
    // mohasebeye meghdare sum

    packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp) + sizeof(uint32_t) + sizeof(uint32_t) * 3 * num_actives;
    ip_hdr->ip_len = htons(packet_size - sizeof(struct sr_ethernet_hdr));
     udp->length = htons(packet_size - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    uint32_t* end = (uint32_t *) (data + packet_size - sizeof(uint32_t));
    *end = 0;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = htons(ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)));
    byte* tmp = new byte[packet_size];
    copyFrame(data, tmp, packet_size);
    Frame new_frame(packet_size, data);
    return sendFrame(new_frame, interface);
}
bool SimulatedMachine::forward_packet(bool is_dsa, uint32_t dstIP){
    // search in forwarding table
    uint32_t nextHop;
    int interface;
    uint16_t dst_port;

    std::map<uint32_t, Routing*>::iterator it_l;
    it_l = forward_table.find(dstIP);
    if (it_l == forward_table.end()){
        return false; // the requested server was not available
    }else{
        struct Routing* r = it_l->second;
        int server_ind = additionalInfo.get_server_ind(dstIP);
        server_locks.at(server_ind)->lock();
        if (is_dsa){
            nextHop = r->next_hop_RTT;
            interface = r->RTT_interface;
            dst_port = 1000;
        }else{
            nextHop = r->next_hop_Loss;
            interface = r->Loss_interface;
            dst_port = 2000;
        }
        server_locks.at(server_ind)->unlock();
    }


    byte* mac;
    if (interface == 0){
        std::map<uint32_t, byte*>::iterator it_l;
        it_l = IP_MAC.find(nextHop);
        if (it_l == IP_MAC.end()){
            return false; // does not have the mac of this ip
        }else{
            mac = it_l->second;
        }
    }else{
        //gateway mac??
        mac = this->additionalInfo.getGatewayMac();
    }

    /// kolle in bakhshe payin toye lock
    port_lock.lock();
    uint16_t src = get_lastport();
    port_lock.unlock();
    if (dst_port == 1000)
        cout << "DSA packet " << src << " destined for "<< printIPstr(dstIP) << " sent to " << printIPstr(nextHop) << "\n";
    else
        cout << "LSA packet " << src << " destined for "<< printIPstr(dstIP) << " sent to " << printIPstr(nextHop) << "\n";

    return send_UDP_packet(interface, dstIP, src, dst_port, mac);
}
bool SimulatedMachine::send_UDP_packet(int interface, uint32_t dstIP, uint16_t src_port, uint16_t dst_port, byte* dest_mac){
    int packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp) + sizeof(uint32_t);
    byte* data = new byte[packet_size];

    // make ethernet header
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) data;
    for(int i = 0; i < 6; i++){
        eth->ether_shost[i] = iface[interface].mac[i];
        eth->ether_dhost[i] = dest_mac[i];
    }
    eth->ether_type = htons(ETHERTYPE_IP);

    // make ip header
    struct ip *ip_hdr = (struct ip*) (data + sizeof(struct sr_ethernet_hdr));
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = htons(packet_size - sizeof(struct sr_ethernet_hdr));
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = htonl(iface[interface].getIp());
    ip_hdr->ip_dst.s_addr = htonl(dstIP); // in ja ro dobare chek konam

 // make udp header
    struct sr_udp *udp = (struct sr_udp*) (data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    udp->port_src = htons(src_port); // in hamon jayie ke az 8000 shoro mishe
    udp->port_dst = htons(dst_port);
    udp->length = htons(packet_size - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    udp->udp_sum = 0;
    // mohasebeye meghdare sum

    struct udp_data *dsa_data = (struct udp_data*) (data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp));
    dsa_data->data = htonl(0x12345678);
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = htons(ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)));
    Frame new_frame(packet_size, data);
    struct NAT_info* nat = (struct NAT_info*) malloc(sizeof(struct NAT_info));
    nat->for_others = false;
    nat->is_dsa = false;
    if(dst_port == 1000)
        nat->is_dsa = true;
    nat->expire = false;
    nat->start = getMilliCount();
    NAT_table.insert(std:: pair<uint32_t, NAT_info*> (src_port, nat));

    printFrame(data, packet_size);
    return sendFrame(new_frame, interface);

}
void SimulatedMachine::reset_ltable(){
    std::map<uint32_t, Routing*>::iterator it_l;
    vector<serverInfo*>* servers = this->additionalInfo.get_servers();
    for (uint i = 0; i < servers->size(); i++){
        serverInfo* s = servers->at(i);
        uint32_t destIP = s->getIP();
        it_l = learn_table.find(destIP);
        /// what if not found
        struct Routing* r = it_l->second;
        r->Loss_interface = 1;
        r->RTT_interface = 1;
        r->next_hop_Loss = additionalInfo.get_gatewayIP();
        r->next_hop_RTT = additionalInfo.get_gatewayIP();
        r->Loss = s->loss_rate();
        r->RTT = s->getRTT();
        r->inf_RTT = s->is_inf_RTT();
    }}
void SimulatedMachine::ltable_ftable(){
    std::map<uint32_t, Routing*>::iterator it_l;
    std::map<uint32_t, Routing*>::iterator it_f;
    vector<serverInfo*>* servers = this->additionalInfo.get_servers();
    for (uint i = 0; i < servers->size(); i++){
        serverInfo* s = servers->at(i);
        uint32_t destIP = s->getIP();
        it_l = learn_table.find(destIP);
        it_f = forward_table.find(destIP);
        if (it_l == learn_table.end() || it_f == forward_table.end())
            continue;
        struct Routing* r = it_l->second;
        struct Routing* to = it_f->second;
        server_locks.at(i)->lock();
        to->next_hop_Loss = r->next_hop_Loss;
        to->next_hop_RTT = r->next_hop_RTT;
        to->Loss_interface = r->Loss_interface;
        to->RTT_interface = r->RTT_interface;
        r->Loss_interface = 1;
        r->RTT_interface = 1;
        r->next_hop_Loss = additionalInfo.get_gatewayIP();
        r->next_hop_RTT = additionalInfo.get_gatewayIP();
        r->Loss = s->loss_rate();
        r->RTT = s->getRTT();
        r->inf_RTT = s->is_inf_RTT();
        server_locks.at(i)->unlock();
    }
}
int SimulatedMachine::get_lastport(){
    return last_port++;
}
int SimulatedMachine::getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}
bool SimulatedMachine::send_ICMP_packet(int interface, uint32_t IP, int sequenc_num){
    int packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmp_hdr);
    byte* data = new byte[packet_size];

    // make ethernet header
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) data;
    for(int i = 0; i < 6; i++){
        eth->ether_shost[i] = iface[interface].mac[i];
        eth->ether_dhost[i] = this->additionalInfo.getGatewayMac()[i];
    }
    eth->ether_type = htons(ETHERTYPE_IP);

    // make ip header
    struct ip *ip_hdr = (struct ip*) (data + sizeof(struct sr_ethernet_hdr));
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = htons(packet_size - sizeof(struct sr_ethernet_hdr));
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_src.s_addr = htonl(iface[interface].getIp());
    ip_hdr->ip_dst.s_addr = htonl(IP); // in ja ro dobare chek konam

    // make icmp header
    struct icmp_hdr *icmp = (struct icmp_hdr*)(data + sizeof(struct sr_ethernet_hdr) + sizeof (struct ip));
    icmp->type = 8;
    icmp->code = 0;
    icmp->id = htons(0);
    icmp->seq_num = htons(sequenc_num);

    icmp->checksum = 0;
    uint32_t t = 0x12345678;
    icmp->data = htonl(t);


    icmp->checksum = htons(ip_sum_calc((3) * 4, (uint8_t*) (icmp)));

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = htons(ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)));
    //printFrame(data, packet_size);
    Frame new_frame(packet_size, data);
    return sendFrame(new_frame, interface);
}
bool SimulatedMachine::valid_icmp(byte* data, int length){
    return true;
}
bool SimulatedMachine::valid_unicast(byte* data, int length){
    return true;
}
bool SimulatedMachine::valid_advertise(byte* data, int length){
    return true;
}
bool SimulatedMachine:: valid_frame(byte* data, int length, int interface){
    if (length < sizeof(struct sr_ethernet_hdr))
        return false;

    struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*) data;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return false;

    if (length < sizeof(struct sr_ethernet_hdr) + sizeof (struct ip))
        return false;

    struct ip* ip_hdr = (struct ip*) (data + sizeof(struct sr_ethernet_hdr));

    if (ip_hdr->ip_v != 4) /// ???
        return false;
    if (ip_hdr->ip_hl < 5)
        return false;
    int ip_size = ntohs(ip_hdr->ip_len);

    if (length < ip_size + sizeof(struct sr_ethernet_hdr))
        return false;

    int packet_size = ip_size + sizeof(struct sr_ethernet_hdr);


    if (ip_hdr->ip_p != IPPROTO_UDP && ip_hdr->ip_p != IPPROTO_ICMP)
        return false;
    if (ip_hdr->ip_p == IPPROTO_ICMP && interface == 0)
        return false;


    uint16_t last_checksum = ntohs(ip_hdr->ip_sum);
    ip_hdr->ip_sum = 0;
    if (ip_sum_calc((ip_hdr->ip_hl)*4,(uint8_t*)(ip_hdr)) != last_checksum)
        return false;



    if (ip_hdr->ip_p == IPPROTO_ICMP){ // icmp packet
        if ((ip_hdr->ip_hl)*sizeof(uint32_t) + sizeof(struct icmp_hdr) > packet_size)
            return false;
    }else{ // recieved udp packet
        if ((ip_hdr->ip_hl)*sizeof(uint32_t) + sizeof(struct sr_udp) > packet_size){
            return false;
        }


    }

    return true;
}
unsigned short SimulatedMachine:: ip_sum_calc(unsigned short len_ip_header, uint8_t* buff){
	unsigned short word16;
	unsigned long sum=0;
	unsigned short i;

		// make 16 bit words out of every two adjacent 8 bit words in the packet
		// and add them up
		for (i=0;i<len_ip_header;i=i+2){
					word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
							sum = sum + (unsigned long) word16;
								}

			// take only 16 bits out of the 32 bit sum and add up the carries
			while (sum>>16)
					  sum = (sum & 0xFFFF)+(sum >> 16);

				// one's complement the result
				sum = ~sum;

				return ((unsigned short) sum);
}
void SimulatedMachine::copyFrame(byte *frame, byte *newFrame, uint32_t len){
    //cerr << "inside copy function!";
    for (uint i = 0; i < len; i++){
        *(newFrame + i) = *(frame + i);
    }
}
void SimulatedMachine:: printFrame(byte* data, int length) {
	cerr << hex;
	for(int i = 0; i < length; i++) {
		if(data[i] < 16) cerr << "0";
		cerr << (int)data[i];
	//	if (i % 2 == 0)
		cerr << " ";
		if (i % 20 == 0)
		cerr << endl;
	}
	cerr << dec << endl;
}
string SimulatedMachine::printIPstr(uint32_t ip){
     unsigned char c1 = 0;
        unsigned char c2 = 0;
        unsigned char c3 = 0;
        unsigned char c4 = 0;
        c1 = (ip & 0xff000000UL) >> 24;
        c2 = (ip & 0x00ff0000UL) >> 16;
        c3 = (ip & 0x0000ff00UL) >>  8;
        c4 = (ip & 0x000000ffUL) ;

        char buffer [50];
        int n;
        n=sprintf (buffer, "%d.%d.%d.%d", c1, c2, c3, c4);
        char* s = &buffer[0];
        *(s + n) = '\0';
        string res = (string) s;
        return res;
}
