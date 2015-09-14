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

#ifndef _S_M_H_
#define _S_M_H_

#include <map>
#include "machine.h"
#include "MCI.h"
#include <sstream>
#include <mutex>
#include <cstring>

class SimulatedMachine : public Machine {
private:
    MCI additionalInfo;
    std:: map<uint32_t, Routing*> forward_table;
    std:: map<uint32_t, Routing*> learn_table;
    std:: map<uint32_t, byte*> IP_MAC;
    std:: map<uint16_t, NAT_info*> NAT_table;
    mutex port_lock;
    vector<mutex*> server_locks;
    int last_port;
public:
	SimulatedMachine (const ClientFramework *cf, int count);
	virtual ~SimulatedMachine ();

	virtual void initialize ();
	virtual void run ();
	virtual void processFrame (Frame frame, int ifaceIndex);

	static void parseArguments (int argc, char *argv[]);

	bool send_ICMP_packet(int interface, uint32_t IP, int sequenc_num);
	bool send_UDP_packet(int interface, uint32_t dstIP, uint16_t src_port, uint16_t dst_port, byte* mac);
    bool advertise(int interface);
    bool forward_packet(bool is_dsa, uint32_t dstIP);

    int get_lastport();

    void update_ltable(uint32_t RTT, double Loss, uint32_t destIP, uint32_t next_hopIP, int interface, int server_ind);
    void reset_ltable();
    void ltable_ftable();

	bool valid_frame(byte* data, int length, int interface);
	bool valid_icmp(byte* data, int length);
	bool valid_advertise(byte* data, int lenght);
	bool valid_unicast(byte* data, int lenght);

    unsigned short ip_sum_calc(unsigned short len_ip_header, uint8_t* buff);
    unsigned short icmp_sum_calc(unsigned short len_ip_header, uint8_t* buff);
	void copyFrame(byte *frame, byte *newFrame, uint32_t len);
	void printFrame(byte* data, int length);
	int getMilliCount();
	string printIPstr(uint32_t IP);
	uint32_t convertIP(char* IP);

};

#endif /* sm.h */

