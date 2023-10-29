#!/bin/bash/env python
# _*_ coding:utf-8_*_

#supports live packert capturing!
#usage: sudo python3 testmain.py wlan0



try:
    import pcap
    from scapy.all import *
    from scapy.utils import wrpcap  #for writting the captured packets into a pcap file
    import os
    import threading
    from ipblock import IPBLOCK    #custom module for blocking IP address
except:
    pass



#for beautifying the terminal output
RED = "\033[0;31m"
WHITE = "\033[0m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"

#  __Initialising Global Values__

#max request sent to target
UTMOST = 1000
#to count the number of packets
PACKET_COUNTER = {}
#the IP to check whether it's been attacked or not!
IPTOSAVE = '192.168.1.1'
VULNERABLE_PORTS_TO_DOS = ['21','22','25','53','80','443','8080']  #ftp,ssh,smtp,dns,http,https,http/https
frame_number = 0 #frame number (i.e packet number)

#regex
#IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'



#to check whether the program is running as sudo or not
def run_as_sudo():
    if os.geteuid() == 0:
        pass
    else:
        exit('[+] Run The Program with Sudo permission!')



#to analyze the captured packets and to analyze DOS
def CapturePacket(packet):
    global frame_number 
    try:
        if 'IP' in packet:
            source_ip = packet['IP'].src
            destination_ip = packet['IP'].dst

            if 'TCP' in packet:
                protocol = "TCP"
                source_port = packet['TCP'].sport
                destination_port = packet['TCP'].dport
        
            elif 'UDP' in packet:
                protocol = "UDP"
                source_port = packet['UDP'].sport
                destination_port = packet['UDP'].dport
            
            else:
                protocol = "Other"
                source_port = "N/A"
                destination_port = "N/A"


            frame_number += 1 

            print(f"{RED}Frame Number: {WHITE}{frame_number} || {BLUE}Source IP: {WHITE}{source_ip} || {YELLOW}Destination IP: {WHITE}{destination_ip} || {RED}Protocol: {WHITE}{protocol} || {BLUE}Source Port: {WHITE}{source_port} || {PURPLE}Destination Port: {WHITE}{destination_port}", end='\n')

            #logging the captured packets in a pcap file
            wrpcap("packet.pcap", packet, append=True)



            #for DOS detection:
            # Count the number of packets with the same source IP

            for p in packet:
                if 'IP' in p:
                    if source_ip in PACKET_COUNTER and destination_port in VULNERABLE_PORTS_TO_DOS:
                        PACKET_COUNTER[source_ip] += 1
                    else:
                        PACKET_COUNTER[source_ip] = 1
    
            # Check if any IP address has sent too many packets
            for ip, count in PACKET_COUNTER.items():

                #checking the number of packets being sent to destination IP,if they are verified the IP causing trouble will get blocked
                if count > UTMOST and destination_ip == IPTOSAVE :  # Adjust this UTMOST value
                    #IPBLOCK.block(ip) #will block the ip
                    print(f'[!] Possible {RED}DoS{WHITE} attack detected --> {RED}{ip}{WHITE} attacked {RED}{IPTOSAVE}{WHITE} with {RED}{count}{WHITE} packets on port {RED}{destination_port}{WHITE}!')
                    print(f'[#] {ip} Blocked Succesfully')
        
    except:
        pass




def forpacketcapture():
    packet = sniff(prn = CapturePacket,iface = interface,store = False)


if __name__  == '__main__':
    if sys.hexversion >= 0x03080000:
        
        #printing the banner
        print('''
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
|P|a|c|k|e|t| |A|n|a|l|y|z|e|r|
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
                    - @Debang5hu
''')
        
        #checking
        run_as_sudo()

        #interface = 'wlan0'

        #cli inputs
        try:
            
            #interface in which the packet capturing will take place (eth0/wlan0)
            interface = sys.argv[1]
            
            #using threading concept
            t1 = threading.Thread(target = forpacketcapture,daemon=True) #using daemon so that runs in background too

            #starting the thread
            t1.start()

            #join 
            t1.join()
        
        except:
            print('\n[+] Usage: [sudo python3 main.py {interface_name}] for capturing network packets')

    else:
        sys.exit('[+] Required Python Version > 3.8!')



