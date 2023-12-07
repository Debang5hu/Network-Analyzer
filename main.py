#!/bin/bash/env python
# _*_ coding:utf-8_*_

#supports live packert capturing!
#usage: sudo python3 testmain.py

# <------ How It Works! --------->
#it scans the packets and look for potential malicious content


try:
    from scapy.all import *
    from scapy.all import  IP,ICMP,TCP,UDP,ARP
    from scapy.utils import wrpcap  #for writting the captured packets into a pcap file
    import os
    import threading
    from ipblock import IPBLOCK    #custom module for blocking IP address
    from time import time
except:
    pass



#for beautifying the terminal output
RED = "\033[0;31m"
WHITE = "\033[0m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"

#  __Initialising Global and Constant Values__

#max request sent to target
UTMOST = 1000
#the IP to check whether it's been attacked or not!
IPTOSAVE = '192.168.1.1'
VULNERABLE_PORTS_TO_DOS = ['21','22','25','53','80','443','8080']  #ftp,ssh,smtp,dns,http,https,http/https
#to count the number of packets
PACKET_COUNTER = {}
FRAME_NUMBER = 0 #frame number (i.e packet number)
ICMP_COUNTER = {} #to count the number of ICMP requests

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
        global FRAME_NUMBER 
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
        
            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
            
            #ICMP packets don't have ports
            elif ICMP in packet:
                protocol = "ICMP"
                source_port = "N/A"
                destination_port = "N/A"

            #ARP packets don't have IP addresses or ports
            elif ARP in packet:
                protocol = "ARP"
                source_ip = "N/A"
                destination_ip = "N/A"
                source_port = "N/A"
                destination_port = "N/A"

            else:
                protocol = "Other"
                source_port = "N/A"
                destination_port = "N/A"


            FRAME_NUMBER += 1  #packet number

            print(f"{RED}Frame Number: {WHITE}{FRAME_NUMBER} || {BLUE}Source IP: {WHITE}{source_ip} || {YELLOW}Destination IP: {WHITE}{destination_ip} || {RED}Protocol: {WHITE}{protocol} || {BLUE}Source Port: {WHITE}{source_port} || {PURPLE}Destination Port: {WHITE}{destination_port}", end='\n')

            #logging the captured packets in a pcap file
            wrpcap("packet.pcap", packet, append=True)



            # <------- for DOS detection: ----------->

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
                    IPBLOCK.block(ip) #will block the source ip
                    print(f'[!] Possible {RED}DoS{WHITE} attack detected --> {RED}{ip}{WHITE} attacked {RED}{IPTOSAVE}{WHITE} with {RED}{count}{WHITE} packets on port {RED}{destination_port}{WHITE}!')



            #checks for partial http request (normally done by slowloris)

            if (packet.haslayer('TCP') or packet.haslayer('UDP')) and ((packet.haslayer('TCP') and packet['TCP'].payload) or(packet.haslayer('UDP') and packet['UDP'].payload)):
                if destination_ip == IPTOSAVE:
                    if packet.haslayer('TCP'):
                        payload = bytes(packet['TCP'].payload)
                    elif packet.haslayer('UDP'):
                        payload = bytes(packet['UDP'].payload)
                    if b"HTTP" in payload:
                        # Identify HTTP headers and content
                    
                        http_request = payload.split(b"\r\n\r\n")[0]
                        print(f'[!] Partial {RED}HTTP Request anomalies{WHITE} Detected from {RED}{source_ip}{WHITE}!')
                        print(http_request.decode("utf-8"))


            #checks for malformed information packet (teardrop attack)  [not appropriate though just a rough idea]

            #to be modified more
            if packet.haslayer(IP) and packet[IP].frag > 0:
                if destination_ip == IPTOSAVE:
                    print(f'[!] Partial {RED}Teardrop attack{WHITE} Detected from {RED}{source_ip}{WHITE}!')


            #ping flood attack (ICMP Packets)

            for p in packet:
                if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                    if source_ip in ICMP_COUNTER:
                        ICMP_COUNTER[source_ip] += 1
                    else:
                        ICMP_COUNTER[source_ip] = 1

            for ip, count in ICMP_COUNTER.items():
                if count > UTMOST and destination_ip == IPTOSAVE:
                    IPBLOCK.block(source_ip) #will block the source ip
                    print(f'[!] Possible {RED}Ping Flood attack{WHITE} Detected from {RED}{source_ip}{WHITE} with {count} {RED}ICMP{WHITE} packets!')






def forpacketcapture():
    packet = sniff(prn = CapturePacket,iface = interface,store = False)


# <--------- starts executing ------>
if __name__  == '__main__':
    if sys.hexversion >= 0x03080000:
        
        #printing the banner
        print('''
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
|P|a|c|k|e|t| |A|n|a|l|y|z|e|r|
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
                     -@Debang5hu
''')
        
        #wants the program to run as sudo!
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
        
        except KeyboardInterrupt:
            print('[!] Stopped by user!')

        except:
            print('\n[+] Usage: [sudo python3 main.py {interface_name}] for capturing network packets')


    else:
        sys.exit('[+] Required Python Version > 3.8!')



