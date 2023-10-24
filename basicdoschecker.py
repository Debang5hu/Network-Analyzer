#!/bin/bash/env python

#credit: https://github.com/Netwok-Analyzer/Network-Packet-Analyzer

import dpkt
import socket
from ipblock import IPBLOCK
import re
from collections import Counter

UTMOST = 1024 #max request per second
VULNERABLE_PORTS_TO_DOS = ['21','22','25','53','80','443','8080']  #ftp,ssh,smtp,dns,http,https,http/https
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
PORT_PATTERN = r'destination_port:\s*(\d+)'
PKT_LIST =[]
RED = "\033[0;31m"
WHITE = "\033[0m"
BLUE = "\033[0;34m"

#counts the number of packet(pcap)
def PacketCountPCAP(pcap):
    pktcount={}
    for buf in pcap:
        try:
            eth=dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            src=socket.inet_ntoa(ip.src)
            dest=socket.inet_ntoa(ip.dst)
        
            tcp=ip.data
            
            dport=tcp.dport

            if str(dport) in VULNERABLE_PORTS_TO_DOS:
                stream= src + ":" + dest
                if stream in pktcount:
                    pktcount[stream]=pktcount[stream]+1
                else:
                    pktcount[stream]=1
            
        except:
            pass

    for stream in pktcount:
        pktsent = pktcount[stream]
        if pktsent >= UTMOST:
            source = stream.split(":")[0]
            destination = stream.split(":")[1]

            #blocking the src ip
            IPBLOCK.block(source)
            print(f'[+] {RED}{source}{WHITE} attacked {RED}{destination}{WHITE} with {RED}{str(pktsent)}{WHITE} packets!')
        else:
            print(f'[+] {BLUE}{str(pktsent)}{WHITE} packets transmitted between {BLUE}{source}{WHITE} and {BLUE}{destination}{WHITE}!')


#counts the number of packet(txt)
def PacketCountTXT(txt):
    with open(txt, "r") as file:
        lines = file.read().splitlines()

    for x in lines:
        # Find all IP addresses in the text
        ip_addresses = re.findall(IP_PATTERN, x)
        port = re.search(PORT_PATTERN, x)


        if len(ip_addresses) >= 2 and port:
            ip1 = ip_addresses[0]
            ip2 = ip_addresses[1]
            port_number = port.group(1)
            if port_number in VULNERABLE_PORTS_TO_DOS:
                payload = ip1 + '--> ' + ip2 + ' --> ' + port_number
                PKT_LIST.append(payload)
    
    #counting the number of packets
    element_count = Counter(PKT_LIST)

    # Print the count of duplicate elements
    for element,count in element_count.items():
        if (count > UTMOST):
            ip = element.split('-->')
            IPBLOCK.block(ip[0])
            print(f'[+] {RED}{ip[0]}{WHITE} attacked {RED}{ip[1]}{WHITE} with {RED}{count}{WHITE} packets!')
        else:
            ip = element.split('-->')
            print(f'[+] {BLUE}{count}{WHITE} packets transmitted between {BLUE}{ip[0]}{WHITE} and {BLUE}{ip[1]}{WHITE}!')


if __name__ == '__main__':
    PacketCountTXT("ip.txt")
