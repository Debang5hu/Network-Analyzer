#!/usr/bin/env python

#supports live packert capturing!
#usage:  sudo python3 main.py -h

#sudo chmod +x main.py
#to run ./main.py --capture


try:
    import pcap  #for capturing packets
    import sys
    import pyshark
    #from scapy.all import *
    from pyfiglet import figlet_format
    import threading
    import getopt
except:
    pass



#for beautifying the terminal output
RED = "\033[0;31m"
WHITE = "\033[0m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"


#listing all the available interfaces of the device
def ListeningInterfaces():
    for x in pcap.findalldevs():
        print(f"{RED}Interface --> {WHITE} {x}")


def saveip(ip1,ip2,dst_port):
    with open('ip.txt','a+') as fh:
        payload = f'source_ip : {ip1},destination_ip: {ip2},destination_port: {dst_port} \n'
        fh.write(payload)

#to analyze the captured packets
def CapturePacket():
    n = interface
    CapturedPacket = pyshark.LiveCapture('any')
    CapturedPacket.sniff(timeout=10)

    for captured in CapturedPacket:
        try:
            for captured in CapturedPacket:
                frame_number = captured.number
                protocol = captured.transport_layer

                if 'IP' in captured:
                    source_ip = captured.ip.src
                    destination_ip = captured.ip.dst
                else:
                    source_ip = "N/A"
                    destination_ip = "N/A"

                if captured.transport_layer:
                    source_port = captured[captured.transport_layer].srcport
                    destination_port = captured[captured.transport_layer].dstport

                else:
                    source_port = "N/A"
                    destination_port = "N/A"


                print(f"{RED}Frame Number: {WHITE}{frame_number} || {BLUE}Source IP: {WHITE}{source_ip} || {YELLOW}Destination IP: {WHITE}{destination_ip} || {RED}Protocol: {WHITE}{protocol} || {BLUE}Source Port: {WHITE}{source_port} || {PURPLE}Destination Port: {WHITE}{destination_port}", end='\n')
                
                #marking(source_ip,destination_ip)
                saveip(source_ip,destination_ip,destination_port)
        except:
            pass


if __name__ == '__main__':
    
    if sys.hexversion >= 0x03080000:
        
        #banner
        print(figlet_format('Packet Analyzer', font = 'digital' ),end = '\n')
            


        #cli input
        try:
            
            arguments=sys.argv[1:]
            args,null=getopt.getopt(arguments,"c:i:",["capture=","interface="])

            for x,y in args:
                if x in ['-c','--capture']:
                    global interface
                    interface = y
                    #analyzing the packet
                    t1 = threading.Thread(target = CapturePacket)

                    # start the threads
                    t1.start()

                    # join the main thread
                    t1.join()
                
                if x in ['-i','--interface']:
                    if y == 'all':
                        ListeningInterfaces()
   
        except:
            print('\nUsage: [(./main.py -c {interface_name}) or (./main.py --capture {interface_name})] for capturing network packets')
            print('\t[(./main.py -i all) or (./main.py --interface all)] for checking available network interfaces')
                
    else:
        sys.exit('[+] Required Python Version > 3.8!')
