#!/bin/bash/python

#to use this module    (IPBLOCK.block('0.0.0.1'))

import subprocess
import platform

RED = "\033[0;31m"
WHITE = "\033[0m"

class IPBLOCK:
    def block(iptoblock):
        if platform.system() == 'Linux':
            try:
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", iptoblock, "-j", "DROP"])
                print(f'{RED}[+] Blocked: {iptoblock}{WHITE}')
            except:
                print('{RED}[+] Failed to block: {iptoblock}{WHITE}')
        
        elif platform.system() == 'Windows':
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", f"remoteip={iptoblock}"])
                print(f'{RED}[+] Blocked: {iptoblock}{WHITE}')
            except:
                print('{RED}[+] Failed to block: {iptoblock}{WHITE}')
        
        else:
            pass


    def unblock(iptounblock):
        if platform.system() == 'Linux':
            try:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", iptounblock, "-j", "DROP"])
                print(f'{RED}[+] Unblocked: {iptounblock}{WHITE}')
            except:
                print('{RED}[+] Failed to unblock: {iptounblock}{WHITE}')
        
        elif platform.system() == 'Windows':
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=BlockIP", "dir=in", "action=allow", f"remoteip={iptounblock}"])
                print(f'{RED}[+] Unblocked: {iptounblock}{WHITE}')
            except:
                print('{RED}[+] Failed to unblock: {iptounblock}{WHITE}')
        
        else:
            pass

