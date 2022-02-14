from scapy.all import *
import os
from subprocess import *

ip = get_if_addr(conf.iface)
print(f'Local IP = {ip}')
banned = []
type = input('''
1 to defend against TCP attacks
2 to defend against UDP attacks
3 to defend against ICMP attacks
''')
if(type=='1'):
    type='tcp'
elif type=='2':
    type='udp'
elif type == '3':
    type='icmp'
else:
    exit()

while(True):
    srcIP = {}
    pkts = sniff(filter = type,timeout =1)

    for packet in pkts:
        print(f"Src: {packet.getlayer(IP).src} -> dist: {packet.getlayer(IP).dst}")
        if packet.getlayer(ICMP).type == 8:
            print(f"type: Request")
        else:
            print(f"type: Replay")
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in srcIP :
                srcIP[packet.getlayer(IP).src]+=1
            else :
                srcIP[packet.getlayer(IP).src]=1

    for packet, req_count in srcIP.items():
        if packet not in banned:
            if req_count>=10 and packet != ip:
                print(f"/********* BANNED : {packet} *********/")
                banned.append(packet)
                cmd = 'iptables -A INPUT -s '+packet+' -p '+type+' -j DROP'
                os.popen(cmd)
                cmd = 'iptables -A OUTPUT -s '+packet+' -p '+type+' -j ACCEPT'
                os.popen(cmd)
                cmd = 'iptables-save'
                os.popen(cmd)
                cmd=''
                req_count = 0
        elif req_count > 0:
                print(f"/********* DROPPED {req_count} Requests from {packet} *********/")
                req_count = 0

