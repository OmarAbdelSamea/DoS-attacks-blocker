from scapy.all import *
import iptc
import os

ip = get_if_addr(conf.iface)
print(f'Local IP = {ip}')

while(True):
    srcIP = {}
    pkts = sniff(iface = "enp0s3",filter = 'icmp',timeout =10)

    for packet in pkts:
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in srcIP:
                srcIP[packet.getlayer(IP).src]+=1
            else :
                srcIP[packet.getlayer(IP).src]=1
            if srcIP[packet.getlayer(IP).src]>2 and packet.getlayer(IP).src != ip:
                if(packet.getlayer(DNS) == None):
                    print(f"{packet.getlayer(IP).src} = {srcIP[packet.getlayer(IP).src]}")
                    cmd = 'iptables -A INPUT -s '+ packet.getlayer(IP).src +' -p icmp -j DROP'
                    os.system(cmd)
                    cmd = 'iptables-save'
                    os.system(cmd)
                srcIP[packet.getlayer(IP).src] = 0



#sudo iptables -P INPUT ACCEPT
#sudo iptables -F