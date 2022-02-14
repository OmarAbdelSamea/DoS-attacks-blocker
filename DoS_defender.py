from scapy.all import *
import os
from typing import Final

TIME_INTERVAL: Final[int] = 10
PACKET_INTERVAL: Final[int] = 10
THRESHOLD: Final[int] = 3


def get_already_banned_iptables():
    cmd = "iptables -n -L INPUT | grep DROP  | awk '{print $2\"_\"$4}'"
    proc = os.popen(cmd)
    dropped_ips = {}
    dropped_ips_string = proc.read()
    dropped_ips_string = dropped_ips_string.split()
    for ip_string in dropped_ips_string:
        type,ip = ip_string.split('_')
        if ip in dropped_ips:
            dropped_ips[ip] += ","+type
        else:
            dropped_ips[ip] = type
    return dropped_ips    


def get_user_input():
    """
    test_function does blah blah blah.

    :param: none
    :return: type
    """
    type = input('''
1 to defend against TCP attacks
2 to defend against UDP attacks
3 to defend against ICMP attacks
''')
    if(type == '1'):      
        type = 'tcp'
    elif type == '2':
        type = 'udp'
    elif type == '3':
        type = 'icmp'
    else:
        type = 'not-defined'
    return type


def sniff_and_count(type):
    """
    test_function does blah blah blah.

    :param: none
    :return: type
    """
    sniffed_packets = sniff(filter=type, timeout=TIME_INTERVAL, count=PACKET_INTERVAL)
    src_ip = {}
    for packet in sniffed_packets:
        print(
            f"Src: {packet.getlayer(IP).src} -> dist: {packet.getlayer(IP).dst}")
        # if packet.getlayer(TCP).type == 8:
        #     print(f"type: Request")
        # else:   
        #     print(f"type: Replay")  
        print("--------------------\n")
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in src_ip:
                src_ip[packet.getlayer(IP).src] += 1
            else:
                src_ip[packet.getlayer(IP).src] = 1
    return src_ip


def catch_dos_attacker(src_ip, banned, local_ip, type):
    """
    test_function does blah blah blah.

    :param: none
    :return: type
    """
    for packet, req_count in src_ip.items():
        if (packet not in banned) or ((packet in banned) and (type not in banned[packet])):
            if req_count > THRESHOLD and packet != local_ip:
                print(f"/********* BANNED: {packet} NO.PACKETS: {req_count} *********/\n")
                if packet in banned:
                    banned[packet] += ","+type
                else:
                    banned[packet] = type
                cmd = 'iptables -A INPUT -s '+packet+' -p '+type+' -j DROP'
                os.popen(cmd)
                cmd = 'iptables -A OUTPUT -s '+packet+' -p '+type+' -j ACCEPT'
                os.popen(cmd)
                cmd = 'iptables-save'
                os.popen(cmd)
                cmd = ''
                req_count = 0
        elif req_count > 0 and (type in banned[packet]):
            print(f"/********* DROPPED {req_count} packets from {packet} *********/\n")
            req_count = 0

def main():
    banned = {}
    banned = get_already_banned_iptables()
    local_ip = get_if_addr(conf.iface)
    print(f'Local IP = {local_ip}')
    type = get_user_input()
    while(type == 'not-defined'):
        print("[ERROR]: Please select 1, 2 or 3")
        type = get_user_input()
    while(True):
        src_ip = {}
        src_ip = sniff_and_count(type)
        catch_dos_attacker(src_ip, banned, local_ip, type)

if __name__ == "__main__":
    main()

