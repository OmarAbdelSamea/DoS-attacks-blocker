from scapy.all import *
import os
from typing import Final
import logging


logging.basicConfig(filename='dos.log',
                    format='[%(levelname)s %(asctime)s] :: %(message)s',
                    level=logging.INFO)


TIME_INTERVAL: Final[int] = 10 # in seconds
PACKET_INTERVAL: Final[int] = 10 
THRESHOLD: Final[int] = 3 # in seconds


def get_already_banned_iptables():
    """
    :get_already_banned_iptables() gets all entries from iptables with
    DROP rule to add them to banned dictionary

    :param: none
    :return: dict dropped_ips: contains all ips with drop rule in iptables
    """
    cmd = "iptables -n -L INPUT | grep DROP  | awk '{print $2\"_\"$4}'"
    proc = os.popen(cmd)
    logging.info(f"command <{cmd}> executed")
    dropped_ips = {}
    dropped_ips_string = proc.read()
    dropped_ips_string = dropped_ips_string.split()
    for ip_string in dropped_ips_string:
        type,ip = ip_string.split('_')
        logging.info(f"added IP: {ip} with type: {type} to banned IPs")
        if ip in dropped_ips:
            dropped_ips[ip] += ","+type
        else:
            dropped_ips[ip] = type
    return dropped_ips    


def get_user_input():
    """
    :get_user_input() gets input from user to select the type of incoming
    request

    :param: none
    :return: string type: packet type chosen by user
    """
    type = input('''
Please select one of the packet types [tcp, udp, icmp]:
''')
    logging.info(f"user selected type: {type}")
    if type not in 'tcp,udp,icmp':
        logging.info(f"user selected wrong type: {type}")
        type = 'not-defined'
    return type


def sniff_and_count(type):
    """
    :sniff_and_count() sniffs all packets with the selected type for 
    timeout to TIME_INTERVAL and count to PACKET_INTERVAL then count 
    number of requests per IP address

    :param: string type: packet type used in sniff() function
    :return: dict src_ip: dictionary containing key:IP value:count
    """
    print("sniffing..................")
    logging.info(f"started packet sniffing for {TIME_INTERVAL} seconds")
    sniffed_packets = sniff(filter=type, timeout=TIME_INTERVAL, count=PACKET_INTERVAL)
    src_ip = {}
    for packet in sniffed_packets:
        logging.info(f"IP: {packet.getlayer(IP).src} sent a packet to IP: {packet.getlayer(IP).dst}")
        print(f"Src: {packet.getlayer(IP).src} -> dist: {packet.getlayer(IP).dst}")
        print("--------------------\n")
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in src_ip:
                src_ip[packet.getlayer(IP).src] += 1
            else:
                src_ip[packet.getlayer(IP).src] = 1
    if not src_ip:
        print("time interval exceeded and no packets sniffed")
        logging.info("sniffed 0 packets")
    return src_ip


def catch_dos_attacker(src_ip, banned, local_ip, type):
    """
    :catch_dos_attacker() loops on src_ip dictionary to ban any ip that
    passes the threshold specified by THRESHOLD. If already banned it will show 
    that the request is dropped and no replay will be sent.

    :param: dict src_ip: containing key:IP value:count 
            dict banned: containing banned ips
            string local_ip: host machine IP address
            string type: packet type
    :return: none
    """
    for packet, req_count in src_ip.items():
        if (packet not in banned) or ((packet in banned) and (type not in banned[packet])):
            if req_count > THRESHOLD and packet != local_ip:
                print(f"/********* BANNED: {packet} NO.PACKETS: {req_count} *********/\n")
                logging.info(f"BANNED: {packet} NO.PACKETS: {req_count}")
                if packet in banned:
                    banned[packet] += ","+type
                else:
                    banned[packet] = type
                cmd = 'iptables -A INPUT -s '+packet+' -p '+type+' -j DROP'
                os.popen(cmd)
                logging.info(f"command <{cmd}> executed")
                cmd = 'iptables -A OUTPUT -s '+packet+' -p '+type+' -j ACCEPT'
                os.popen(cmd)
                logging.info(f"command <{cmd}> executed")
                cmd = 'iptables-save'
                os.popen(cmd)
                logging.info(f"command <{cmd}> executed")
                cmd = ''
                req_count = 0
        elif req_count > 0 and (type in banned[packet]):
            print(f"/********* DROPPED {req_count} packets from {packet} *********/\n")
            logging.info(f"DROPPED {req_count} packets from {packet}")
            req_count = 0


def main():
    banned = {}
    banned = get_already_banned_iptables()
    local_ip = get_if_addr(conf.iface)
    logging.info(f"host machine IP is {local_ip}")
    print(f'Local IP = {local_ip}')
    type = get_user_input()
    while(type == 'not-defined'):
        print("[ERROR]: Please select tcp, udp or icmp")
        type = get_user_input()
    while(True):
        src_ip = {}
        src_ip = sniff_and_count(type)
        catch_dos_attacker(src_ip, banned, local_ip, type)

if __name__ == "__main__":
    main()

