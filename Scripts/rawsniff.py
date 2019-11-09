#!/bin/python

import socket
import struct

# formatting mac from bytes to aa:bb:cc:dd:ee:ff
def get_mac_addr(bytes_mac):
	bytes_str = map('{:02x}'.format,bytes_mac)
	mac = ':'.join(bytes_str).upper()
	return mac

#formatting ip v4 address
def get_ipv4_addr(bytes_addr):
	str_addr = map(str,bytes_addr)
	str_addr = '.'.join(str_addr)
	return str_addr

#unpack ethernet frame computer<=>router
def ethernet_frame(data):
	dst_mac,src_mac,proto = struct.unpack("! 6s 6s H", data[:14])
	dst_mac = get_mac_addr(dst_mac)
	src_mac = get_mac_addr(src_mac)
	proto = socket.htons(proto)
	return dst_mac,src_mac,proto,data[14:]

#unpack IPV4 packet
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4 #0000 version 
	header_length = (version_header_length & 15) * 4
	ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
	src = get_ipv4_addr(src) 
	target = get_ipv4_addr(target) 
	return version,header_length,ttl,proto,src,target,data[header_length:]

#unpack ICMP packet
def icmp_packet(data):
	icmp_type,code,chekcsum = struct.unpack('! B B H',data[:4])
	return icmp_type,code,chekcsum,data[4:]

#unpack UDP packet
def udp_packet(data):
	src_port,dst_port,size = struct.unpack('! H H 2x H',data[:8])
	return src_port,dst_port,size,data[8:]

#unpack TCP packet
def tcp_packet(data):
	src_port,dst_port,sequence,acknowledgment,offset_reverved_flags = struct.unpack('! H H L L H ',data[:14])
	offset = (offset_reverved_flags >> 12) * 4 
	flag_urg = (offset_reverved_flags & 32 ) >> 5
	flag_ack = (offset_reverved_flags & 16 ) >> 4
	flag_psh = (offset_reverved_flags & 8 ) >> 3
	flag_rst = (offset_reverved_flags & 4 ) >> 2
	flag_syn = (offset_reverved_flags & 2 ) >> 1
	flag_fin =  offset_reverved_flags & 1 
	return src_port,dst_port,sequence,acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]

#main function
def main():
	sck = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
	while True:
		raw_data,addr = sck.recvfrom(65536)
		dst_mac,src_mac,eth_type,eth_data = ethernet_frame(raw_data)
		print('\nEthernet Frame:')
		print('\t Destination:  {}   Source:  {}   Type:  {} '.format(dst_mac,src_mac,eth_type))

		#ipv4
		if eth_type == 8:
			version,header_length,ttl,ip_proto,src,target,ip_data = ipv4_packet(eth_data)
			print('\tIPv4 Packet:')
			print('\t\tVersion:  {}   Header Length:  {}  TTL:  {} '.format(version,header_length,ttl))
			print('\t\tProtocol:  {}  Source:  {}   Destination:  {} '.format(ip_proto,src,target))

			#icmp
			if ip_proto == 1:
				icmp_type,code,chekcsum,icmp_data = icmp_packet(ip_data)
				print('\t\tICMP Packet:')
				print('\t\t\tType: {}  Code: {}  Checksum: {} '.format(icmp_type,code,chekcsum))
				print('\t\t\tICMP payload: {} '.format(icmp_data))

			#udp
			if ip_proto == 17:
				src_port,dst_port,size,udp_data = udp_packet(ip_data)
				print('\t\tUDP Segment:')
				print('\t\t\tSource Port: {}   Destination Port: {}  Size {} '.format(src_port,dst_port,size))

			#tcp
			if ip_proto == 6:
				src_port,dst_port,sequence,acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,tcp_data = tcp_packet(ip_data)
				print('\t\tTCP Segment')
				print('\t\t\tSource Port: {}   Destination Port: {} '.format(src_port,dst_port))
				print('\t\t\tSequence: {}  Acknowlegment: {} '.format(sequence,acknowledgment))
				print('\t\t\tLength: '+ str(len(tcp_data)))
				print('\t\t\tFlags:')
				print('\t\t\t\tURG: {}  ACK: {}  PSH: {}  RST: {}  SYN: {}  FIN: {}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))

				
				if len(tcp_data) > 0:
					#http
					if src_port == 80 or dst_port == 80:
						print('\t\t\tHTTP Data:')
						try:
							http_data = tcp_data.decode('utf-8')
							http_info = str(http_data).split('\n')
							for lines in http_info:
								print('\t\t\t\t'+str(lines))
						except:
							print('\t\t\t\t'+str(tcp_data))
					else:
						print('\t\t\t\t'+str(tcp_data))


main()