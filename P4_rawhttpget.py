#!/usr/bin/env python


import sys
import socket
from urlparse import urlparse
import os
import random
from struct import *
from timeit import default_timer
import re

# Enabling Promiscuous Mode to observe all incoming packets
promisc_mode = os.system("ifconfig eth0 promisc")
# Drop outgoing TCP RST packets
reset_drop = os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

# Function to calculate the Checksum of a packet

def checksum_function(data):
    pos = len(data)
    # Converting to even number, if odd
    if (pos&1):  
        pos = pos - 1
        result = ord(data[pos])  
    else:
        result = 0       
    for i in range(0, pos, 2):
        temp = ord(data[i]) + (ord(data[i+1]) << 8)
        result = result + temp     
    result = (result >> 16) + (result & 0xffff)
    result = result + (result >> 16)
    # Finding 1's complement
    result = ~result & 0xffff
    return result


# Initializing url
url = ''
if (len(sys.argv) > 1):
    url = sys.argv[1]
else:
    print "Program exit due to no command line argument"
    sys.exit()

# Retrieving Hostname and Path of the given url
path = urlparse(url).path
hostname = urlparse(url).hostname


# Retrieving the IP address of the local machine
sdup = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sdup.connect((hostname,80))
my_ip = sdup.getsockname()[0]
sdup.close

# Randomly picking a source port to start communication
main_source_port = random.randrange(40000,60000)
my_port = main_source_port

# Setting the server port to 80
server_port = 80

# Creating IPPROTO_RAW socket for Sending. Exit program if failure. 
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , err:
    print 'Socket creation failure. Error Code is ' + str(err[0]) + 'Msg: ' + err[1]
    sys.exit()


################# SYN START #############################

packet = '';

# Retrieving the server ip 
main_server_ip = socket.gethostbyname(hostname)
server_ip = main_server_ip

# Setting Congestion Window to 1
cwnd = 1
# Randomly picking an initial sequence number
my_syn_seq = random.randrange(1000,10000)
 
# Setting IP header fields
ip_header_len = 5                                       # IP Header Length
ip_version = 4                                          # IP Version
ip_type_of_service = 0                                  # IP Type of Service
ip_total_length = 0                                     # Total Packet Length
ip_id = 1                                               # IP Packet ID
ip_f_offset = 0                                         # Fragment Offset
ip_ttl = 255                                            # Number of Hops
ip_proto = socket.IPPROTO_TCP                           # Transport Layer protocol (TCP here)
ip_csum = 0                                             # IP Packet Checksum
ip_source_address = socket.inet_aton (my_ip)            # Source IP Address 
ip_dest_address = socket.inet_aton (server_ip)          # Destination IP Address
ip_header_len_ver = (ip_version << 4) + ip_header_len   # IP Header Length and Version

# Creating the IP header using the format string !BBHHHBBH4s4s
ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)
   

# Setting TCP header fields
tcp_source_port = my_port                   # TCP Source Port
tcp_dest_port = server_port                 # TCP Destination Port
tcp_seq_no = my_syn_seq                     # Sequence Number
tcp_ack_no = 0                              # Acknowledgement Number
tcp_data_offset = 5                         # Data Offset
tcp_fin = 0                                 # FIN Flag
tcp_syn = 1                                 # SYN Flag
tcp_rst = 0                                 # RST Flag
tcp_psh = 0                                 # PSH Flag
tcp_ack = 0                                 # ACK Flag
tcp_urg = 0                                 # URG Flag
tcp_window = 8192                           # TCP Advertised Window
tcp_csum = 0                                # TCP Segmnet Checksum
tcp_urg_ptr = 0                             # Urgent Pointer
tcp_reserved = (tcp_data_offset << 4) + 0   # Reserved Bits
# Concatenating all the flags
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 

# Creating the TCP header using the format string !HHLLBBHHH
tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags, tcp_window, tcp_csum, tcp_urg_ptr)


# Creating the pseudoheader for checksum computation 
psh_source_addr = socket.inet_aton(my_ip)
psh_dest_addr = socket.inet_aton(server_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header)
 
psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length);
psh = psh + tcp_header
 

# Computing TCP checksum
tcp_csum = checksum_function(psh)


# Creating the new TCP header by adding the calculated Checksum
tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags, tcp_window) + pack('H' , tcp_csum) + pack('H' , tcp_urg_ptr)


# Creating the Packet that is to be sent (in this case, a SYN packet)
packet = ip_header + tcp_header
 

s.sendto(packet, (server_ip , 0))          # SYN packet sent to server_ip

# Start timer after packet is sent
connection_timer = default_timer()


# Creating socket for receiving packets

try:
    rd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , err:
    print 'Receiver Socket could not be created. Error Code is: ' + str(err[0]) + ' Message: ' + err[1]
    sys.exit()


################# LOOP TILL FIN-ACK IS RECEIVED #############

# Initializing required loop variables
finalData = ''
packetBuffer = dict()
get_flag = 0
server_seq = 0 
server_ack_my_seq = 0

# Display message to show that file is being downloaded
print "Downloading the File... Please Wait..."

# Runs Infinitely till FIN-ACK is received 
while True:

    # Receiving all incoming packets
    response = rd.recvfrom(65535) 
    response = response[0]

    # Check if 180 seconds have elapsed without a packet being received
    if (default_timer() - connection_timer > 180):
        print "Connection timed out"
        sys.exit()

    # Unpacking IP packet
    ip_header = response[0:20]
    ip_headerUnpacked = unpack('!BBHHHBBH4s4s',ip_header)

    version_temp = ip_headerUnpacked[0]
    version = version_temp >> 4                             # IP Version
    iph_len_temp = version_temp & 0xF                       

    server_ip = socket.inet_ntoa(ip_headerUnpacked[-2])     # Server IP
    my_ip = socket.inet_ntoa(ip_headerUnpacked[-1])         # Local Machine IP

       
    iph_length = iph_len_temp * 4                           # IP Header Length

    # Unpacking TCP segment
    tcp_header = response[iph_length:iph_length+20] 
    tcp_headerUnpacked = unpack('!HHLLBBHHH',tcp_header)
    

    server_port = tcp_headerUnpacked[0]                     # Server Port
    my_port = tcp_headerUnpacked[1]                         # Local Machine Port
    server_seq = tcp_headerUnpacked[2]                      # Server Sequence Number
    server_ack_my_seq = tcp_headerUnpacked[3]               # Server Acknowledgement Number
   

    tcpDoff = tcp_headerUnpacked[4]                         # Data Offset
    tcph_length = tcpDoff >> 4                              # TCP Header Length

    flag = tcp_headerUnpacked[5]                            # TCP Flags

    packet_header_size = iph_length + tcph_length * 4       # Total Packet Header Length
    packet_data_size = len(response) - packet_header_size   # Packet Data Size

    my_ack = server_seq + packet_data_size                  # ACK Number to Send

    fin = flag&1                                            # FIN Flag Value
    syn = flag&2                                            # SYN Flag Value

    # Checking if the packet checksum is correct and the packet is from the required Server
    if (checksum_function(ip_header) == 0 and server_ip == main_server_ip):

        # Reseting Connection Timeout Timer as packet is received 
        connection_timer = default_timer()

        # Increasing Congestion Window as an ACK is received
        if (cwnd < 801):
            cwnd = cwnd + 200
	elif(cwnd == 801):
	    cwnd = cwnd + 199 

        # Retransmiting if a packet is dropped
        delete_list = []
        for key in packetBuffer:
            if(packetBuffer.get(key)[0] == server_seq):
                delete_list.append(key)
            elif(default_timer() - packetBuffer.get(key)[2] > 60):
                s.sendto(packetBuffer.get(key)[1], (server_ip , 0))
                packetBuffer[key][2] = default_timer()

        for ele in delete_list:
            del packetBuffer[ele]

        # Received an normal ACK

        if (syn != 2 and fin != 1):

            # Creating IP Packet
            ip_header_len = 5
            ip_version = 4
            ip_type_of_service = 0
            ip_total_length = 0

            # Wrapping Around IP Packet ID
            if (ip_id < 65535):
                ip_id = ip_id + 1   
            else:
                ip_id = 1
                
            ip_f_offset = 0
            ip_ttl = 255
            ip_proto = socket.IPPROTO_TCP
            ip_csum = 0    
            ip_source_address = socket.inet_aton (my_ip)   
            ip_dest_address = socket.inet_aton (server_ip)
 
            ip_header_len_ver = (ip_version << 4) + ip_header_len


            ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)   

            # Creating TCP Segment            
            tcp_source_port = my_port 
            tcp_dest_port = server_port
            tcp_seq_no = server_ack_my_seq
            tcp_ack_no = my_ack
            tcp_data_offset = 5
            tcp_fin = 0
            tcp_syn = 0
            tcp_rst = 0
            tcp_psh = 0
            tcp_ack = 1
            tcp_urg = 0
            tcp_window = 8192
            tcp_csum = 0
            tcp_urg_ptr = 0
 
            tcp_reserved = (tcp_data_offset << 4) + 0
            tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
            tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window, tcp_csum, tcp_urg_ptr)
 
            # Creating pseudoheader for checksum computation
            psh_source_addr = socket.inet_aton(my_ip)
            psh_dest_addr = socket.inet_aton(server_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
 
            psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length)
            psh = psh + tcp_header
 
            tcp_csum = checksum_function(psh)

            tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window) + pack('H' , tcp_csum) + pack('H' , tcp_urg_ptr)

 
            packet = ip_header + tcp_header

            # Sending Packet to server
            s.sendto(packet, (server_ip , 0))

            # Adding packet to buffer, to retransmit if dropped
            key = ip_id
            packetBuffer.setdefault(key, [])
            packetBuffer[key].append(tcp_ack_no)
            packetBuffer[key].append(packet)
            packetBuffer[key].append(default_timer())
            

            # Storing the Packet Data
            finalData = finalData + response[packet_header_size:]

        # Received a SYN ACK
        elif(syn == 2):
            
            ############### SENDING ACK (Step 1) ####################

            # Creating TCP Segment 
            tcp_source_port = my_port
            tcp_dest_port = server_port
            tcp_seq_no = my_syn_seq + 1 
            tcp_ack_no = my_ack + 1
            tcp_data_offset = 5    
            tcp_fin = 0
            tcp_syn = 0
            tcp_rst = 0
            tcp_psh = 0
            tcp_ack = 1
            tcp_urg = 0
            tcp_window = 8192
            tcp_csum = 0
            tcp_urg_ptr = 0
 
            tcp_reserved = (tcp_data_offset << 4) + 0
            tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
            tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window, tcp_csum, tcp_urg_ptr)

            # Creating the pseudoheader for checksum calculation
            psh_source_addr = socket.inet_aton(my_ip)
            psh_dest_addr = socket.inet_aton(server_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
  
            psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length);
            psh = psh + tcp_header

            tcp_csum = checksum_function(psh)
 
            tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window) + pack('H' , tcp_csum) + pack('H' , tcp_urg_ptr)

            packet = ''
            
            if (ip_id < 65535):
                ip_id = ip_id + 1
            else:
                ip_id = 1

            ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)

            packet = ip_header + tcp_header

            s.sendto(packet, (server_ip , 0))

            ############## SENDING DATA (Step 2) #################

            # Creating IP Packet
            ip_header_len = 5
            ip_version = 4
            ip_type_of_service = 0
            ip_total_length = 0
            if (ip_id < 65535):
                ip_id = ip_id + 1
            else:
                ip_id = 1

            ip_f_offset = 0
            ip_ttl = 255
            ip_proto = socket.IPPROTO_TCP
            ip_csum = 0
            ip_source_address = socket.inet_aton (my_ip)
            ip_dest_address = socket.inet_aton (server_ip)
 
            ip_header_len_ver = (ip_version << 4) + ip_header_len
 
            ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)   


            # Creating TCP Segment
            tcp_source_port = my_port
            tcp_dest_port = server_port
            tcp_seq_no = my_syn_seq + 1
            tcp_ack_no = my_ack + 1
            tcp_data_offset = 5
            tcp_fin = 0
            tcp_syn = 0
            tcp_rst = 0
            tcp_psh = 1
            tcp_ack = 1
            tcp_urg = 0
            tcp_window = 8192
            tcp_csum = 0
            tcp_urg_ptr = 0
 
            tcp_reserved = (tcp_data_offset << 4) + 0
            tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
     
            tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window, tcp_csum, tcp_urg_ptr)

            # Setting the Filename
            if (path == '' or path == '/'):
                path = '/'
                filename = "index.html"
            else:
                splitFilename = path.split('/')
                filename = splitFilename[-1] 
                filename = filename + "1"

            # Preparing the HTTP GET request for the first time
            if(get_flag == 0):
            	complete_user_data = ("GET "+path+" HTTP/1.0\n"+
                		     "Host: "+hostname+"\n"+
                		     "Connection: keep-alive\n"+
                		     "Accept: text/html\n\n")                		     
		get_flag = 1


            # Determining the amount of data to be sent based on CWND
	    min_packet_len = min(len(complete_user_data),cwnd)
	    if(min_packet_len > 0):
		user_data = complete_user_data[:min_packet_len]
		complete_user_data = complete_user_data[min_packet_len:]

	        # Creating pseudoheader for checksum computation
            	psh_source_addr = socket.inet_aton(my_ip)
            	psh_dest_addr = socket.inet_aton(server_ip)
            	placeholder = 0
            	protocol = socket.IPPROTO_TCP
            	tcp_length = len(tcp_header) + len(user_data)
            	psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length)    
            	psh = psh + tcp_header + user_data
 
            	tcp_csum = checksum_function(psh)

            
            	tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window) + pack('H' , tcp_csum) + pack('H' , tcp_urg_ptr)


                # Creating and Sending Packet
            	packet = ip_header + tcp_header + user_data
 
            	s.sendto(packet, (server_ip , 0))

                # Adding packet to buffer, to retransmit if dropped
            	key = ip_id
            	packetBuffer.setdefault(key, [])
            	packetBuffer[key].append(tcp_ack_no)
            	packetBuffer[key].append(packet)
            	packetBuffer[key].append(default_timer())            

        # Received FIN-ACK
        elif(fin == 1):

            # Storing the Packet Data and Breaking from the Loop
            finalData = finalData + response[packet_header_size:]
            break

        # Received Invalid TCP Segment
        else:
            print "Invalid TCP flag"
            sys.exit()

    # Incorrect Checksum 
    elif(checksum_function(ip_header) != 0):
        print "Invalid Checksum!"
        sys.exit()
        
    
########## OBTAINED FIN ###################
################## SEND THE FINAL ACK ##################

# Creating IP Packet
ip_header_len = 5
ip_version = 4
ip_type_of_service = 0
ip_total_length = 0
if (ip_id < 65535):
    ip_id = ip_id + 1
else:
    ip_id = 1
ip_f_offset = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_csum = 0
ip_source_address = socket.inet_aton (my_ip)
ip_dest_address = socket.inet_aton (server_ip)
 
ip_header_len_ver = (ip_version << 4) + ip_header_len
 
ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)

# Creating TCP Segment
tcp_source_port = my_port 
tcp_dest_port = server_port 
tcp_seq_no = server_ack_my_seq
tcp_ack_no = my_ack + 1
tcp_data_offset = 5 
tcp_fin = 0
tcp_syn = 0
tcp_rst = 0
tcp_psh = 0
tcp_ack = 1
tcp_urg = 0
tcp_window = 8192
tcp_csum = 0
tcp_urg_ptr = 0
 
tcp_reserved = (tcp_data_offset << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window, tcp_csum, tcp_urg_ptr)

# Creating Psuedo Header for Checksum calculation
psh_source_addr = socket.inet_aton(my_ip)
psh_dest_addr = socket.inet_aton(server_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header)
 
psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length);
psh = psh + tcp_header

tcp_csum = checksum_function(psh)

tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window) + pack('H' , tcp_csum) + pack('H' , 
tcp_urg_ptr)

packet = ''

# Preparing and Sending the Packet 
packet = ip_header + tcp_header

s.sendto(packet, (server_ip , 0))    

################## SEND THE FINAL FIN ACK ##################

# Creating IP Packet
ip_header_len = 5
ip_version = 4
ip_type_of_service = 0
ip_total_length = 0 
 
if (ip_id < 65535):
    ip_id = ip_id + 1  
else:
    ip_id = 1               

ip_f_offset = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_csum = 0    
ip_source_address = socket.inet_aton (my_ip)   
ip_dest_address = socket.inet_aton (server_ip)
ip_header_len_ver = (ip_version << 4) + ip_header_len


# Creating the IP header using the format string BBHHHBBH4s4s

ip_header = pack('!BBHHHBBH4s4s' , ip_header_len_ver, ip_type_of_service, ip_total_length, ip_id, ip_f_offset, ip_ttl, ip_proto, ip_csum, ip_source_address, ip_dest_address)

# Creating TCP Segment
tcp_source_port = my_port   
tcp_dest_port = server_port
tcp_data_offset = 5  
tcp_fin = 1
tcp_syn = 0
tcp_rst = 0
tcp_psh = 0
tcp_ack = 1
tcp_urg = 0
tcp_window = 8192
tcp_csum = 0
tcp_urg_ptr = 0
 
tcp_reserved = (tcp_data_offset << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window, tcp_csum, tcp_urg_ptr)

# Creating Psuedo Header for Checksum calculation
psh_source_addr = socket.inet_aton(my_ip)
psh_dest_addr = socket.inet_aton(server_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header)
 
psh = pack('!4s4sBBH' , psh_source_addr , psh_dest_addr , placeholder , protocol , tcp_length);
psh = psh + tcp_header

tcp_csum = checksum_function(psh)


tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_no, tcp_ack_no, tcp_reserved, tcp_flags,  tcp_window) + pack('H' , tcp_csum) + pack('H' , 
tcp_urg_ptr)

packet = ''

packet = ip_header + tcp_header

s.sendto(packet, (server_ip , 0))

# Waiting for Final Ack and closing all socket connections
lastResponse = rd.recvfrom(65535)
s.close()
rd.close()

# Checking if its a valid HTTP Response i.e Status Code 200
valid_status_code = re.search(r'HTTP/1.[0-5] 200 OK', finalData)
if valid_status_code == None:
	print "Invalid HTTP Status Code in the HTTP Respone"
	
else:
        # Writing the body of the HTTP Response to a file
	body = finalData.split('\r\n\r\n',1)
	fptr = open(filename , "w")
	fptr.write(body[1])
	

